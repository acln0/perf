// Copyright 2019 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package perf provides access to the Linux perf API. See man 2 perf_event_open.
package perf

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	// CallingThread configures the event to measure the calling thread.
	CallingThread = 0

	// AllThreads configures the event to measure all threads on the
	// specified CPU.
	AllThreads = -1
)

// AnyCPU configures the specified process/thread to be measured on any CPU.
const AnyCPU = -1

// Flag is a set of flags for Open. Values are |-ed together.
type Flag int

// Flags for calls to Open.
const (
	// NoGroup configures the event to ignore the group parameter
	// except for the purpose of setting up output redirection using
	// the FDOutput flag.
	NoGroup Flag = unix.PERF_FLAG_FD_NO_GROUP

	// FDOutput re-routes the event's sampled output to be included in the
	// memory mapped buffer of the event specified by the group parameter.
	FDOutput Flag = unix.PERF_FLAG_FD_OUTPUT

	// PidCGroup activates per-container system-wide monitoring. In this
	// case, a file descriptor opened on /dev/group/<x> must be passed
	// as the pid parameter. Consult the perf_event_open man page for
	// more details.
	PidCGroup Flag = unix.PERF_FLAG_PID_CGROUP

	// cloexec configures the event file descriptor to be opened in
	// close-on-exec mode. Package perf sets this flag by default on
	// all file descriptors.
	//
	// TODO(acln): PERF_FLAG_FD_CLOEXEC is missing from x/sys/unix
	cloexec Flag = 1 << 3
)

type Event struct {
	// state is the state of the event. See eventState* constants.
	state int32

	// fd is the event file descriptor.
	fd int

	// group contains other events in the event group, if this event is an
	// event group leader.
	group []*Event

	// attr is the set of attributes the Event was configured with.
	attr EventAttr

	// ring is the (entire) memory mapped ring buffer.
	ring []byte

	// ringdata is the data region of the ring buffer.
	ringdata []byte

	// meta is the metadata page: &ring[0].
	meta *unix.PerfEventMmapPage

	// evfd is an event file descriptor (see eventfd(2)): it is used to
	// unblock calls to ppoll(2) on the perf fd.
	evfd int

	// pollreq communicates requests from ReadRecord to the poll goroutine
	// associated with the ring.
	pollreq chan pollreq

	// pollresp receives responses from the poll goroutine associated
	// with the ring, back to ReadRecord.
	pollresp chan pollresp
}

// Event states.
const (
	eventStateUninitialized = 0
	eventStateOK            = 1
	eventStateClosed        = 2
)

// numRingPages is the number of pages we map for the ring buffer (excluding
// the meta page). This is the value the perf tool seems to use, at least
// on systems with 4KiB pages. There is no other theory behind this number.
const numRingPages = 128

// Open opens the event configured by attr.
//
// The pid and cpu parameters specify which thread and CPU to monitor:
//
//     * if pid == CallingThread and cpu == AnyCPU, the event measures
//       the calling thread on any CPU
//
//     * if pid == CallingThread and cpu >= 0, the event measures
//       the calling thread only when running on the specified CPU
//
//     * if pid > 0 and cpu == AnyCPU, the event measures the specified
//       thread on any CPU
//
//     * if pid > 0 and cpu >= 0, the event measures the specified thread
//       only when running on the specified CPU
//
//     * if pid == AllThreads and cpu >= 0, the event measures all threads
//       on the specified CPU
//
//     * finally, the pid == AllThreads and cpu == AnyCPU setting is invalid
//
// If group is non-nil, the returned Event is made part of the group
// associated with the specified group Event. If group is non-nil, and
// FlagNoGroup | FlagFDOutput are not set, the attr.Options.Disabled setting
// is ignored: the group leader controls when the entire group is enabled.
func Open(attr EventAttr, pid, cpu int, group *Event, flags Flag) (*Event, error) {
	groupfd := -1
	if group != nil {
		if err := group.ok(); err != nil {
			return nil, err
		}
		// TODO(acln): this is not quite right: fix the race somehow.
		groupfd = group.fd
	}
	flags |= cloexec
	fd, err := unix.PerfEventOpen(attr.sysAttr(), pid, cpu, groupfd, int(flags))
	if err != nil {
		return nil, os.NewSyscallError("perf_event_open", err)
	}
	if err := unix.SetNonblock(fd, true); err != nil {
		unix.Close(fd)
		return nil, os.NewSyscallError("setnonblock", err)
	}
	size := (1 + numRingPages) * unix.Getpagesize()
	ring, err := unix.Mmap(fd, 0, size, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED)
	if err != nil {
		unix.Close(fd)
		return nil, os.NewSyscallError("mmap", err)
	}
	meta := (*unix.PerfEventMmapPage)(unsafe.Pointer(&ring[0]))
	ringdata := ring[meta.Data_offset:]
	evfd, err := unix.Eventfd(0, unix.EFD_CLOEXEC|unix.EFD_NONBLOCK)
	if err != nil {
		unix.Close(fd)
		return nil, os.NewSyscallError("eventfd", err)
	}
	ev := &Event{
		fd:       fd,
		attr:     attr,
		ring:     ring,
		ringdata: ringdata,
		meta:     meta,
		evfd:     evfd,
		pollreq:  make(chan pollreq),
		pollresp: make(chan pollresp),
	}
	if group != nil {
		group.group = append(group.group, ev)
	}
	atomic.StoreInt32(&ev.state, eventStateOK)
	go ev.poll() // TODO(acln): start this lazily somehow?
	return ev, nil
}

func (ev *Event) ok() error {
	if ev == nil {
		return os.ErrInvalid
	}
	state := atomic.LoadInt32(&ev.state)
	switch state {
	case eventStateUninitialized:
		return os.ErrInvalid
	case eventStateOK:
		return nil
	default: // eventStateClosed
		return os.ErrClosed
	}
}

// Enable enables the event.
func (ev *Event) Enable() error {
	if err := ev.ok(); err != nil {
		return err
	}
	return ioctlEnable(ev.fd)
}

// Disable disables the event.
func (ev *Event) Disable() error {
	if err := ev.ok(); err != nil {
		return err
	}
	return ioctlDisable(ev.fd)
}

// Reset resets the counters associated with the event.
func (ev *Event) Reset() error {
	if err := ev.ok(); err != nil {
		return err
	}
	return ioctlReset(ev.fd)
}

// TODO(acln): add remaining ioctls as methods on *Event.

// TODO(acln): scrap all of the following and just use unsafe to read?

var isLittleEndian bool

func init() {
	var x uint16 = 0x1234
	b := (*[2]byte)(unsafe.Pointer(&x))
	if b[0] == 0x34 {
		isLittleEndian = true
	}
}

func nativeEndianUint64(b []byte) uint64 {
	if isLittleEndian {
		return binary.LittleEndian.Uint64(b)
	}
	return binary.BigEndian.Uint64(b)
}

var errGroupEvent = errors.New("calling ReadCount on group Event")

// ReadCount reads a single count. If the Event was configured with
// ReadFormat.Group, ReadCount returns an error.
func (ev *Event) ReadCount() (Count, error) {
	var c Count
	if err := ev.ok(); err != nil {
		return c, err
	}
	if ev.attr.ReadFormat.Group {
		return c, errGroupEvent
	}
	// TODO(acln): use rdpmc on x86 instead of read(2)?
	buf := make([]byte, ev.attr.ReadFormat.readSize())
	_, err := unix.Read(ev.fd, buf)
	if err != nil {
		return c, os.NewSyscallError("read", err)
	}
	nextField := func() uint64 {
		val := nativeEndianUint64(buf)
		buf = buf[8:]
		return val
	}
	c.Value = nextField()
	if ev.attr.ReadFormat.TotalTimeEnabled {
		c.TimeEnabled = time.Duration(nextField())
	}
	if ev.attr.ReadFormat.TotalTimeRunning {
		c.TimeRunning = time.Duration(nextField())
	}
	if ev.attr.ReadFormat.ID {
		c.ID = nextField()
	}
	return c, err
}

var errSingleEvent = errors.New("calling ReadGroupCount on non-group Event")

// ReadGroupCount reads the counts associated with ev.
//
// If the Event was not configued with ReadFormat.Group, ReadGroupCount
// returns an error.
func (ev *Event) ReadGroupCount() (GroupCount, error) {
	var gc GroupCount
	if err := ev.ok(); err != nil {
		return gc, err
	}
	if !ev.attr.ReadFormat.Group {
		return gc, errSingleEvent
	}
	headerSize := ev.attr.ReadFormat.groupReadHeaderSize()
	countsSize := (1 + len(ev.group)) * ev.attr.ReadFormat.groupReadCountSize()
	buf := make([]byte, headerSize+countsSize)
	_, err := unix.Read(ev.fd, buf)
	if err != nil {
		return gc, os.NewSyscallError("read", err)
	}
	nextField := func() uint64 {
		val := nativeEndianUint64(buf)
		buf = buf[8:]
		return val
	}
	nr := int(nextField())
	if ev.attr.ReadFormat.TotalTimeEnabled {
		gc.TimeEnabled = time.Duration(nextField())
	}
	if ev.attr.ReadFormat.TotalTimeRunning {
		gc.TimeRunning = time.Duration(nextField())
	}
	counts := make([]struct{ Value, ID uint64 }, 0, nr)
	for i := 0; i < nr; i++ {
		var c struct{ Value, ID uint64 }
		c.Value = nextField()
		if ev.attr.ReadFormat.ID {
			c.ID = nextField()
		}
		counts = append(counts, c)
	}
	gc.Counts = counts
	return gc, nil
}

// ReadRawRecord reads and decodes a sampling event from the ring buffer
// associated with ev into rec.
//
// ReadRawRecord may be called concurrently with ReadCount or ReadGroupCount,
// but not concurrently with Close or any other method.
func (ev *Event) ReadRawRecord(ctx context.Context, rec *RawRecord) error {
	if err := ev.ok(); err != nil {
		return err
	}
	// Fast path: try reading from the ring buffer first. If there is
	// a record there, we are done.
	if ev.readRawRecord(rec) {
		return nil
	}
	// If the context has a deadline, and that deadline is in the future,
	// use it to compute a timeout for ppoll(2). If the context is
	// expired, bail out. Otherwise, the timeout is zero, which means
	// no timeout.
	var timeout time.Duration
	deadline, ok := ctx.Deadline()
	if ok {
		timeout = deadline.Sub(time.Now())
		if timeout <= 0 {
			<-ctx.Done()
			return ctx.Err()
		}
	}
	// Start a round of polling.
	ev.pollreq <- pollreq{timeout: timeout}
	// Await results.
	select {
	case <-ctx.Done():
		active := false
		err := ctx.Err()
		if err == context.Canceled {
			// Initiate active wakeup. Send a signal on ev.evfd
			// and wait for doPoll to wake up. doPoll might miss
			// this signal, but that's okay: see below.
			unix.Write(ev.evfd, nativeEndian1Bytes)
			active = true
		}
		<-ev.pollresp
		// We don't know if doPoll woke up due to our active wakeup
		// or because it timed out. It doesn't make a difference.
		// The important detail here is that doPoll does not touch
		// ev.evfd (besides polling it for readiness). If we initiated
		// active wakeup, we must restore the event file descriptor
		// to quiescent state ourselves, in order to avoid a spurious
		// wakeup during the next round of polling.
		if active {
			var buf [8]byte
			unix.Read(ev.evfd, buf[:])
		}
		return err
	case resp := <-ev.pollresp:
		if resp.err != nil {
			// Polling failed. Nothing to do but report the error.
			return resp.err
		}
		if !resp.perfready {
			// Here, we have not touched ev.evfd, there was no
			// polling error, and ev.fd is not ready. Therefore,
			// ppoll(2) must have timed out. The reason we
			// are here is the following: doPoll woke up, and
			// immediately sent us a pollresp, which won the
			// race with <-ctx.Done(), such that this select
			// case fired. In any case, ctx is expired, because
			// we wouldn't be here otherwise.
			<-ctx.Done()
			return ctx.Err()
		}
		ev.readRawRecord(rec) // will succeed now
		return nil
	}
}

// RawRecord is a raw overflow record.
//
// TODO(acln): document that Data includes the Header bytes
type RawRecord struct {
	Header RecordHeader
	Data   []byte
}

func (raw *RawRecord) fields() recordFields {
	return recordFields(raw.Data[8:]) // first 8 bytes are header data
}

// readRawRecord reads (non-blocking) a raw record into rec.
//
// The boolean return value signals whether a record was actually found.
func (ev *Event) readRawRecord(rec *RawRecord) bool {
	head := atomic.LoadUint64(&ev.meta.Data_head)
	tail := atomic.LoadUint64(&ev.meta.Data_tail)
	if head == tail {
		return false
	}

	start := tail % uint64(len(ev.ringdata))
	rec.Header = *(*RecordHeader)(unsafe.Pointer(&ev.ringdata[start]))
	end := (tail + uint64(rec.Header.Size)) % uint64(len(ev.ringdata))

	var data []byte
	if end < start {
		// Record straddles the ring buffer. Allocate, in order to
		// return a contiguous area of memory to the caller.
		data = make([]byte, rec.Header.Size)
		n := copy(data, ev.ringdata[start:])
		copy(data[n:], ev.ringdata[:int(rec.Header.Size)-n])
	} else {
		data = ev.ringdata[start:end]
	}
	rec.Data = data

	atomic.AddUint64(&ev.meta.Data_tail, uint64(rec.Header.Size))
	return true
}

func (ev *Event) poll() {
	defer close(ev.pollresp)

	for req := range ev.pollreq {
		ev.pollresp <- ev.doPoll(req)
	}
}

// doPoll executes one round of polling on ev.fd and ev.evfd.
//
// A req.timeout of zero is interpreted as "no timeout".
func (ev *Event) doPoll(req pollreq) pollresp {
	var systimeout *unix.Timespec
	if req.timeout > 0 {
		sec := req.timeout / time.Second
		nsec := req.timeout - sec*time.Second
		systimeout = &unix.Timespec{
			Sec:  int64(sec),
			Nsec: int64(nsec),
		}
	}
	pollfds := []unix.PollFd{
		{Fd: int32(ev.fd), Events: unix.POLLIN},
		{Fd: int32(ev.evfd), Events: unix.POLLIN},
	}
again:
	_, err := unix.Ppoll(pollfds, systimeout, nil)
	if err == unix.EINTR {
		goto again
	}
	// If we are here and we have successfully woken up, it is for one
	// of three reasons: we got POLLIN on ev.fd, the ppoll(2) timeout
	// fired, or we got POLLIN on ev.evfd.
	//
	// Report if the perf fd is ready, and any errors except EINTR.
	// The machinery is documented in more detail in ReadRecord.
	return pollresp{
		perfready: pollfds[0].Revents&unix.POLLIN != 0,
		err:       os.NewSyscallError("ppoll", err),
	}
}

var (
	evfd1              = uint64(1)
	nativeEndian1Bytes = (*[8]byte)(unsafe.Pointer(&evfd1))[:]
)

// Close closes the event. Close must not be called concurrently with any
// other methods on the Event.
func (ev *Event) Close() error {
	atomic.StoreInt32(&ev.state, eventStateClosed)
	close(ev.pollreq)
	<-ev.pollresp
	unix.Munmap(ev.ring)
	unix.Close(ev.evfd)
	return unix.Close(ev.fd)
}

type pollreq struct {
	timeout time.Duration // timeout for ppoll(2): zero means no timeout
}

type pollresp struct {
	perfready bool  // is the perf FD ready?
	err       error // an *os.SyscallError, never contains EINTR
}

// An EventGroup configures a group of related events.
// The zero value of EventGroup is an empty group.
type EventGroup struct {
	events []*EventAttr
	labels []string
	// etc.
}

func (g *EventGroup) Open(pid int, cpu int, flags Flag) (*Event, error) {
	panic("not implemented")
}

// AddCounter adds a set of counters to the event group.
func (g *EventGroup) AddCounter(counters ...Counter) {
	for _, counter := range counters {
		g.AddEvent(counter.Label(), counter.EventAttr())
	}
	// maybe we need to set some flags here, investigate
	panic("not implemented")
}

// AddEvent adds the specified event to the group. The label need not be unique
// and may be empty.
func (g *EventGroup) AddEvent(label string, attr EventAttr) {
	panic("not implemented")
}

type Counter interface {
	Label() string
	EventAttr() EventAttr
}

// Count is a measurement taken by an Event.
//
// The Value field is always present and populated.
//
// The TimeEnabled field is populated if ReadFormat.TimeEnabled is set on
// the Event the Count was read from. Ditto for TimeRunning and ID.
type Count struct {
	Value       uint64
	TimeEnabled time.Duration
	TimeRunning time.Duration
	ID          uint64
}

// GroupCount is a group of measurements taken by an Event group.
//
// Fields are populated as described in the Count documentation.
type GroupCount struct {
	TimeEnabled time.Duration
	TimeRunning time.Duration
	Counts      []struct {
		Value uint64
		ID    uint64
	}
}

// EventAttr configures a perf event.
type EventAttr struct {
	// Type is the major type of the event.
	Type EventType

	// Config is the type-specific event configuration.
	Config uint64

	// Sample configures the sample period or sample frequency for
	// overflow packets, based on Options.Freq: if Options.Freq is set,
	// Sample is interpreted as "sample frequency", otherwise it is
	// interpreted as "sample period".
	Sample uint64

	// SampleFormat configures the format for overflow packets read from
	// the ring buffer associated with the event.
	SampleFormat SampleFormat

	// ReadFormat specifies the format of counts read from the event file
	// descriptor. See struct read_format in perf_event.h for details.
	//
	// TODO(acln): do better than send people to a C header.
	ReadFormat ReadFormat

	// Options contains fine grained event configuration.
	//
	// TODO(acln): this is not a great description.
	Options EventOptions

	// Wakeup configures event wakeup. If Options.Watermark is set,
	// Wakeup is interpreted as the number of bytes before wakeup.
	// Otherwise, it is interpreted as "wake up every n events".
	Wakeup uint32

	// BreakpointType is the breakpoint type, if Type == BreakpointEvent.
	BreakpointType uint32

	// Config1 is used for events that need an extra register or otherwise
	// do not fit in the regular config field.
	//
	// For breakpoint events, Config1 is the breakpoint address.
	// For kprobes, Config1 is the kprobe function. For uprobes, Config1
	// is the uprobe path.
	Config1 uint64

	// Config2 is a further extension of the Config1 field.
	//
	// For breakpoint events, Config2 is the length of the breakpoint.
	// For kprobes, when the kprobe function is NULL, Config2 is the
	// address of the kprobe. For both kprobes and uprobes, Config2 is
	// the probe offset.
	Config2 uint64

	// BranchSampleFormat specifies what branches to include in the
	// branch record, if SampleFormat.BranchStack is set.
	BranchSampleFormat BranchSampleFormat

	// SampleRegsUser is the set of user registers to dump on samples.
	SampleRegsUser uint64

	// SampleStackUser is the size of the user stack to  dump on samples.
	SampleStackUser uint32

	// ClockID is the clock ID to use with samples, if Options.UseClockID
	// is set.
	ClockID int32

	// SampleRegsInt is the set of register to dump for each sample.
	// See asm/perf_regs.h for details.
	SampleRegsInt uint64

	// AuxWatermark is the watermark for the aux area.
	AuxWatermark uint32

	// SampleMaxStack is the maximum number of frame pointers in a call
	// chain. It should be < /proc/sys/kernel/perf_event_max_stack.
	//
	// TODO(acln): this field does not exist in unix.PerfEventAttr.
	SampleMaxStack uint16
}

func (attr EventAttr) sysAttr() *unix.PerfEventAttr {
	return &unix.PerfEventAttr{
		Type:               uint32(attr.Type),
		Size:               uint32(unsafe.Sizeof(unix.PerfEventAttr{})),
		Config:             attr.Config,
		Sample:             attr.Sample,
		Sample_type:        attr.SampleFormat.marshal(),
		Read_format:        attr.ReadFormat.marshal(),
		Bits:               attr.Options.marshal(),
		Wakeup:             attr.Wakeup,
		Bp_type:            attr.BreakpointType,
		Ext1:               attr.Config1,
		Ext2:               attr.Config2,
		Branch_sample_type: uint64(attr.BranchSampleFormat),
		Sample_regs_user:   attr.SampleRegsUser,
		Sample_stack_user:  attr.SampleStackUser,
		Clockid:            attr.ClockID,
		Sample_regs_intr:   attr.SampleRegsInt,
		Aux_watermark:      attr.AuxWatermark,
	}
}

// SetSamplePeriod configures the sampling period for the event.
//
// It sets attr.Sample to p and attr.Options.Freq to false.
func (attr *EventAttr) SetSamplePeriod(p uint64) {
	attr.Sample = p
	attr.Options.Freq = false
}

// SetSampleFreq configures the sampling frequency for the event.
//
// It sets attr.Sample to f and enables attr.Options.Freq.
func (attr *EventAttr) SetSampleFreq(f uint64) {
	attr.Sample = f
	attr.Options.Freq = true
}

// EventType is the overall type of a performance event.
type EventType uint32

// Supported event types.
const (
	HardwareEvent      EventType = unix.PERF_TYPE_HARDWARE
	SoftwareEvent      EventType = unix.PERF_TYPE_SOFTWARE
	TracepointEvent    EventType = unix.PERF_TYPE_TRACEPOINT
	HardwareCacheEvent EventType = unix.PERF_TYPE_HW_CACHE
	RawEvent           EventType = unix.PERF_TYPE_RAW
	BreakpointEvent    EventType = unix.PERF_TYPE_BREAKPOINT
)

// ProbePMU probes /sys/bus/event_source/devices/<name>/type for the EventType
// value associated with the specified PMU.
func ProbePMU(name string) (EventType, error) {
	panic("not implemented")
}

// HardwareCounter is a hardware performance counter.
type HardwareCounter uint64

// Hardware counters.
const (
	CPUCycles             HardwareCounter = unix.PERF_COUNT_HW_CPU_CYCLES
	Instructions          HardwareCounter = unix.PERF_COUNT_HW_INSTRUCTIONS
	CacheReferences       HardwareCounter = unix.PERF_COUNT_HW_CACHE_REFERENCES
	CacheMisses           HardwareCounter = unix.PERF_COUNT_HW_CACHE_MISSES
	BranchInstructions    HardwareCounter = unix.PERF_COUNT_HW_BRANCH_INSTRUCTIONS
	BranchMisses          HardwareCounter = unix.PERF_COUNT_HW_BRANCH_MISSES
	BusCycles             HardwareCounter = unix.PERF_COUNT_HW_BUS_CYCLES
	StalledCyclesFrontend HardwareCounter = unix.PERF_COUNT_HW_STALLED_CYCLES_FRONTEND
	StalledCyclesBackend  HardwareCounter = unix.PERF_COUNT_HW_STALLED_CYCLES_BACKEND
	RefCPUCycles          HardwareCounter = unix.PERF_COUNT_HW_REF_CPU_CYCLES
)

func (hwc HardwareCounter) Label() string {
	// TODO(acln): figure out how to get at these:
	// https://github.com/golang/go/issues/21295#issuecomment-335519282
	panic("not implemented")
}

func (hwc HardwareCounter) EventAttr() EventAttr {
	return EventAttr{Type: HardwareEvent, Config: uint64(hwc)}
}

// AllHardwareCounters returns a slice of all known hardware counters.
func AllHardwareCounters() []Counter {
	return []Counter{
		CPUCycles,
		Instructions,
		CacheReferences,
		CacheMisses,
		BranchInstructions,
		BranchMisses,
		BusCycles,
		StalledCyclesFrontend,
		StalledCyclesBackend,
		RefCPUCycles,
	}
}

// SoftwareCounter is a software performance counter.
type SoftwareCounter uint64

// Software counters.
const (
	CPUClock        SoftwareCounter = unix.PERF_COUNT_SW_CPU_CLOCK
	TaskClock       SoftwareCounter = unix.PERF_COUNT_SW_TASK_CLOCK
	PageFaults      SoftwareCounter = unix.PERF_COUNT_SW_PAGE_FAULTS
	ContextSwitches SoftwareCounter = unix.PERF_COUNT_SW_CONTEXT_SWITCHES
	CPUMigrations   SoftwareCounter = unix.PERF_COUNT_SW_CPU_MIGRATIONS
	MinorPageFaults SoftwareCounter = unix.PERF_COUNT_SW_PAGE_FAULTS_MIN
	MajorPageFaults SoftwareCounter = unix.PERF_COUNT_SW_PAGE_FAULTS_MAJ
	AlignmentFaults SoftwareCounter = unix.PERF_COUNT_SW_ALIGNMENT_FAULTS
	EmulationFaults SoftwareCounter = unix.PERF_COUNT_SW_EMULATION_FAULTS
	Dummy           SoftwareCounter = unix.PERF_COUNT_SW_DUMMY
	BPFOutput       SoftwareCounter = 10 // TODO(acln): missing from x/sys/unix
)

func (swc SoftwareCounter) Label() string {
	panic("not implemented")
}

func (swc SoftwareCounter) EventAttr() EventAttr {
	return EventAttr{Type: SoftwareEvent, Config: uint64(swc)}
}

// AllSoftwareCounters returns a slice of all known software counters.
func AllSoftwareCounters() []Counter {
	return []Counter{
		CPUClock,
		TaskClock,
		PageFaults,
		ContextSwitches,
		CPUMigrations,
		MinorPageFaults,
		MajorPageFaults,
		AlignmentFaults,
		EmulationFaults,
		Dummy,
		BPFOutput,
	}
}

// Cache identifies a cache.
type Cache uint64

// Caches.
const (
	L1D  Cache = unix.PERF_COUNT_HW_CACHE_L1D
	L1I  Cache = unix.PERF_COUNT_HW_CACHE_L1I
	LL   Cache = unix.PERF_COUNT_HW_CACHE_LL
	DTLB Cache = unix.PERF_COUNT_HW_CACHE_DTLB
	ITLB Cache = unix.PERF_COUNT_HW_CACHE_ITLB
	BPU  Cache = unix.PERF_COUNT_HW_CACHE_BPU
	NODE Cache = unix.PERF_COUNT_HW_CACHE_NODE
)

// AllCaches returns a slice of all known cache types.
func AllCaches() []Cache {
	return []Cache{L1D, L1I, LL, DTLB, ITLB, BPU, NODE}
}

// CacheOp is a cache operation.
type CacheOp uint64

// Cache operations.
const (
	Read     CacheOp = unix.PERF_COUNT_HW_CACHE_OP_READ
	Write    CacheOp = unix.PERF_COUNT_HW_CACHE_OP_WRITE
	Prefetch CacheOp = unix.PERF_COUNT_HW_CACHE_OP_PREFETCH
)

// AllCacheOps returns a slice of all known cache operations.
func AllCacheOps() []CacheOp {
	return []CacheOp{Read, Write, Prefetch}
}

// CacheOpResult is the result of a cache operation.
type CacheOpResult uint64

// Cache operation results.
const (
	Access CacheOpResult = unix.PERF_COUNT_HW_CACHE_RESULT_ACCESS
	Miss   CacheOpResult = unix.PERF_COUNT_HW_CACHE_RESULT_MISS
)

// AllCacheOpResults returns a slice of all known cache operation results.
func AllCacheOpResults() []CacheOpResult {
	return []CacheOpResult{Access, Miss}
}

// A HardwareCacheCounter groups a cache, a cache operation, and an
// operation result.
type HardwareCacheCounter struct {
	Cache  Cache
	Op     CacheOp
	Result CacheOpResult
}

func (hwcc HardwareCacheCounter) Label() string {
	panic("not implemented")
}

func (hwcc HardwareCacheCounter) EventAttr() EventAttr {
	config := uint64(hwcc.Cache) | uint64(hwcc.Op<<8) | uint64(hwcc.Result<<16)
	return EventAttr{Type: HardwareCacheEvent, Config: config}
}

// HardwareCacheCounters returns triples of cache counters, measuring the specified
// caches, operations and results.
func HardwareCacheCounters(caches []Cache, ops []CacheOp, results []CacheOpResult) []Counter {
	counters := make([]Counter, 0, len(caches)*len(ops)*len(results))
	for _, cache := range caches {
		for _, op := range ops {
			for _, result := range results {
				c := HardwareCacheCounter{
					Cache:  cache,
					Op:     op,
					Result: result,
				}
				counters = append(counters, c)
			}
		}
	}
	return counters
}

// NewTracepoint probes /sys/kernel/debug/tracing/events/<category>/<event>/id
// for the value of the trace point associated with the specified category and
// event, and returns an *EventAttr with the Type and Config fields set
// to the appropriate values.
func NewTracepoint(category string, event string) (EventAttr, error) {
	f := filepath.Join("/sys/kernel/debug/tracing/events", category, event, "id")
	content, err := ioutil.ReadFile(f)
	if err != nil {
		return EventAttr{}, err
	}
	nr := strings.TrimSpace(string(content)) // remove trailing newline
	config, err := strconv.ParseUint(nr, 10, 64)
	if err != nil {
		return EventAttr{}, err
	}
	return EventAttr{
		Type:   TracepointEvent,
		Config: config,
	}, nil
}

// NewBreakpoint returns an EventAttr configured to record breakpoint events.
//
// typ is the type of the breakpoint.
//
// addr is the address of the breakpoint. For execution breakpoints, this is
// the memory address of the instruction of interest; for read and write breakpoints,
// it is the memory address of the memory location of interest.
//
// length is the length of the breakpoint being measured.
//
// Breakpoint sets the Type, BreakpointType, Config1 and Config2 fields on the
// returned Event.
func NewBreakpoint(typ BreakpointType, addr uint64, length BreakpointLength) EventAttr {
	return EventAttr{
		Type:           BreakpointEvent,
		BreakpointType: uint32(typ),
		Config1:        addr,
		Config2:        uint64(length),
	}
}

// TODO(acln): document this, add these constants, see ptrace.h.
type BreakpointType uint32

// TODO(acln): document this, add these constants, see ptrace.h.
type BreakpointLength uint64

// NewExecutionBreakpoint returns an Event configured to record an execution
// breakpoint at the specified address.
func NewExecutionBreakpoint(addr uint64) *EventAttr {
	panic("not implemented")
}

// SampleFormat configures information requested in overflow packets.
type SampleFormat struct {
	IP          bool
	Tid         bool
	Time        bool
	Addr        bool
	Read        bool
	Callchain   bool
	ID          bool
	CPU         bool
	Period      bool
	StreamID    bool
	Raw         bool
	BranchStack bool
	RegsUser    bool
	StackUser   bool
	Weight      bool
	DataSource  bool
	Identifier  bool
	Transaction bool
	RegsIntr    bool
	PhysAddr    bool
}

// marshal packs the SampleFormat into a uint64.
func (st SampleFormat) marshal() uint64 {
	// Always keep this in sync with the type definition above.
	fields := []bool{
		st.IP,
		st.Tid,
		st.Time,
		st.Addr,
		st.Read,
		st.Callchain,
		st.ID,
		st.CPU,
		st.Period,
		st.StreamID,
		st.Raw,
		st.BranchStack,
		st.RegsUser,
		st.StackUser,
		st.Weight,
		st.DataSource,
		st.Identifier,
		st.Transaction,
		st.RegsIntr,
		st.PhysAddr,
	}
	return marshalBitwiseUint64(fields)
}

// ReadFormat configures the format of Count or GroupCount measurements.
type ReadFormat struct {
	TotalTimeEnabled bool
	TotalTimeRunning bool
	ID               bool
	Group            bool
}

func (f ReadFormat) readSize() int {
	size := 8 // value is always set
	if f.TotalTimeEnabled {
		size += 8
	}
	if f.TotalTimeRunning {
		size += 8
	}
	if f.ID {
		size += 8
	}
	return size
}

func (f ReadFormat) groupReadHeaderSize() int {
	size := 8 // number of events is always set
	if f.TotalTimeEnabled {
		size += 8
	}
	if f.TotalTimeRunning {
		size += 8
	}
	return size
}

func (f ReadFormat) groupReadCountSize() int {
	size := 8 // value is always set
	if f.ID {
		size += 8
	}
	return size
}

// marshal marshals the ReadFormat into a uint64.
func (f ReadFormat) marshal() uint64 {
	// Always keep this in sync with the type definition above.
	fields := []bool{
		f.TotalTimeEnabled,
		f.TotalTimeRunning,
		f.ID,
		f.Group,
	}
	return marshalBitwiseUint64(fields)
}

// EventOptions contains low level event options.
type EventOptions struct {
	Disabled               bool // off by default
	Inherit                bool // children inherit it
	Pinned                 bool // must always be on PMU
	Exclusive              bool // only group on PMU
	ExcludeUser            bool // don't count user
	ExcludeKernel          bool // ditto kernel
	ExcludeHypervisor      bool // ditto hypervisor
	ExcludeIdle            bool // don't count when idle
	Mmap                   bool // include mmap data
	Comm                   bool // include comm data
	Freq                   bool // use frequency, not period
	InheritStat            bool // per task counts
	EnableOnExec           bool // next exec enables
	Task                   bool // trace fork/exit
	Watermark              bool // wake up at watermark
	PreciseIP              Skid // skid constraint
	MmapData               bool // non-exec mmap data
	SampleIDAll            bool // include all events in SampleFormat
	ExcludeHost            bool // don't count in host
	ExcludeGuest           bool // don't count in guest
	ExcludeCallchainKernel bool // exclude kernel callchains
	ExcludeCallchainUser   bool // exclude user callchains
	Mmap2                  bool // include mmap with inode data
	CommExec               bool // flag comm events that are due to an exec
	UseClockID             bool // use ClockID for time fields
	ContextSwitch          bool // context switch data
	WriteBackward          bool // TODO(acln): support this at all?
	Namespaces             bool // include namespaces data
}

func (opt EventOptions) marshal() uint64 {
	fields := []bool{
		opt.Disabled,
		opt.Inherit,
		opt.Pinned,
		opt.Exclusive,
		opt.ExcludeUser,
		opt.ExcludeKernel,
		opt.ExcludeHypervisor,
		opt.ExcludeIdle,
		opt.Mmap,
		opt.Comm,
		opt.Freq,
		opt.InheritStat,
		opt.EnableOnExec,
		opt.Task,
		opt.Watermark,
		false, false, // 2 bits for skid constraint, TODO
		opt.MmapData,
		opt.SampleIDAll,
		opt.ExcludeHost,
		opt.ExcludeGuest,
		opt.ExcludeCallchainKernel,
		opt.ExcludeCallchainUser,
		opt.Mmap2,
		opt.CommExec,
		opt.UseClockID,
		opt.ContextSwitch,
		opt.WriteBackward,
		opt.Namespaces,
	}
	return marshalBitwiseUint64(fields)
}

// Skid is an instruction pointer skid constraint.
type Skid int

// Supported Skid settings.
const (
	CanHaveArbitrarySkid Skid = 0
	MustHaveConstantSkid Skid = 1
	RequestedZeroSkid    Skid = 2
	MustHaveZeroSkid     Skid = 3
)

// BranchSampleFormat ...
type BranchSampleFormat uint32

// Branch sample types.
const (
	BranchSampleUser         BranchSampleFormat = unix.PERF_SAMPLE_BRANCH_USER
	BranchSampleKernel       BranchSampleFormat = unix.PERF_SAMPLE_BRANCH_KERNEL
	BranchSampleHypervisor   BranchSampleFormat = unix.PERF_SAMPLE_BRANCH_HV
	BranchSampleAny          BranchSampleFormat = unix.PERF_SAMPLE_BRANCH_ANY
	BranchSampleAnyCall      BranchSampleFormat = unix.PERF_SAMPLE_BRANCH_ANY_CALL
	BranchSampleAnyReturn    BranchSampleFormat = unix.PERF_SAMPLE_BRANCH_ANY_RETURN
	BranchSampleIndirectCall BranchSampleFormat = unix.PERF_SAMPLE_BRANCH_IND_CALL

	BranchSampleAbortTransaction BranchSampleFormat = 1 << (7 + iota) // TODO(acln): missing from x/sys/unix
	BranchSampleInTransaction
	BranchSampleNoTransaction
	BranchSampleCond
	BranchSampleCallStack
	BranchSampleIndirectJump
	BranchSampleCall
	BranchSampleNoFlags
	BranchSampleNoCycles
	BranchSampleSave
)

// RecordType is the type of an overflow record.
//
// TODO(acln): add these constants
type RecordType uint32

// Known record types.
const ()

// RecordHeader is the header present in every overflow record.
type RecordHeader struct {
	Type RecordType
	Misc uint16
	Size uint16
}

// Header returns rh, such that types which embed a RecordHeader
// automatically implement the Record interface.
func (rh RecordHeader) Header() RecordHeader { return rh }

// RecordID contains identifiers for when and where a record was collected.
//
// See struct sample_id in the perf_event_open manual page.
//
// TODO(acln): document the relationship between this and SampleFormat.
type RecordID struct {
	Pid        uint32
	Tid        uint32
	Time       uint64
	ID         uint64
	StreamID   uint64
	CPU        uint32
	Res        uint32
	Identifier uint64
}

type recordFields []byte

func (rf *recordFields) uint64(v *uint64) {
	*v = *(*uint64)(unsafe.Pointer(&(*rf)[0]))
	*rf = (*rf)[8:]
}

func (rf *recordFields) uint64If(cond bool, v *uint64) {
	if cond {
		rf.uint64(v)
	}
}

func (rf *recordFields) uint32(a, b *uint32) {
	*a = *(*uint32)(unsafe.Pointer(&(*rf)[0]))
	*b = *(*uint32)(unsafe.Pointer(&(*rf)[4]))
	*rf = (*rf)[8:]
}

func (rf *recordFields) uint32If(cond bool, a, b *uint32) {
	if cond {
		rf.uint32(a, b)
	}
}

func (rf *recordFields) string(s *string) {
	*s = "TODO"
}

func (rf *recordFields) id(id *RecordID, ev *Event) {
	if !ev.attr.Options.SampleIDAll {
		return
	}
	rf.uint32If(ev.attr.SampleFormat.Tid, &id.Pid, &id.Tid)
	rf.uint64If(ev.attr.SampleFormat.Time, &id.Time)
	rf.uint64If(ev.attr.SampleFormat.ID, &id.ID)
	rf.uint64If(ev.attr.SampleFormat.StreamID, &id.StreamID)
	rf.uint32If(ev.attr.SampleFormat.CPU, &id.CPU, &id.Res)
	rf.uint64If(ev.attr.SampleFormat.Identifier, &id.Identifier)
}

type MmapRecord struct {
	RecordHeader
	Pid      uint32
	Tid      uint32
	Addr     uint64
	Len      uint64
	Pgoff    uint64
	Filename string
	RecordID
}

func (mr *MmapRecord) DecodeFrom(raw *RawRecord, ev *Event) {
	mr.RecordHeader = raw.Header
	rf := raw.fields()
	rf.uint32(&mr.Pid, &mr.Tid)
	rf.uint64(&mr.Addr)
	rf.uint64(&mr.Len)
	rf.uint64(&mr.Pgoff)
	rf.string(&mr.Filename)
	rf.id(&mr.RecordID, ev)
}

type LostRecord struct {
	RecordHeader
	ID   uint64
	Lost uint64
	RecordID
}

func (lr *LostRecord) DecodeFrom(raw *RawRecord, ev *Event) {
	lr.RecordHeader = raw.Header
	rf := raw.fields()
	rf.uint64(&lr.ID)
	rf.uint64(&lr.Lost)
	rf.id(&lr.RecordID, ev)
}

type CommRecord struct {
	RecordHeader
	Pid  uint32
	Tid  uint32
	Comm string
	RecordID
}

func (cr *CommRecord) DecodeFrom(raw *RawRecord, ev *Event) {
	cr.RecordHeader = raw.Header
	rf := raw.fields()
	rf.uint32(&cr.Pid, &cr.Tid)
	rf.string(&cr.Comm)
	rf.id(&cr.RecordID, ev)
}

type ExitRecord struct {
	RecordHeader
	Pid  uint32
	Ppid uint32
	Tid  uint32
	Ptid uint32
	Time uint64
	RecordID
}

func (er *ExitRecord) DecodeFrom(raw *RawRecord, ev *Event) {
	er.RecordHeader = raw.Header
	rf := raw.fields()
	rf.uint32(&er.Pid, &er.Ppid)
	rf.uint32(&er.Tid, &er.Ptid)
	rf.uint64(&er.Time)
	rf.id(&er.RecordID, ev)
}

type ThrottleRecord struct {
	RecordHeader
	Time     uint64
	ID       uint64
	StreamID uint64
	RecordID
}

func (tr *ThrottleRecord) DecodeFrom(raw *RawRecord, ev *Event) {
	tr.RecordHeader = raw.Header
	rf := raw.fields()
	rf.uint64(&tr.Time)
	rf.uint64(&tr.ID)
	rf.uint64(&tr.StreamID)
	rf.id(&tr.RecordID, ev)
}

type UnthrottleRecord struct {
	RecordHeader
	Time     uint64
	ID       uint64
	StreamID uint64
	RecordID
}

func (ur *UnthrottleRecord) DecodeFrom(raw *RawRecord, ev *Event) {
	ur.RecordHeader = raw.Header
	rf := raw.fields()
	rf.uint64(&ur.Time)
	rf.uint64(&ur.ID)
	rf.uint64(&ur.StreamID)
	rf.id(&ur.RecordID, ev)
}

type ForkRecord struct {
	RecordHeader
	Pid  uint32
	Ppid uint32
	Tid  uint32
	Ptid uint32
	Time uint64
	RecordID
}

func (fr *ForkRecord) DecodeFrom(raw *RawRecord, ev *Event) {
	fr.RecordHeader = raw.Header
	rf := raw.fields()
	rf.uint32(&fr.Pid, &fr.Ppid)
	rf.uint32(&fr.Tid, &fr.Ptid)
	rf.uint64(&fr.Time)
	rf.id(&fr.RecordID, ev)
}

type ReadRecord struct {
	RecordHeader
	Pid    uint32
	Tid    uint32
	Values ReadFormat
	RecordID
}

func (rr *ReadRecord) DecodeFrom(raw *RawRecord, ev *Event) {
	rr.RecordHeader = raw.Header
	rf := raw.fields()
	rf.uint32(&rr.Pid, &rr.Tid)
	// TODO(acln): values
}

type SampleRecord struct {
	// ABI fields:

	RecordHeader
	Identifier uint64
	IP         uint64
	Pid        uint32
	Tid        uint32
	Time       uint64
	Addr       uint64
	ID         uint64
	StreamID   uint64
	CPU        uint32
	Res        uint32
	Period     uint64
	Values     ReadFormat
	Callchain  []uint64

	// Non-ABI fields:

	Data        []byte
	BranchStack []struct {
		From  uint64
		To    uint64
		Flags uint64
	}
	UserRegsABI      uint64
	UserRegs         []uint64
	UserStackSize    uint64
	UserStackData    []uint64
	UserStackDynSize uint64
	Weight           uint64
	DataSrc          uint64
	Transaction      uint64
	IntrRegsABI      uint64
	IntrRegs         []uint64
	PhysAddr         uint64
}

func (sr *SampleRecord) DecodeFrom(raw *RawRecord, ev *Event) {
	sr.RecordHeader = raw.Header
	rf := raw.fields()
	rf.uint64If(ev.attr.SampleFormat.Identifier, &sr.Identifier)
	rf.uint64If(ev.attr.SampleFormat.IP, &sr.IP)
	rf.uint32If(ev.attr.SampleFormat.Tid, &sr.Pid, &sr.Tid)
	rf.uint64If(ev.attr.SampleFormat.Time, &sr.Time)
	rf.uint64If(ev.attr.SampleFormat.Addr, &sr.Addr)
	rf.uint64If(ev.attr.SampleFormat.ID, &sr.ID)
	rf.uint64If(ev.attr.SampleFormat.StreamID, &sr.StreamID)
	rf.uint32If(ev.attr.SampleFormat.CPU, &sr.CPU, &sr.Res)
	rf.uint64If(ev.attr.SampleFormat.Period, &sr.Period)
	// TODO(acln): values
	// TODO(acln): callchain
	// TODO(acln): non-ABI bits
}

type Mmap2Record struct {
	RecordHeader
	Pid           uint32
	Tid           uint32
	Addr          uint64
	Len           uint64
	Pgoff         uint64
	Maj           uint32
	Min           uint32
	Ino           uint64
	InoGeneration uint64
	Prot          uint32
	Flags         uint32
	Filename      string
	RecordID
}

func (mr *Mmap2Record) DecodeFrom(raw *RawRecord, ev *Event) {
	mr.RecordHeader = raw.Header
	rf := raw.fields()
	rf.uint32(&mr.Pid, &mr.Tid)
	rf.uint64(&mr.Addr)
	rf.uint64(&mr.Len)
	rf.uint64(&mr.Pgoff)
	rf.uint32(&mr.Maj, &mr.Min)
	rf.uint64(&mr.Ino)
	rf.uint64(&mr.InoGeneration)
	rf.uint32(&mr.Prot, &mr.Flags)
	rf.string(&mr.Filename)
	rf.id(&mr.RecordID, ev)
}

type AuxRecord struct {
	RecordHeader
	AuxOffset uint64
	AuxSize   uint64
	Flags     uint64
	RecordID
}

func (ar *AuxRecord) DecodeFrom(raw *RawRecord, ev *Event) {
	ar.RecordHeader = raw.Header
	rf := raw.fields()
	rf.uint64(&ar.AuxOffset)
	rf.uint64(&ar.AuxSize)
	rf.uint64(&ar.Flags)
	rf.id(&ar.RecordID, ev)
}

type ItraceStartRecord struct {
	RecordHeader
	Pid uint32
	Tid uint32
	RecordID
}

func (ir *ItraceStartRecord) DecodeFrom(raw *RawRecord, ev *Event) {
	ir.RecordHeader = raw.Header
	rf := raw.fields()
	rf.uint32(&ir.Pid, &ir.Tid)
	rf.id(&ir.RecordID, ev)
}

type SwitchRecord struct {
	RecordHeader
	RecordID
}

func (sr *SwitchRecord) DecodeFrom(raw *RawRecord, ev *Event) {
	sr.RecordHeader = raw.Header
	rf := raw.fields()
	rf.id(&sr.RecordID, ev)
}

type CPUWideSwitchRecord struct {
	RecordHeader
	Pid uint32
	Tid uint32
	RecordID
}

func (sr *CPUWideSwitchRecord) DecodeFrom(raw *RawRecord, ev *Event) {
	sr.RecordHeader = raw.Header
	rf := raw.fields()
	rf.uint32(&sr.Pid, &sr.Tid)
	rf.id(&sr.RecordID, ev)
}

type NamespacesRecord struct {
	RecordHeader
	Pid        uint32
	Tid        uint32
	Namespaces []struct {
		Dev   uint64
		Inode uint64
	}
	RecordID
}

func (nr *NamespacesRecord) DecodeFrom(raw *RawRecord, ev *Event) {
	nr.RecordHeader = raw.Header
	rf := raw.fields()
	rf.uint32(&nr.Pid, &nr.Tid)
	var num uint64
	rf.uint64(&num)
	nr.Namespaces = make([]struct{ Dev, Inode uint64 }, num)
	for i := 0; i < int(num); i++ {
		rf.uint64(&nr.Namespaces[i].Dev)
		rf.uint64(&nr.Namespaces[i].Inode)
	}
	rf.id(&nr.RecordID, ev)
}

// A File wraps a perf.data file and decodes the records therein.
type File struct {
	fd *os.File
}

// OpenFile opens a perf.data file for reading.
func OpenFile(r io.ReaderAt) (*File, error) {
	panic("not implemented")
}

func (f *File) ReadRawRecord(rr *RawRecord) error {
	panic("not implemented")
}

// TODO(acln): github.com/aclements/go-perf/perffile has perhaps a nicer API than this: investigate

func marshalBitwiseUint64(fields []bool) uint64 {
	var res uint64
	for shift, set := range fields {
		if set {
			res |= 1 << uint(shift)
		}
	}
	return res
}
