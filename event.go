// Copyright 2019 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package perf

import (
	"errors"
	"io/ioutil"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// Special pid values for Open.
const (
	// CallingThread configures the event to measure the calling thread.
	CallingThread = 0

	// AllThreads configures the event to measure all threads on the
	// specified CPU.
	AllThreads = -1
)

// AnyCPU configures the specified process/thread to be measured on any CPU.
const AnyCPU = -1

// Flag is a set of flags for Open. Values are or-ed together.
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
	cloexec Flag = unix.PERF_FLAG_FD_CLOEXEC
)

// Event states.
const (
	eventStateUninitialized = 0
	eventStateOK            = 1
	eventStateClosed        = 2
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
	// It is a clone of the original.
	attr *Attr

	// ring is the (entire) memory mapped ring buffer.
	ring []byte

	// ringdata is the data region of the ring buffer.
	ringdata []byte

	// meta is the metadata page: &ring[0].
	meta *unix.PerfEventMmapPage

	// evfd is an event file descriptor (see eventfd(2)): it is used to
	// unblock calls to ppoll(2) on the perf fd.
	evfd int

	// pollreq communicates requests from ReadRawRecord to the poll goroutine
	// associated with the ring.
	pollreq chan pollreq

	// pollresp receives responses from the poll goroutine associated
	// with the ring, back to ReadRawRecord.
	pollresp chan pollresp
}

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
func Open(attr *Attr, pid, cpu int, group *Event, flags Flag) (*Event, error) {
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
	attrClone := new(Attr)
	*attrClone = *attr // ok to copy since no slices
	ev := &Event{
		state:    eventStateOK,
		fd:       fd,
		attr:     attrClone,
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
	go ev.poll() // TODO(acln): start this lazily somehow?
	return ev, nil
}

func (ev *Event) ok() error {
	if ev == nil {
		return os.ErrInvalid
	}
	switch ev.state {
	case eventStateUninitialized:
		return os.ErrInvalid
	case eventStateOK:
		return nil
	default: // eventStateClosed
		return os.ErrClosed
	}
}

// Measure disables the event, resets it, enables it, runs f, disables it again,
// then reads the Count associated with the event.
func (ev *Event) Measure(f func()) (Count, error) {
	if err := ev.Disable(); err != nil {
		return Count{}, err
	}
	if err := ev.Reset(); err != nil {
		return Count{}, err
	}
	if err := ev.Enable(); err != nil {
		return Count{}, err
	}
	f()
	if err := ev.Disable(); err != nil {
		return Count{}, err
	}
	return ev.ReadCount()
}

// MeasureGroup is like Measure, but for event groups.
func (ev *Event) MeasureGroup(f func()) (GroupCount, error) {
	if err := ev.Disable(); err != nil {
		return GroupCount{}, err
	}
	if err := ev.Reset(); err != nil {
		return GroupCount{}, err
	}
	if err := ev.Enable(); err != nil {
		return GroupCount{}, err
	}
	f()
	if err := ev.Disable(); err != nil {
		return GroupCount{}, err
	}
	return ev.ReadGroupCount()
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

// TODO(acln): (*Event).Refresh, which means handling POLLHUP

// Reset resets the counters associated with the event.
func (ev *Event) Reset() error {
	if err := ev.ok(); err != nil {
		return err
	}
	return ioctlReset(ev.fd)
}

// UpdatePeriod updates the overflow period for the event. On older kernels,
// the new period does not take effect until after the next overflow.
func (ev *Event) UpdatePeriod(p uint64) error {
	if err := ev.ok(); err != nil {
		return err
	}
	return ioctlPeriod(ev.fd, &p)
}

// SetOutput tells the kernel to report event notifications to the specified
// target Event rather than ev. ev and target must be on the same CPU.
//
// If target is nil, output from ev is ignored.
func (ev *Event) SetOutput(target *Event) error {
	if err := ev.ok(); err != nil {
		return err
	}
	if target == nil {
		return ioctlSetOutput(ev.fd, -1)
	}
	if err := target.ok(); err != nil {
		return err
	}
	return ioctlSetOutput(ev.fd, target.fd)
}

// TODO(acln): (*Event).SetFtraceFilter

// ID returns the unique event ID value for ev.
func (ev *Event) ID() (uint64, error) {
	if err := ev.ok(); err != nil {
		return 0, err
	}
	var val uint64
	err := ioctlID(ev.fd, &val)
	return val, err
}

// SetBPF attaches a BPF program to ev, which must be a kprobe tracepoint
// event. progfd is the file descriptor associated with the BPF program.
func (ev *Event) SetBPF(progfd uint32) error {
	if err := ev.ok(); err != nil {
		return err
	}
	return ioctlSetBPF(ev.fd, progfd)
}

// PauseOutput pauses the output from ev.
func (ev *Event) PauseOutput() error {
	if err := ev.ok(); err != nil {
		return err
	}
	return ioctlPauseOutput(ev.fd, 1)
}

// ResumeOutput resumes output from ev.
func (ev *Event) ResumeOutput() error {
	if err := ev.ok(); err != nil {
		return err
	}
	return ioctlPauseOutput(ev.fd, 0)
}

// QueryBPF queries the event for BPF program file descriptors attached to
// the same tracepoint as ev. max is the maximum number of file descriptors
// to return.
func (ev *Event) QueryBPF(max uint32) ([]uint32, error) {
	if err := ev.ok(); err != nil {
		return nil, err
	}
	return ioctlQueryBPF(ev.fd, max)
}

// ModifyAttributes modifies the attributes of an event.
func (ev *Event) ModifyAttributes(attr Attr) error {
	if err := ev.ok(); err != nil {
		return err
	}
	return ioctlModifyAttributes(ev.fd, attr.sysAttr())
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

// ReadCount reads the measurement associated with ev. If the Event was
// configured with CountFormat.Group, ReadCount returns an error.
func (ev *Event) ReadCount() (Count, error) {
	var c Count
	if err := ev.ok(); err != nil {
		return c, err
	}
	if ev.attr.CountFormat.Group {
		return c, errors.New("calling ReadCount on group Event")
	}
	// TODO(acln): use rdpmc on x86 instead of read(2)?
	buf := make([]byte, ev.attr.CountFormat.readSize())
	_, err := unix.Read(ev.fd, buf)
	if err != nil {
		return c, os.NewSyscallError("read", err)
	}
	f := fields(buf)
	f.count(&c, ev)
	return c, err
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

// ReadGroupCount reads the measurements associated with ev. If the Event
// was not configued with CountFormat.Group, ReadGroupCount returns an error.
func (ev *Event) ReadGroupCount() (GroupCount, error) {
	var gc GroupCount
	if err := ev.ok(); err != nil {
		return gc, err
	}
	if !ev.attr.CountFormat.Group {
		return gc, errors.New("calling ReadGroupCount on non-group Event")
	}
	headerSize := ev.attr.CountFormat.groupReadHeaderSize()
	countsSize := (1 + len(ev.group)) * ev.attr.CountFormat.groupReadCountSize()
	buf := make([]byte, headerSize+countsSize)
	_, err := unix.Read(ev.fd, buf)
	if err != nil {
		return gc, os.NewSyscallError("read", err)
	}
	f := fields(buf)
	f.groupCount(&gc, ev)
	return gc, nil
}

// Close closes the event. Close must not be called concurrently with any
// other methods on the Event.
func (ev *Event) Close() error {
	ev.state = eventStateClosed
	close(ev.pollreq)
	<-ev.pollresp
	muerr := unix.Munmap(ev.ring)
	evfderr := unix.Close(ev.evfd)
	cerr := unix.Close(ev.fd)
	if muerr != nil {
		return muerr
	}
	if evfderr != nil {
		return evfderr
	}
	return cerr
}

// Attr configures a perf event.
type Attr struct {
	// Type is the major type of the event.
	Type EventType

	// Config is the type-specific event configuration.
	Config uint64

	// Sample configures the sample period or sample frequency for
	// overflow packets, based on Options.Freq: if Options.Freq is set,
	// Sample is interpreted as "sample frequency", otherwise it is
	// interpreted as "sample period".
	Sample uint64

	// RecordFormat configures the format for overflow packets read from
	// the ring buffer associated with the event.
	RecordFormat RecordFormat

	// CountFormat specifies the format of counts read from the
	// Event using ReadCount or ReadGroupCount. See the CountFormat
	// documentation for more details.
	CountFormat CountFormat

	// Options contains more fine grained event configuration.
	Options Options

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

	// SampleRegsIntr is the set of register to dump for each sample.
	// See asm/perf_regs.h for details.
	SampleRegsIntr uint64

	// AuxWatermark is the watermark for the aux area.
	AuxWatermark uint32

	// SampleMaxStack is the maximum number of frame pointers in a call
	// chain. It should be < /proc/sys/kernel/perf_event_max_stack.
	SampleMaxStack uint16
}

func (a Attr) sysAttr() *unix.PerfEventAttr {
	return &unix.PerfEventAttr{
		Type:               uint32(a.Type),
		Size:               uint32(unsafe.Sizeof(unix.PerfEventAttr{})),
		Config:             a.Config,
		Sample:             a.Sample,
		Sample_type:        a.RecordFormat.marshal(),
		Read_format:        a.CountFormat.marshal(),
		Bits:               a.Options.marshal(),
		Wakeup:             a.Wakeup,
		Bp_type:            a.BreakpointType,
		Ext1:               a.Config1,
		Ext2:               a.Config2,
		Branch_sample_type: a.BranchSampleFormat.marshal(),
		Sample_regs_user:   a.SampleRegsUser,
		Sample_stack_user:  a.SampleStackUser,
		Clockid:            a.ClockID,
		Sample_regs_intr:   a.SampleRegsIntr,
		Aux_watermark:      a.AuxWatermark,
		Sample_max_stack:   a.SampleMaxStack,
	}
}

// SetSamplePeriod configures the sampling period for the event.
//
// It sets attr.Sample to p and attr.Options.Freq to false.
func (a *Attr) SetSamplePeriod(p uint64) {
	a.Sample = p
	a.Options.Freq = false
}

// SetSampleFreq configures the sampling frequency for the event.
//
// It sets attr.Sample to f and enables attr.Options.Freq.
func (a *Attr) SetSampleFreq(f uint64) {
	a.Sample = f
	a.Options.Freq = true
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
	p := filepath.Join("/sys/bus/event_source/devices", name, "type")
	content, err := ioutil.ReadFile(p)
	if err != nil {
		return 0, err
	}
	nr := strings.TrimSpace(string(content)) // remove trailing newline
	et, err := strconv.ParseUint(nr, 10, 32)
	if err != nil {
		return 0, err
	}
	return EventType(et), nil
}

// HardwareCounter is a hardware performance counter.
type HardwareCounter uint64

// Hardware performance counters.
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

func (hwc HardwareCounter) MarshalAttr() Attr {
	return Attr{Type: HardwareEvent, Config: uint64(hwc)}
}

// AllHardwareCounters returns a slice of all known hardware counters.
func AllHardwareCounters() []TODOInterfaceName {
	return []TODOInterfaceName{
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

// Software performance counters.
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
	BPFOutput       SoftwareCounter = unix.PERF_COUNT_SW_BPF_OUTPUT
)

func (swc SoftwareCounter) Label() string {
	panic("not implemented")
}

func (swc SoftwareCounter) MarshalAttr() Attr {
	return Attr{Type: SoftwareEvent, Config: uint64(swc)}
}

// AllSoftwareCounters returns a slice of all known software counters.
func AllSoftwareCounters() []TODOInterfaceName {
	return []TODOInterfaceName{
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

// A HardwareCacheCounter groups a cache, a cache operation, and an operation
// result.
type HardwareCacheCounter struct {
	Cache  Cache
	Op     CacheOp
	Result CacheOpResult
}

func (hwcc HardwareCacheCounter) Label() string {
	panic("not implemented")
}

func (hwcc HardwareCacheCounter) MarshalAttr() Attr {
	config := uint64(hwcc.Cache) | uint64(hwcc.Op<<8) | uint64(hwcc.Result<<16)
	return Attr{Type: HardwareCacheEvent, Config: config}
}

// HardwareCacheCounters returns cache counters which measure the cartesian
// product of the specified caches, operations and results.
func HardwareCacheCounters(caches []Cache, ops []CacheOp, results []CacheOpResult) []TODOInterfaceName {
	counters := make([]TODOInterfaceName, 0, len(caches)*len(ops)*len(results))
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
// for the value of the trace point associated with the specified category
// and event, and returns an *MarshalAttr with the Type and Config fields
// set to the appropriate values.
func NewTracepoint(category string, event string) (*Attr, error) {
	f := filepath.Join("/sys/kernel/debug/tracing/events", category, event, "id")
	content, err := ioutil.ReadFile(f)
	if err != nil {
		return nil, err
	}
	nr := strings.TrimSpace(string(content)) // remove trailing newline
	config, err := strconv.ParseUint(nr, 10, 64)
	if err != nil {
		return nil, err
	}
	return &Attr{Type: TracepointEvent, Config: config}, nil
}

// NewBreakpoint returns an MarshalAttr configured to record breakpoint events.
//
// typ is the type of the breakpoint.
//
// addr is the address of the breakpoint. For execution breakpoints, this
// is the memory address of the instruction of interest; for read and write
// breakpoints, it is the memory address of the memory location of interest.
//
// length is the length of the breakpoint being measured.
//
// Breakpoint sets the Type, BreakpointType, Config1 and Config2 fields on
// the returned MarshalAttr.
func NewBreakpoint(typ BreakpointType, addr uint64, length BreakpointLength) *Attr {
	return &Attr{
		Type:           BreakpointEvent,
		BreakpointType: uint32(typ),
		Config1:        addr,
		Config2:        uint64(length),
	}
}

// BreakpointType is the type of a breakpoint.
type BreakpointType uint32

// Breakpoint types. Values are |-ed together. The combination of
// BreakpointTypeR or BreakpointTypeW with BreakpointTypeX is invalid.
//
// TODO(acln): add these to x/sys/unix?
const (
	BreakpointTypeEmpty BreakpointType = 0x0
	BreakpointTypeR     BreakpointType = 0x1
	BreakpointTypeW     BreakpointType = 0x2
	BreakpointTypeRW                   = BreakpointTypeR | BreakpointTypeW
	BreakpointTypeX                    = 0x4
)

// BreakpointLength is the length of the breakpoint being measured.
type BreakpointLength uint64

// Breakpoint length values.
//
// TODO(acln): add these to x/sys/unix?
const (
	BreakpointLength1 BreakpointLength = 1
	BreakpointLength2 BreakpointLength = 2
	BreakpointLength4 BreakpointLength = 4
	BreakpointLength8 BreakpointLength = 8
)

// ExecutionBreakpointLength returns the length of an execution breakpoint.
//
func ExecutionBreakpointLength() BreakpointLength {
	// TODO(acln): is this correct? The man page says to set this to
	// sizeof(long). Is sizeof(C long) == sizeof(Go uintptr) on all
	// platforms of interest?
	var x uintptr
	return BreakpointLength(unsafe.Sizeof(x))
}

// NewExecutionBreakpoint returns an Event configured to record an execution
// breakpoint at the specified address.
func NewExecutionBreakpoint(addr uint64) *Attr {
	return NewBreakpoint(BreakpointTypeX, addr, ExecutionBreakpointLength())
}

// CountFormat configures the format of Count or GroupCount measurements.
//
// TotalTimeEnabled and TotalTimeRunning configure the Event to include time
// enabled and time running measurements to the counts. Usually, these two
// values are equal. They may differ when events are multiplexed.
// TODO(acln): elaborate, see also time_shift and time_mul on the mmap meta page
//
// If ID is set, a unique ID is assigned to the associated event.
//
// TODO(acln): mention that the returned ID is the same as what we get
// from the ID method / ioctl (after verifying using tests).
//
// If Group is set, callers must use ReadGroupCount on the associated Event.
// Otherwise, they must use ReadCount.
type CountFormat struct {
	TotalTimeEnabled bool
	TotalTimeRunning bool
	ID               bool
	Group            bool
}

func (f CountFormat) readSize() int {
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

func (f CountFormat) groupReadHeaderSize() int {
	size := 8 // number of events is always set
	if f.TotalTimeEnabled {
		size += 8
	}
	if f.TotalTimeRunning {
		size += 8
	}
	return size
}

func (f CountFormat) groupReadCountSize() int {
	size := 8 // value is always set
	if f.ID {
		size += 8
	}
	return size
}

// marshal marshals the CountFormat into a uint64.
func (f CountFormat) marshal() uint64 {
	// Always keep this in sync with the type definition above.
	fields := []bool{
		f.TotalTimeEnabled,
		f.TotalTimeRunning,
		f.ID,
		f.Group,
	}
	return marshalBitwiseUint64(fields)
}

// Options contains low level event options.
type Options struct {
	// Disabled disables the event by default. If the event is in a
	// group, but not a group leader, this option has no effect, since
	// the group leader controls when events are enabled or disabled.
	Disabled bool

	// Inherit specifies that this counter should count events of child
	// tasks as well as the specified task. This only applies to new
	// children, not to any existing children at the time the counter
	// is created (nor to any new children of existing children).
	//
	// Inherit does not work with some combination of CountFormat options,
	// such as CountFormat.Group.
	Inherit bool

	// Pinned specifies that the counter should always be on the CPU if
	// possible. This bit applies only to hardware counters, and only
	// to group leaders. If a pinned counter canno be put onto the CPU,
	// then the counter goes into an error state, where reads return EOF,
	// until it is subsequently enabled or disabled.
	Pinned bool

	// Exclusive specifies that when this counter's group is on the CPU,
	// it should be the only group using the CPUs counters.
	Exclusive bool

	// ExcludeUser excludes events that happen in user space.
	ExcludeUser bool

	// ExcludeKernel excludes events that happen in kernel space.
	ExcludeKernel bool

	// ExcludeHypervisor excludes events that happen in the hypervisor.
	ExcludeHypervisor bool

	// ExcludeIdle disables counting while the CPU is idle.
	ExcludeIdle bool

	// The mmap bit enables generation of MmapRecord records for every
	// mmap(2) call that has PROT_EXEC set.
	Mmap bool

	// Comm enables tracking of process command name, as modified by
	// exec(2), prctl(PR_SET_NAME), as well as writing to /proc/self/comm.
	// If CommExec is also set, then the CommRecord records produced
	// can be queries using the WasExec method, to differentiate exec(2)
	// from the other ases.
	Comm bool

	// Freq configures the event to use sample frequency, rather than
	// sample period. See also Attr.Sample.
	Freq bool

	// InheritStat enables saving of event counts on context switch for
	// inherited tasks. InheritStat is only meaningful if Inherit is
	// also set.
	InheritStat bool

	// EnableOnExec configures the counter to be enabled automatically
	// after a call to exec(2).
	EnableOnExec bool

	// Task configures the event to include fork/exit notifications in
	// the ring buffer.
	Task bool

	// Watermark configures the ring buffer to issue an overflow
	// notification when the Wakeup boundary is crossed. If not set,
	// notifications happen after Wakeup samples. See also Attr.Wakeup.
	Watermark bool

	// PreciseIP controls the number of instructions between an event of
	// interest happening and the kernel being able to stop and record
	// the event.
	PreciseIP Skid

	// MmapData is the counterpart to Mmap. It enables generation of
	// MmapRecord records for mmap(2) calls that do not have PROT_EXEC
	// set.
	MmapData bool

	// RecordIDAll configures Tid, Time, ID, StreamID and CPU samples
	// to be included in non-Sample records.
	RecordIDAll bool

	// ExcludeHost configures only events happening inside a guest
	// instance (one that has executed a KVM_RUN ioctl) to be measured.
	ExcludeHost bool

	// ExcludeGuest is the opposite of ExcludeHost: it configures only
	// events outside a guest instance to be measured.
	ExcludeGuest bool

	// ExcludeKernelCallchain excludes kernel callchains.
	ExcludeKernelCallchain bool

	// ExcludeUserCallchain excludes user callchains.
	ExcludeUserCallchain bool

	// Mmap2 configures mmap(2) events to include inode data.
	Mmap2 bool

	// CommExec allows the distinction between process renaming
	// via exec(2) or via other means. See also Comm, and
	// (*CommRecord).WasExec.
	CommExec bool

	// UseClockID allows selecting which internal linux clock to use
	// when generating timestamps via the ClockID field.
	UseClockID bool

	// ContextSwitch enables the generation of SwitchRecord records,
	// and SwitchCPUWideRecord records when sampling in CPU-wide mode.
	ContextSwitch bool

	// writeBackward configures the kernel to write to the memory
	// mapped ring buffer backwards. This option is not supported by
	// this package.
	writeBackward bool

	// Namespaces enables the generation of NamespacesRecord records.
	Namespaces bool
}

func (opt Options) marshal() uint64 {
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
		opt.RecordIDAll,
		opt.ExcludeHost,
		opt.ExcludeGuest,
		opt.ExcludeKernelCallchain,
		opt.ExcludeUserCallchain,
		opt.Mmap2,
		opt.CommExec,
		opt.UseClockID,
		opt.ContextSwitch,
		opt.writeBackward,
		opt.Namespaces,
	}
	return marshalBitwiseUint64(fields)
}
