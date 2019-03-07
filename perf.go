// Copyright 2019 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package perf provides access to the Linux perf API. See man 2 perf_event_open.
package perf

import (
	"encoding/binary"
	"errors"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"strconv"
	"strings"
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

// OpenFlag is a set of flags for Open.
type OpenFlag int

// Flags for calls to Open.
const (
	// FlagNoGroup configures the event to ignore the group parameter
	// except for the purpose of setting up output redirection using
	// the FlagFDOutput flag.
	FlagNoGroup OpenFlag = unix.PERF_FLAG_FD_NO_GROUP

	// FlagFDOutput re-routes the event's sampled output to be included in the
	// memory mapped buffer of the event specified by the group parameter.
	FlagFDOutput OpenFlag = unix.PERF_FLAG_FD_OUTPUT

	// FlagPidCGroup activates per-container system-wide monitoring. In this
	// case, a file descriptor opened on /dev/group/<x> must be passed
	// as the pid parameter. Consult the perf_event_open man page for
	// more details.
	FlagPidCGroup OpenFlag = unix.PERF_FLAG_PID_CGROUP

	// flagCloexec configures the event file descriptor to be opened in
	// close-on-exec mode.
	flagCloexec OpenFlag = 1 << 3 // TODO(acln): missing PERF_FLAG_FD_CLOEXEC from x/sys/unix
)

type Event struct {
	intfd    int                     // integer file descriptor
	fd       *os.File                // event file descriptor
	ring     []byte                  // memory mapped ring buffer
	ringSize int                     // size of the ring in bytes, excluding meta page
	meta     *unix.PerfEventMmapPage // metadata page: &ring[0]
	group    []*Event

	attr *EventAttr // attributes the Event was configured with
}

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
//
//
func Open(attr *EventAttr, pid int, cpu int, group *Event, flags OpenFlag) (*Event, error) {
	groupfd := -1
	if group != nil {
		// TODO(acln): do better than this
		groupfd = group.intfd
	}
	flags |= flagCloexec
	fd, err := unix.PerfEventOpen(attr.sysAttr(), pid, cpu, groupfd, int(flags))
	if err != nil {
		return nil, os.NewSyscallError("perf_event_open", err)
	}
	if err := unix.SetNonblock(fd, true); err != nil {
		return nil, os.NewSyscallError("setnonblock", err)
	}
	ev := &Event{
		intfd: fd,
		fd:    os.NewFile(uintptr(fd), "perf"),
		attr:  attr, // TODO(acln): make a copy
	}
	ev.group = append(ev.group, ev)
	if group != nil {
		group.group = append(group.group, ev)
	}
	return ev, nil
}

// Enable enables the event.
func (ev *Event) Enable() error {
	return ioctlEnable(int(ev.intfd))
}

// Disable disables the event.
func (ev *Event) Disable() error {
	return ioctlDisable(int(ev.intfd))
}

// Reset resets the counters associated with the event.
func (ev *Event) Reset() error {
	return ioctlReset(int(ev.intfd))
}

// TODO(acln): add remaining ioctls as methods on *Event.

// Close closes the ev and any other events in its group.
func (ev *Event) Close() error {
	// TODO(acln): close the other ones as well.
	return ev.fd.Close()
}

var errGroupEvent = errors.New("calling ReadCount on group Event")

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

// ReadCount reads a single count. If the Event was configured with
// ReadFormat.Group, ReadCount returns an error.
func (ev *Event) ReadCount() (Count, error) {
	var c Count
	if ev.attr.ReadFormat.Group {
		return c, errGroupEvent
	}
	// TODO(acln): since c is contiguous, pass it to read() directly?
	// TODO(acln): use rdpmc on x86 instead of a system call?
	buf := make([]byte, ev.attr.ReadFormat.readSize())
	_, err := ev.fd.Read(buf)
	if err != nil {
		return c, err
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
	if !ev.attr.ReadFormat.Group {
		return gc, errSingleEvent
	}
	headerSize := ev.attr.ReadFormat.groupReadHeaderSize()
	countsSize := len(ev.group) * ev.attr.ReadFormat.groupReadCountSize()
	buf := make([]byte, headerSize+countsSize)
	_, err := ev.fd.Read(buf)
	if err != nil {
		return gc, err
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
	counts := make([]Count, 0, nr)
	for i := 0; i < nr; i++ {
		var c Count
		c.Value = nextField()
		if ev.attr.ReadFormat.ID {
			c.ID = nextField()
		}
		counts = append(counts, c)
	}
	gc.Counts = counts
	return gc, nil
}

// ReadRecord reads and decodes a record from the memory mapped ring buffer
// associated with ev.
func (ev *Event) ReadRecord() (Record, error) {
	panic("not implemented")
}

// ReadRawRecord reads a raw record from the memory mapped ring buffer
// associated with ev.
func (ev *Event) ReadRawRecord(raw *RawRecord) error {
	panic("not implemented")
}

// An EventGroup configures a group of related events.
// The zero value of EventGroup is an empty group.
type EventGroup struct {
	events []*EventAttr
	labels []string
	// etc.
}

func (g *EventGroup) Open(pid int, cpu int, flags OpenFlag) (*Event, error) {
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
func (g *EventGroup) AddEvent(label string, attr *EventAttr) {
	panic("not implemented")
}

type Counter interface {
	Label() string
	EventAttr() *EventAttr
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
// TODO(acln): document that TimeEnabled is set only at the top level
// TODO(acln): anonymous struct for Counts?
type GroupCount struct {
	TimeEnabled time.Duration
	TimeRunning time.Duration
	Counts      []Count
}

// EventAttr configures a perf event.
type EventAttr struct {
	// Type is the major type of the event.
	Type EventType

	// Config holds type-specific event configuration.
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
	ReadFormat ReadFormat

	// Options holds general event options.
	Options EventOptions

	// Wakeup configures event wakeup. If Options.Watermark is set,
	// Wakeup is interpreted as the number of bytes before wakeup.
	// Otherwise, it is interpreted as "wake up every n events".
	Wakeup uint32

	// BreakpointType holds the breakpoint type.
	BreakpointType uint32

	// Config1 is used for events that need an extra register or otherwise
	// do not fit in the regular config field.
	//
	// For breakpoint events, Config1 holds the breakpoint address.
	// For kprobes, Config1 holds the kprobe function. For uprobes,
	// Config1 holds the uprobe path.
	Config1 uint64

	// Config2 is a further extension of the Config1 field.
	//
	// For breakpoint events, Config2 holds the length of the breakpoint.
	// For kprobes, when the kprobe function is NULL, Config2 holds the
	// address of the kprobe. For both kprobes and uprobes, Config2 holds
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

func (attr *EventAttr) sysAttr() *unix.PerfEventAttr {
	return &unix.PerfEventAttr{
		Type:               uint32(attr.Type),
		Size:               uint32(unsafe.Sizeof(unix.PerfEventAttr{})),
		Config:             attr.Config,
		Sample:             attr.Sample,
		Sample_type:        attr.SampleFormat.Marshal(),
		Read_format:        attr.ReadFormat.Marshal(),
		Bits:               attr.Options.Marshal(),
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

func (hwc HardwareCounter) EventAttr() *EventAttr {
	return &EventAttr{Type: HardwareEvent, Config: uint64(hwc)}
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

func (swc SoftwareCounter) EventAttr() *EventAttr {
	return &EventAttr{Type: SoftwareEvent, Config: uint64(swc)}
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

func (hwcc HardwareCacheCounter) EventAttr() *EventAttr {
	config := uint64(hwcc.Cache) | uint64(hwcc.Op<<8) | uint64(hwcc.Result<<16)
	return &EventAttr{Type: HardwareCacheEvent, Config: config}
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
func NewTracepoint(category string, event string) (*EventAttr, error) {
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
	return &EventAttr{
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
func NewBreakpoint(typ BreakpointType, addr uint64, length BreakpointLength) *EventAttr {
	return &EventAttr{
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

// Marshal packs the SampleFormat into a uint64.
func (st SampleFormat) Marshal() uint64 {
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

// Marshal marshals the ReadFormat into a uint64.
func (f ReadFormat) Marshal() uint64 {
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
	Disabled               bool           // off by default
	Inherit                bool           // children inherit it
	Pinned                 bool           // must always be on PMU
	Exclusive              bool           // only group on PMU
	ExcludeUser            bool           // don't count user
	ExcludeKernel          bool           // ditto kernel
	ExcludeHypervisor      bool           // ditto hypervisor
	ExcludeIdle            bool           // don't count when idle
	Mmap                   bool           // include mmap data
	Comm                   bool           // include comm data
	Freq                   bool           // use frequency, not period
	InheritStat            bool           // per task counts
	EnableOnExec           bool           // next exec enables
	Task                   bool           // trace fork/exit
	Watermark              bool           // wake up at watermark
	PreciseIP              SkidConstraint // skid constraint
	MmapData               bool           // non-exec mmap data
	SampleIDAll            bool           // include all events in SampleFormat
	ExcludeHost            bool           // don't count in host
	ExcludeGuest           bool           // don't count in guest
	ExcludeCallchainKernel bool           // exclude kernel callchains
	ExcludeCallchainUser   bool           // exclude user callchains
	Mmap2                  bool           // include mmap with inode data
	CommExec               bool           // flag comm events that are due to an exec
	UseClockID             bool           // use ClockID for time fields
	ContextSwitch          bool           // context switch data
	WriteBackward          bool           // TODO(acln): support this at all?
	Namespaces             bool           // include namespaces data
}

func (opt EventOptions) Marshal() uint64 {
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

// SkidConstraint is an instruction pointer skid constraint.
type SkidConstraint int

// Supported Skid settings.
const (
	CanHaveArbitrarySkid SkidConstraint = 0
	MustHaveConstantSkid SkidConstraint = 1
	RequestedZeroSkid    SkidConstraint = 2
	MustHaveZeroSkid     SkidConstraint = 3
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

// RawRecord is a raw overflow record.
type RawRecord struct {
	Header RecordHeader
	Data   []byte
}

// Decode decodes the raw record.
func (rr *RawRecord) Decode() Record {
	panic("not implemented")
}

// RecordType is the type of an overflow record.
//
// TODO(acln): add these constants
type RecordType uint32

// RecordHeader is the header present in every overflow record.
type RecordHeader struct {
	Type RecordType
	Misc uint16
	Size uint16
}

// Header returns rh, such that types which embed a RecordHeader
// automatically implement the Record interface.
func (rh RecordHeader) Header() RecordHeader { return rh }

// MmapRecord records PROT_EXEC mappings, so user-space instruction pointers
// can be correlated to code.
type MmapRecord struct {
	RecordHeader
	Pid, Tid uint32
	Addr     uint64
	Len      uint64
	Pgoff    uint64
	Filename string
}

func (mr *MmapRecord) DecodeFrom(rr *RawRecord) error {
	panic("not implemented")
}

// LostRecord indicates when events are lost.
type LostRecord struct {
	RecordHeader
	ID uint64
	RecordID
}

func (lr *LostRecord) DecodeFrom(rr *RawRecord) error {
	panic("not implemented")
}

// ExitRecord indicates a process exit event.
type ExitRecord struct {
	RecordHeader
	Pid, Ppid uint32
	Tid, Ptid uint32
	Time      uint64
	RecordID
}

func (er *ExitRecord) DecodeFrom(rr *RawRecord) error {
	panic("not implemented")
}

// Record is the interface implemented by all record types.
//
// TODO(acln): not all record types are implemented
type Record interface {
	Header() RecordHeader
	DecodeFrom(rr *RawRecord) error
}

// RecordID holds identifiers when and where a record was collected.
//
// See struct sample_id in the perf_event_open manual page.
//
// TODO(acln): document the relationship between this and SampleFormat
type RecordID struct {
	Pid, Tid uint32
	Time     uint64
	ID       uint64
	StreamID uint64
	CPU, Res uint32
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
func (f *File) ReadRecord() (Record, error) {
	panic("not implemented")
}

func marshalBitwiseUint64(fields []bool) uint64 {
	var res uint64
	for shift, set := range fields {
		if set {
			res |= 1 << uint(shift)
		}
	}
	return res
}
