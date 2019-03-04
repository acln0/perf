// Copyright 2019 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package perf provides access to the Linux perf API. See man 2 perf_event_open.
package perf

import (
	"io"
	"os"

	"golang.org/x/sys/unix"
)

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
	panic("not implemented")
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

// RecordFormat configures information requested in overflow packets.
type RecordFormat struct {
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

// Marshal packs the RecordFormat into a uint64.
func (f RecordFormat) Marshal() uint64 {
	// Always keep this in sync with the type definition above.
	fields := []bool{
		f.IP,
		f.Tid,
		f.Time,
		f.Addr,
		f.Read,
		f.Callchain,
		f.ID,
		f.CPU,
		f.Period,
		f.StreamID,
		f.Raw,
		f.BranchStack,
		f.RegsUser,
		f.StackUser,
		f.Weight,
		f.DataSource,
		f.Identifier,
		f.Transaction,
		f.RegsIntr,
		f.PhysAddr,
	}
	return marshalBitwiseUint64(fields)
}

// CountFormat configures the format of Count or GroupCount measurements.
type CountFormat struct {
	TotalTimeEnabled bool
	TotalTimeRunning bool
	ID               bool
	Group            bool
}

// Marshal marshals the CountFormat into a uint64.
func (f CountFormat) Marshal() uint64 {
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

// BranchSampleType ...
type BranchSampleType uint32

// Branch sample types.
const (
	BranchSampleUser         BranchSampleType = unix.PERF_SAMPLE_BRANCH_USER
	BranchSampleKernel       BranchSampleType = unix.PERF_SAMPLE_BRANCH_KERNEL
	BranchSampleHypervisor   BranchSampleType = unix.PERF_SAMPLE_BRANCH_HV
	BranchSampleAny          BranchSampleType = unix.PERF_SAMPLE_BRANCH_ANY
	BranchSampleAnyCall      BranchSampleType = unix.PERF_SAMPLE_BRANCH_ANY_CALL
	BranchSampleAnyReturn    BranchSampleType = unix.PERF_SAMPLE_BRANCH_ANY_RETURN
	BranchSampleIndirectCall BranchSampleType = unix.PERF_SAMPLE_BRANCH_IND_CALL

	BranchSampleAbortTransaction BranchSampleType = 1 << (7 + iota) // TODO(acln): missing from x/sys/unix
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
// TODO(acln): document the relationship between this and RecordFormat
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
