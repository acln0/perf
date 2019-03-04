// Copyright 2019 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package perf provides access to the Linux perf API. See man 2 perf_event_open.
package perf

import (
	"errors"
	"os"
	"unsafe"

	"golang.org/x/sys/unix"

	"acln.ro/ioctl"
)

// Special Open and OpenGroup pid parameter values.
const (
	// TODO(acln): document
	CallingThread = 0

	// TODO(acln): document
	AllThreads = -1
)

// Special Open and OpenGroup cpu parameter values.
const (
	// TODO(acln): document
	AnyCPU = -1
)

// Open opens the event configured by attr. The pid and cpu specify which
// process and CPU to monitor:
//
// TODO(acln): add paragraph about pid and cpu value combinations,
// mention AnyCPU and CallingThread constants.
//
// If group is non-nil, the output (TODO: clarify) from the returned Event is
// redirected to the group Event. If group is nil, the Event is created as a
// group leader.
//
// TODO(acln): respect attr.Options.Disabled settings, document that we do
//
// TODO(acln): Do we add CLOEXEC to flags unconditionally? Should the documentation
// mention that we do so?
func Open(attr *EventAttr, pid int, cpu int, group *Event, flags int) (*Event, error) {
	// TODO(acln): use group.fd
	fd, err := unix.PerfEventOpen(attr.unixEventAttr(), pid, cpu, -1, flags)
	if err != nil {
		return nil, os.NewSyscallError("perf_event_open", err)
	}
	if err := unix.SetNonblock(fd, true); err != nil {
		return nil, os.NewSyscallError("setnonblock", err)
	}
	return &Event{
		intfd: fd,
		fd:    os.NewFile(uintptr(fd), "perf"),
	}, nil
}

// OpenGroup opens a group of events. The pid, cpu and flags arguments behave
// as described in the Open documentation.
//
// The returned event group is disabled by default, and the Options.Disabled
// flag is ignored for all EventAttrs added to g.
//
// TODO(acln): document that we do PERF_FLAG_FD_OUTPUT.
func OpenGroup(g *EventGroup, pid int, cpu int, flags int) (*Event, error) {
	panic("not implemented")
}

// An EventGroup configures a group of related events.
// The zero value of EventGroup is an empty group.
type EventGroup struct {
	events []*EventAttr
	labels []string
	// etc.
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

// A Counter configures
type Counter interface {
	Label() string
	EventAttr() *EventAttr
}

type Event struct {
	intfd    int                     // integer file descriptor
	fd       *os.File                // event file descriptor
	ring     []byte                  // memory mapped ring buffer
	ringSize int                     // size of the ring in bytes, excluding meta page
	meta     *unix.PerfEventMmapPage // metadata page: &ring[0]
	isGroup  bool
	group    []*Event
}

// PERF_EVENT_IOC_* ioctls.
var (
	ioctlEnable = ioctl.N{
		Name: "PERF_EVENT_IOC_ENABLE",
		Type: '$',
		Nr:   0,
	}
	ioctlDisable = ioctl.N{
		Name: "PERF_EVENT_IOC_DISABLE",
		Type: '$',
		Nr:   1,
	}
	ioctlRefresh = ioctl.N{
		Name: "PERF_EVENT_IOC_REFRESH",
		Type: '$',
		Nr:   2,
	}
	ioctlReset = ioctl.N{
		Name: "PERF_EVENT_IOC_RESET",
		Type: '$',
		Nr:   3,
	}
	ioctlPeriod = ioctl.W{
		Name: "PERF_EVENT_IOC_PERIOD",
		Type: '$',
		Nr:   4,
	}
	ioctlSetOutput = ioctl.N{
		Name: "PERF_EVENT_IOC_SET_OUTPUT",
		Type: '$',
		Nr:   5,
	}
	ioctlSetFilter = ioctl.W{
		Name: "PERF_EVENT_IOC_SET_FILTER",
		Type: '$',
		Nr:   6,
	}
	ioctlID = ioctl.R{
		Name: "PERF_EVENT_IOC_ID",
		Type: '$',
		Nr:   7,
	}
	ioctlSetBPF = ioctl.W{
		Name: "PERF_EVENT_IOC_SET_BPF",
		Type: '$',
		Nr:   8,
	}
	ioctlPauseOutput = ioctl.W{
		Name: "PERF_EVENT_IOC_PAUSE_OUTPUT",
		Type: '$',
		Nr:   9,
	}
	ioctlQueryBPF = ioctl.WR{
		Name: "PERF_EVENT_IOC_QUERY_BPF",
		Type: '$',
		Nr:   10,
	}
	ioctlModifyAttributes = ioctl.W{
		Name: "PERF_EVENT_IOC_MODIFY_ATTRIBUTES",
		Type: '$',
		Nr:   11,
	}
)

// Enable enables the event.
func (ev *Event) Enable() error {
	_, err := ioctlEnable.Exec(int(ev.intfd))
	return err
}

// Disable disables the event.
func (ev *Event) Disable() error {
	_, err := ioctlDisable.Exec(int(ev.intfd))
	return err
}

// Reset resets the counters associated with the event.
func (ev *Event) Reset() error {
	_, err := ioctlReset.Exec(int(ev.intfd))
	return err
}

// TODO(acln): add remaining ioctls as methods on *Event.

// Close closes the ev and any other events in its group.
func (ev *Event) Close() error {
	// TODO(acln): close the other ones as well.
	return ev.fd.Close()
}

// Count is a measurement taken by an Event.
//
// TODO(acln): document which fields are set based on CountFormat.
type Count struct {
	Value       uint64
	TimeEnabled uint64
	TimeRunning uint64
	ID          uint64
	Label       string
}

// GroupCount is a group of measurements taken by an Event group.
//
// TODO(acln): document which fields are set based on CountFormat.
type GroupCount struct {
	TimeEnabled uint64
	TimeRunning uint64
	Counts      []Count
}

var errGroupEvent = errors.New("calling ReadCount on group Event")

// ReadCount reads a single count. It returns an error if ev represents an
// event group.
func (ev *Event) ReadCount() (Count, error) {
	// TODO(acln): check ev.isGroup

	// TODO(acln): check what flags we have
	var val uint64
	b := (*[8]byte)(unsafe.Pointer(&val))[:]
	if _, err := ev.fd.Read(b); err != nil {
		return Count{}, err
	}
	return Count{Value: val}, nil
}

var errSingleEvent = errors.New("calling ReadGroupCount on non-group Event")

// ReadGroupCount reads the counts associated with ev. It returns an error
// if ev does not represent an event group.
func (ev *Event) ReadGroupCount() (GroupCount, error) {
	if !ev.isGroup {
		return GroupCount{}, errSingleEvent
	}
	panic("not implemented")
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

	// RecordFormat configures the format for overflow packets read from
	// the ring buffer associated with the event.
	RecordFormat RecordFormat

	// CountFormat specifies the format of counts read from the event file
	// descriptor. See struct read_format in perf_event.h for details.
	CountFormat CountFormat

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

	// BranchSampleType specifies what branches to include in the
	// branch record, if SampleFormat.BranchStack is set.
	BranchSampleType BranchSampleType

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

func (attr *EventAttr) unixEventAttr() *unix.PerfEventAttr {
	return &unix.PerfEventAttr{
		Type:               uint32(attr.Type),
		Size:               uint32(unsafe.Sizeof(unix.PerfEventAttr{})),
		Config:             attr.Config,
		Sample:             attr.Sample,
		Sample_type:        attr.RecordFormat.Marshal(),
		Read_format:        attr.CountFormat.Marshal(),
		Bits:               attr.Options.Marshal(),
		Wakeup:             attr.Wakeup,
		Bp_type:            attr.BreakpointType,
		Ext1:               attr.Config1,
		Ext2:               attr.Config2,
		Branch_sample_type: uint64(attr.BranchSampleType),
		Sample_regs_user:   attr.SampleRegsUser,
		Sample_stack_user:  attr.SampleStackUser,
		Clockid:            attr.ClockID,
		Sample_regs_intr:   attr.SampleRegsInt,
		Aux_watermark:      attr.AuxWatermark,
	}
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
