// Copyright 2019 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package perf

import (
	"context"
	"fmt"
	"math/bits"
	"os"
	"sync/atomic"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// ReadRecord reads and decodes a record from the ring buffer associated
// with ev.
//
// ReadRecord may be called concurrently with ReadCount or ReadGroupCount,
// but not concurrently with itself, ReadRawRecord, Close, or any other
// Event method.
func (ev *Event) ReadRecord(ctx context.Context) (Record, error) {
	if err := ev.ok(); err != nil {
		return nil, err
	}
	var raw RawRecord
	if err := ev.ReadRawRecord(ctx, &raw); err != nil {
		return nil, err
	}
	rec, err := newRecord(ev, raw.Header.Type)
	if err != nil {
		return nil, err
	}
	rec.DecodeFrom(&raw, ev)
	return rec, nil
}

// ReadRawRecord reads and decodes a raw record from the ring buffer
// associated with ev into rec. Callers must not retain rec.Data.
//
// ReadRawRecord may be called concurrently with ReadCount or ReadGroupCount,
// but not concurrently with itself, ReadRecord, Close or any other Event
// method.
func (ev *Event) ReadRawRecord(ctx context.Context, raw *RawRecord) error {
	if err := ev.ok(); err != nil {
		return err
	}
	// Fast path: try reading from the ring buffer first. If there is
	// a record there, we are done.
	if ev.readRawRecordNonblock(raw) {
		return nil
	}
	// If the context has a deadline, and that deadline is in the future,
	// use it to compute a timeout for ppoll(2). If the context is
	// expired, bail out. Otherwise, the timeout is zero, which means
	// no timeout.
	var timeout time.Duration
	deadline, ok := ctx.Deadline()
	if ok {
		timeout = time.Until(deadline)
		if timeout <= 0 {
			<-ctx.Done()
			return ctx.Err()
		}
	}
	// Start a round of polling, then await results. Only one request
	// can be in flight at a time, and the whole request-response cycle
	// is owned by the current invocation of ReadRawRecord.
	ev.pollreq <- pollreq{timeout: timeout}
	select {
	case <-ctx.Done():
		active := false
		err := ctx.Err()
		if err == context.Canceled {
			// Initiate active wakeup. Send a signal on ev.evfd
			// and wait for doPoll to wake up. doPoll might miss
			// this signal, but that's okay: see below.
			val := uint64(1)
			buf := (*[8]byte)(unsafe.Pointer(&val))[:]
			unix.Write(ev.evfd, buf)
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
		ev.readRawRecordNonblock(raw) // will succeed now
		return nil
	}
}

// readRawRecordNonblock reads a raw record into rec, if one is available.
// Callers must not retain rec.Data. The boolean return value signals whether
// a record was actually found / written to rec.
func (ev *Event) readRawRecordNonblock(raw *RawRecord) bool {
	head := atomic.LoadUint64(&ev.meta.Data_head)
	tail := atomic.LoadUint64(&ev.meta.Data_tail)
	if head == tail {
		return false
	}
	// Head and tail values only ever grow, so we must take their value
	// modulo the size of the data segment of the ring.
	start := tail % uint64(len(ev.ringdata))
	raw.Header = *(*RecordHeader)(unsafe.Pointer(&ev.ringdata[start]))
	end := (tail + uint64(raw.Header.Size)) % uint64(len(ev.ringdata))
	// If the record wraps around the ring, we must allocate storage,
	// so that we can return a contiguous area of memory to the caller.
	var data []byte
	if end < start {
		data = make([]byte, raw.Header.Size)
		n := copy(data, ev.ringdata[start:])
		copy(data[n:], ev.ringdata[:int(raw.Header.Size)-n])
	} else {
		data = ev.ringdata[start:end]
	}
	raw.Data = data[unsafe.Sizeof(raw.Header):]
	// Notify the kernel of the last record we've seen.
	atomic.AddUint64(&ev.meta.Data_tail, uint64(raw.Header.Size))
	return true
}

// poll services requests from ev.pollreq and sends responses on ev.pollresp.
func (ev *Event) poll() {
	defer close(ev.pollresp)

	for req := range ev.pollreq {
		ev.pollresp <- ev.doPoll(req)
	}
}

// doPoll executes one round of polling on ev.fd and ev.evfd. A req.timeout
// value of zero is interpreted as "no timeout".
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
	// TODO(acln): do we need to do this business at all? See #20400.
	if err == unix.EINTR {
		goto again
	}
	// If we are here and we have successfully woken up, it is for one
	// of three reasons: we got POLLIN on ev.fd, the ppoll(2) timeout
	// fired, or we got POLLIN on ev.evfd.
	//
	// Report if the perf fd is ready, and any errors except EINTR.
	// The machinery is documented in more detail in ReadRawRecord.
	return pollresp{
		perfready: pollfds[0].Revents&unix.POLLIN != 0,
		err:       os.NewSyscallError("ppoll", err),
	}
}

type pollreq struct {
	// timeout is the timeout for ppoll(2): zero means no timeout
	timeout time.Duration
}

type pollresp struct {
	// perfready indicates if the perf FD (ev.fd) is ready.
	perfready bool

	// err is the *os.SyscallError from ppoll(2).
	err error
}

// SampleFormat configures information requested in overflow packets.
type SampleFormat struct {
	IP              bool
	Tid             bool
	Time            bool
	Addr            bool
	Count           bool
	Callchain       bool
	ID              bool
	CPU             bool
	Period          bool
	StreamID        bool
	Raw             bool
	BranchStack     bool
	UserRegisters   bool
	UserStack       bool
	Weight          bool
	DataSource      bool
	Identifier      bool
	Transaction     bool
	IntrRegisters   bool
	PhysicalAddress bool
}

// marshal packs the SampleFormat into a uint64.
func (st SampleFormat) marshal() uint64 {
	// Always keep this in sync with the type definition above.
	fields := []bool{
		st.IP,
		st.Tid,
		st.Time,
		st.Addr,
		st.Count,
		st.Callchain,
		st.ID,
		st.CPU,
		st.Period,
		st.StreamID,
		st.Raw,
		st.BranchStack,
		st.UserRegisters,
		st.UserStack,
		st.Weight,
		st.DataSource,
		st.Identifier,
		st.Transaction,
		st.IntrRegisters,
		st.PhysicalAddress,
	}
	return marshalBitwiseUint64(fields)
}

// RecordID contains identifiers for when and where a record was collected.
//
// A RecordID is included with a Record if Options.SampleIDAll is set on the
// associated event. Fields are present based on SampleFormat options.
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

// Record is the interface implemented by all record types.
type Record interface {
	Header() RecordHeader
	DecodeFrom(*RawRecord, *Event)
}

// RecordType is the type of an overflow record.
type RecordType uint32

// Known record types.
const (
	RecordTypeMmap          RecordType = unix.PERF_RECORD_MMAP
	RecordTypeLost          RecordType = unix.PERF_RECORD_LOST
	RecordTypeComm          RecordType = unix.PERF_RECORD_COMM
	RecordTypeExit          RecordType = unix.PERF_RECORD_EXIT
	RecordTypeThrottle      RecordType = unix.PERF_RECORD_THROTTLE
	RecordTypeUnthrottle    RecordType = unix.PERF_RECORD_UNTHROTTLE
	RecordTypeFork          RecordType = unix.PERF_RECORD_FORK
	RecordTypeRead          RecordType = unix.PERF_RECORD_READ
	RecordTypeSample        RecordType = unix.PERF_RECORD_SAMPLE
	RecordTypeMmap2         RecordType = unix.PERF_RECORD_MMAP2
	RecordTypeAux           RecordType = unix.PERF_RECORD_AUX
	RecordTypeItraceStart   RecordType = unix.PERF_RECORD_ITRACE_START
	RecordTypeLostSamples   RecordType = unix.PERF_RECORD_LOST_SAMPLES
	RecordTypeSwitch        RecordType = unix.PERF_RECORD_SWITCH
	RecordTypeSwitchCPUWide RecordType = unix.PERF_RECORD_SWITCH_CPU_WIDE
	RecordTypeNamespaces    RecordType = unix.PERF_RECORD_NAMESPACES
)

func (rt RecordType) known() bool {
	return rt >= RecordTypeMmap && rt <= RecordTypeNamespaces
}

// RecordHeader is the header present in every overflow record.
type RecordHeader struct {
	Type RecordType
	Misc uint16
	Size uint16
}

// Header returns rh itself, so that types which embed a RecordHeader
// automatically implement a part of the Record interface.
func (rh RecordHeader) Header() RecordHeader { return rh }

// CPUMode returns the CPU mode in use when the sample happened.
func (rh RecordHeader) CPUMode() CPUMode {
	return CPUMode(rh.Misc & cpuModeMask)
}

// CPUMode is a CPU operation mode.
type CPUMode uint8

const cpuModeMask = 7

// Known CPU modes.
//
// TODO(acln): add to x/sys/unix?
const (
	UnknownMode     CPUMode = 0
	KernelMode      CPUMode = 1
	UserMode        CPUMode = 2
	HypervisorMode  CPUMode = 3
	GuestKernelMode CPUMode = 4
	GuestUserMode   CPUMode = 5
)

// RawRecord is a raw overflow record, read from the memory mapped ring
// buffer associated with an Event.
//
// Header is the 8 byte record header. Data contains the rest of the record.
type RawRecord struct {
	Header RecordHeader
	Data   []byte
}

func (raw RawRecord) fields() fields { return fields(raw.Data) }

var newRecordFuncs = [...]func(ev *Event) Record{
	RecordTypeMmap:          func(_ *Event) Record { return &MmapRecord{} },
	RecordTypeLost:          func(_ *Event) Record { return &LostRecord{} },
	RecordTypeComm:          func(_ *Event) Record { return &CommRecord{} },
	RecordTypeExit:          func(_ *Event) Record { return &ExitRecord{} },
	RecordTypeThrottle:      func(_ *Event) Record { return &ThrottleRecord{} },
	RecordTypeUnthrottle:    func(_ *Event) Record { return &UnthrottleRecord{} },
	RecordTypeFork:          func(_ *Event) Record { return &ForkRecord{} },
	RecordTypeRead:          newReadRecord,
	RecordTypeSample:        newSampleRecord,
	RecordTypeMmap2:         func(_ *Event) Record { return &Mmap2Record{} },
	RecordTypeAux:           func(_ *Event) Record { return &AuxRecord{} },
	RecordTypeItraceStart:   func(_ *Event) Record { return &ItraceStartRecord{} },
	RecordTypeLostSamples:   func(_ *Event) Record { return &LostSamplesRecord{} },
	RecordTypeSwitch:        func(_ *Event) Record { return &SwitchRecord{} },
	RecordTypeSwitchCPUWide: func(_ *Event) Record { return &SwitchCPUWideRecord{} },
	RecordTypeNamespaces:    func(_ *Event) Record { return &NamespacesRecord{} },
}

func newReadRecord(ev *Event) Record {
	if ev.attr.CountFormat.Group {
		return &ReadGroupRecord{}
	}
	return &ReadRecord{}
}

func newSampleRecord(ev *Event) Record {
	if ev.attr.CountFormat.Group {
		return &SampleGroupRecord{}
	}
	return &SampleRecord{}
}

// newRecord returns an empty Record of the given type, tailored for the
// specified Event.
func newRecord(ev *Event, rt RecordType) (Record, error) {
	if !rt.known() {
		return nil, fmt.Errorf("unknown record type %d", rt)
	}
	return newRecordFuncs[rt](ev), nil
}

// mmapDataBit is PERF_RECORD_MISC_MMAP_DATA
const mmapDataBit = 1 << 13 // TODO(acln): add to x/sys/unix?

// MmapRecord (PERF_RECORD_MMAP) records PROT_EXEC mappings such that
// user-space IPs can be correlated to code.
type MmapRecord struct {
	RecordHeader
	Pid        uint32 // process ID
	Tid        uint32 // thread ID
	Addr       uint64 // address of the allocated memory
	Len        uint64 // length of the allocated memory
	PageOffset uint64 // page offset of the allocated memory
	Filename   string // describes backing of allocated memory
	RecordID
}

func (mr *MmapRecord) DecodeFrom(raw *RawRecord, ev *Event) {
	mr.RecordHeader = raw.Header
	f := raw.fields()
	f.uint32(&mr.Pid, &mr.Tid)
	f.uint64(&mr.Addr)
	f.uint64(&mr.Len)
	f.uint64(&mr.PageOffset)
	f.string(&mr.Filename)
	f.id(&mr.RecordID, ev)
}

// Executable returns a boolean indicating whether the mapping is executable.
func (mr *MmapRecord) Executable() bool {
	// The data bit is set when the mapping is _not_ executable.
	return mr.RecordHeader.Misc&mmapDataBit == 0
}

// LostRecord (PERF_RECORD_LOST) indicates when events are lost.
type LostRecord struct {
	RecordHeader
	ID   uint64 // the unique ID for the lost events
	Lost uint64 // the number of lost events
	RecordID
}

func (lr *LostRecord) DecodeFrom(raw *RawRecord, ev *Event) {
	lr.RecordHeader = raw.Header
	f := raw.fields()
	f.uint64(&lr.ID)
	f.uint64(&lr.Lost)
	f.id(&lr.RecordID, ev)
}

// CommRecord (PERF_RECORD_COMM) indicates a change in the process name.
type CommRecord struct {
	RecordHeader
	Pid     uint32 // process ID
	Tid     uint32 // threadID
	NewName string // the new name of the process
	RecordID
}

func (cr *CommRecord) DecodeFrom(raw *RawRecord, ev *Event) {
	cr.RecordHeader = raw.Header
	f := raw.fields()
	f.uint32(&cr.Pid, &cr.Tid)
	f.string(&cr.NewName)
	f.id(&cr.RecordID, ev)
}

// commExecBit is PERF_RECORD_MISC_COMM_EXEC
const commExecBit = 1 << 13 // TODO(acln): add to x/sys/unix?

// WasExec returns a boolean indicating whether a process name change
// was caused by an exec(2) system call.
func (cr *CommRecord) WasExec() bool {
	return cr.RecordHeader.Misc&(commExecBit) != 0
}

// ExitRecord (PERF_RECORD_EXIT) indicates a process exit event.
type ExitRecord struct {
	RecordHeader
	Pid  uint32 // process ID
	Ppid uint32 // parent process ID
	Tid  uint32 // thread ID
	Ptid uint32 // parent thread ID
	Time uint64 // time when the process exited
	RecordID
}

func (er *ExitRecord) DecodeFrom(raw *RawRecord, ev *Event) {
	er.RecordHeader = raw.Header
	f := raw.fields()
	f.uint32(&er.Pid, &er.Ppid)
	f.uint32(&er.Tid, &er.Ptid)
	f.uint64(&er.Time)
	f.id(&er.RecordID, ev)
}

// ThrottleRecord (PERF_RECORD_THROTTLE) indicates a throttle event.
type ThrottleRecord struct {
	RecordHeader
	Time     uint64
	ID       uint64
	StreamID uint64
	RecordID
}

func (tr *ThrottleRecord) DecodeFrom(raw *RawRecord, ev *Event) {
	tr.RecordHeader = raw.Header
	f := raw.fields()
	f.uint64(&tr.Time)
	f.uint64(&tr.ID)
	f.uint64(&tr.StreamID)
	f.id(&tr.RecordID, ev)
}

// UnthrottleRecord (PERF_RECORD_UNTHROTTLE) indicates an unthrottle event.
type UnthrottleRecord struct {
	RecordHeader
	Time     uint64
	ID       uint64
	StreamID uint64
	RecordID
}

func (ur *UnthrottleRecord) DecodeFrom(raw *RawRecord, ev *Event) {
	ur.RecordHeader = raw.Header
	f := raw.fields()
	f.uint64(&ur.Time)
	f.uint64(&ur.ID)
	f.uint64(&ur.StreamID)
	f.id(&ur.RecordID, ev)
}

// ForkRecord (PERF_RECORD_FORK) indicates a fork event.
type ForkRecord struct {
	RecordHeader
	Pid  uint32 // process ID
	Ppid uint32 // parent process ID
	Tid  uint32 // thread ID
	Ptid uint32 // parent thread ID
	Time uint64 // time when the fork occurred (TODO: is that true?)
	RecordID
}

func (fr *ForkRecord) DecodeFrom(raw *RawRecord, ev *Event) {
	fr.RecordHeader = raw.Header
	f := raw.fields()
	f.uint32(&fr.Pid, &fr.Ppid)
	f.uint32(&fr.Tid, &fr.Ptid)
	f.uint64(&fr.Time)
	f.id(&fr.RecordID, ev)
}

// ReadRecord (PERF_RECORD_READ) indicates a read event.
type ReadRecord struct {
	RecordHeader
	Pid   uint32 // process ID
	Tid   uint32 // thread ID
	Count Count  // count value
	RecordID
}

func (rr *ReadRecord) DecodeFrom(raw *RawRecord, ev *Event) {
	rr.RecordHeader = raw.Header
	f := raw.fields()
	f.uint32(&rr.Pid, &rr.Tid)
	f.count(&rr.Count, ev)
}

// ReadGroupRecord (PERF_RECORD_READ) indicates a read event on a group event.
type ReadGroupRecord struct {
	RecordHeader
	Pid        uint32     // process ID
	Tid        uint32     // thread ID
	GroupCount GroupCount // group count values
	RecordID
}

func (rr *ReadGroupRecord) DecodeFrom(raw *RawRecord, ev *Event) {
	rr.RecordHeader = raw.Header
	f := raw.fields()
	f.uint32(&rr.Pid, &rr.Tid)
	f.groupCount(&rr.GroupCount, ev)
}

// SampleRecord indicates a sample.
//
// All the fields up to and including Callchain represent ABI bits. All the
// fields starting with Data are non-ABI and have no compatibility guarantees.
//
// Fields on SamplRecord are set according to the SampleFormat the event
// was configured with. A boolean flag in SampleFormat typically enables
// the homonymous field in SampleRecord.
type SampleRecord struct {
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
	Count      Count
	Callchain  []uint64

	Raw                  []byte
	BranchStack          []BranchEntry
	UserRegisterABI      uint64
	UserRegisters        []uint64
	UserStack            []byte
	UserStackDynamicSize uint64
	Weight               uint64
	DataSource           DataSource
	Transaction          Transaction
	IntrRegisterABI      uint64
	IntrRegisters        []uint64
	PhysicalAddress      uint64
}

func (sr *SampleRecord) DecodeFrom(raw *RawRecord, ev *Event) {
	sr.RecordHeader = raw.Header
	f := raw.fields()
	f.uint64Cond(ev.attr.SampleFormat.Identifier, &sr.Identifier)
	f.uint64Cond(ev.attr.SampleFormat.IP, &sr.IP)
	f.uint32Cond(ev.attr.SampleFormat.Tid, &sr.Pid, &sr.Tid)
	f.uint64Cond(ev.attr.SampleFormat.Time, &sr.Time)
	f.uint64Cond(ev.attr.SampleFormat.Addr, &sr.Addr)
	f.uint64Cond(ev.attr.SampleFormat.ID, &sr.ID)
	f.uint64Cond(ev.attr.SampleFormat.StreamID, &sr.StreamID)
	f.uint32Cond(ev.attr.SampleFormat.CPU, &sr.CPU, &sr.Res)
	f.uint64Cond(ev.attr.SampleFormat.Period, &sr.Period)
	if ev.attr.SampleFormat.Count {
		f.count(&sr.Count, ev)
	}
	if ev.attr.SampleFormat.Callchain {
		var nr uint64
		f.uint64(&nr)
		sr.Callchain = make([]uint64, nr)
		for i := 0; i < len(sr.Callchain); i++ {
			f.uint64(&sr.Callchain[i])
		}
	}
	if ev.attr.SampleFormat.Raw {
		f.uint32sizeBytes(&sr.Raw)
	}
	if ev.attr.SampleFormat.BranchStack {
		var nr uint64
		f.uint64(&nr)
		sr.BranchStack = make([]BranchEntry, nr)
		for i := 0; i < len(sr.BranchStack); i++ {
			var from, to, tmp uint64
			f.uint64(&from)
			f.uint64(&to)
			f.uint64(&tmp)
			sr.BranchStack[i] = BranchEntry{
				From:             from,
				To:               to,
				Mispredicted:     tmp&(1<<0) != 0,
				Predicted:        tmp&(1<<1) != 0,
				InTransaction:    tmp&(1<<2) != 0,
				TransactionAbort: tmp&(1<<3) != 0,
				Cycles:           uint16((tmp << 44) >> 48),
				BranchType:       uint8((tmp << 40) >> 44),
			}
		}
	}
	if ev.attr.SampleFormat.UserRegisters {
		f.uint64(&sr.UserRegisterABI)
		num := bits.OnesCount64(ev.attr.SampleRegsUser)
		sr.UserRegisters = make([]uint64, num)
		for i := 0; i < len(sr.UserRegisters); i++ {
			f.uint64(&sr.UserRegisters[i])
		}
	}
	if ev.attr.SampleFormat.UserStack {
		f.uint64sizeBytes(&sr.UserStack)
		if len(sr.UserStack) > 0 {
			f.uint64(&sr.UserStackDynamicSize)
		}
	}
	f.uint64Cond(ev.attr.SampleFormat.Weight, &sr.Weight)
	if ev.attr.SampleFormat.DataSource {
		var ds uint64
		f.uint64(&ds)
		sr.DataSource = DataSource(ds)
	}
	if ev.attr.SampleFormat.Transaction {
		var tx uint64
		f.uint64(&tx)
		sr.Transaction = Transaction(tx)
	}
	if ev.attr.SampleFormat.IntrRegisters {
		f.uint64(&sr.IntrRegisterABI)
		num := bits.OnesCount64(ev.attr.SampleRegsIntr)
		sr.IntrRegisters = make([]uint64, num)
		for i := 0; i < len(sr.IntrRegisters); i++ {
			f.uint64(&sr.IntrRegisters[i])
		}
	}
	f.uint64Cond(ev.attr.SampleFormat.PhysicalAddress, &sr.PhysicalAddress)
}

// exactIPBit is PERF_RECORD_MISC_EXACT_IP
const exactIPBit = 1 << 14 // TODO(acln): add to x/sys/unix?

// ExactIP indicates that sr.IP points to the actual instruction that
// triggered the event. See also Options.PreciseIP.
func (sr *SampleRecord) ExactIP() bool {
	return sr.RecordHeader.Misc&exactIPBit != 0
}

// SampleGroupRecord indicates a sample from an event group.
//
// All the fields up to and including Callchain represent ABI bits. All the
// fields starting with Data are non-ABI and have no compatibility guarantees.
//
// Fields on SampleGroupRecord are set according to the SampleFormat the event
// was configured with. A boolean flag in SampleFormat typically enables the
// homonymous field in SampleGroupRecord.
type SampleGroupRecord struct {
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
	Count      GroupCount
	Callchain  []uint64

	Raw                  []byte
	BranchStack          []BranchEntry
	UserRegisterABI      uint64
	UserRegisters        []uint64
	UserStack            []byte
	UserStackDynamicSize uint64
	Weight               uint64
	DataSource           DataSource
	Transaction          Transaction
	IntrRegisterABI      uint64
	IntrRegisters        []uint64
	PhysicalAddress      uint64
}

func (sr *SampleGroupRecord) DecodeFrom(raw *RawRecord, ev *Event) {
	sr.RecordHeader = raw.Header
	f := raw.fields()
	f.uint64Cond(ev.attr.SampleFormat.Identifier, &sr.Identifier)
	f.uint64Cond(ev.attr.SampleFormat.IP, &sr.IP)
	f.uint32Cond(ev.attr.SampleFormat.Tid, &sr.Pid, &sr.Tid)
	f.uint64Cond(ev.attr.SampleFormat.Time, &sr.Time)
	f.uint64Cond(ev.attr.SampleFormat.Addr, &sr.Addr)
	f.uint64Cond(ev.attr.SampleFormat.ID, &sr.ID)
	f.uint64Cond(ev.attr.SampleFormat.StreamID, &sr.StreamID)
	f.uint32Cond(ev.attr.SampleFormat.CPU, &sr.CPU, &sr.Res)
	f.uint64Cond(ev.attr.SampleFormat.Period, &sr.Period)
	if ev.attr.SampleFormat.Count {
		f.groupCount(&sr.Count, ev)
	}
	if ev.attr.SampleFormat.Callchain {
		var nr uint64
		f.uint64(&nr)
		sr.Callchain = make([]uint64, nr)
		for i := 0; i < len(sr.Callchain); i++ {
			f.uint64(&sr.Callchain[i])
		}
	}
	if ev.attr.SampleFormat.Raw {
		f.uint32sizeBytes(&sr.Raw)
	}
	if ev.attr.SampleFormat.BranchStack {
		var nr uint64
		f.uint64(&nr)
		sr.BranchStack = make([]BranchEntry, nr)
		for i := 0; i < len(sr.BranchStack); i++ {
			var from, to, tmp uint64
			f.uint64(&from)
			f.uint64(&to)
			f.uint64(&tmp)
			sr.BranchStack[i] = BranchEntry{
				From:             from,
				To:               to,
				Mispredicted:     tmp&(1<<0) != 0,
				Predicted:        tmp&(1<<1) != 0,
				InTransaction:    tmp&(1<<2) != 0,
				TransactionAbort: tmp&(1<<3) != 0,
				Cycles:           uint16((tmp << 44) >> 48),
				BranchType:       uint8((tmp << 40) >> 44),
			}
		}
	}
	if ev.attr.SampleFormat.UserRegisters {
		f.uint64(&sr.UserRegisterABI)
		num := bits.OnesCount64(ev.attr.SampleRegsUser)
		sr.UserRegisters = make([]uint64, num)
		for i := 0; i < len(sr.UserRegisters); i++ {
			f.uint64(&sr.UserRegisters[i])
		}
	}
	if ev.attr.SampleFormat.UserStack {
		f.uint64sizeBytes(&sr.UserStack)
		if len(sr.UserStack) > 0 {
			f.uint64(&sr.UserStackDynamicSize)
		}
	}
	f.uint64Cond(ev.attr.SampleFormat.Weight, &sr.Weight)
	if ev.attr.SampleFormat.DataSource {
		var ds uint64
		f.uint64(&ds)
		sr.DataSource = DataSource(ds)
	}
	if ev.attr.SampleFormat.Transaction {
		var tx uint64
		f.uint64(&tx)
		sr.Transaction = Transaction(tx)
	}
	if ev.attr.SampleFormat.IntrRegisters {
		f.uint64(&sr.IntrRegisterABI)
		num := bits.OnesCount64(ev.attr.SampleRegsIntr)
		sr.IntrRegisters = make([]uint64, num)
		for i := 0; i < len(sr.IntrRegisters); i++ {
			f.uint64(&sr.IntrRegisters[i])
		}
	}
	f.uint64Cond(ev.attr.SampleFormat.PhysicalAddress, &sr.PhysicalAddress)
}

// ExactIP indicates that sr.IP points to the actual instruction that
// triggered the event. See also Options.PreciseIP.
func (sr *SampleGroupRecord) ExactIP() bool {
	return sr.RecordHeader.Misc&exactIPBit != 0
}

type BranchEntry struct {
	From             uint64
	To               uint64
	Mispredicted     bool
	Predicted        bool
	InTransaction    bool
	TransactionAbort bool
	Cycles           uint16
	BranchType       uint8
}

// Mmap2Record (PERF_RECORD_MMAP2) includes extended information on mmap(2)
// calls returning executable mappings. It is similar to MmapRecord, but
// includes extra values, allowing unique identification of shared mappings.
type Mmap2Record struct {
	RecordHeader
	Pid             uint32 // process ID
	Tid             uint32 // thread ID
	Addr            uint64 // address of the allocated memory
	Len             uint64 // length of the allocated memory
	PageOffset      uint64 // page offset of the allocated memory
	MajorID         uint32 // major ID of the underlying device
	MinorID         uint32 // minor ID of the underlying device
	Inode           uint64 // inode number
	InodeGeneration uint64 // inode generation
	Prot            uint32 // protection information
	Flags           uint32 // flags information
	Filename        string // describes the backing of the allocated memory
	RecordID
}

func (mr *Mmap2Record) DecodeFrom(raw *RawRecord, ev *Event) {
	mr.RecordHeader = raw.Header
	f := raw.fields()
	f.uint32(&mr.Pid, &mr.Tid)
	f.uint64(&mr.Addr)
	f.uint64(&mr.Len)
	f.uint64(&mr.PageOffset)
	f.uint32(&mr.MajorID, &mr.MinorID)
	f.uint64(&mr.Inode)
	f.uint64(&mr.InodeGeneration)
	f.uint32(&mr.Prot, &mr.Flags)
	f.string(&mr.Filename)
	f.id(&mr.RecordID, ev)
}

// Executable returns a boolean indicating whether the mapping is executable.
func (mr *Mmap2Record) Executable() bool {
	// The data bit is set when the mapping is _not_ executable.
	return mr.RecordHeader.Misc&mmapDataBit == 0
}

// AuxRecord (PERF_RECORD_AUX) reports that new data is available in the
// AUX buffer region.
type AuxRecord struct {
	RecordHeader
	Offset uint64  // offset in the AUX mmap region where the new data begins
	Size   uint64  // size of data made available
	Flags  AuxFlag // describes the update
	RecordID
}

// AuxFlag describes an update to a record in the AUX buffer region.
type AuxFlag uint64

// AuxFlag bits.
//
// TODO(acln): add to x/sys/unix?
const (
	AuxTruncated AuxFlag = 0x01 // record was truncated to fit
	AuxOverwrite AuxFlag = 0x02 // snapshot from overwrite mode
	AuxPartial   AuxFlag = 0x04 // record contains gaps
	AuxCollision AuxFlag = 0x08 // sample collided with another
)

func (ar *AuxRecord) DecodeFrom(raw *RawRecord, ev *Event) {
	ar.RecordHeader = raw.Header
	f := raw.fields()
	f.uint64(&ar.Offset)
	f.uint64(&ar.Size)
	var flag uint64
	f.uint64(&flag)
	ar.Flags = AuxFlag(flag)
	f.id(&ar.RecordID, ev)
}

// ItraceStartRecord (PERF_RECORD_ITRACE_START) indicates which process
// has initiated an instruction trace event, allowing tools to correlate
// instruction addresses in the AUX buffer with the proper executable.
type ItraceStartRecord struct {
	RecordHeader
	Pid uint32 // process ID of the thread starting an instruction trace
	Tid uint32 // thread ID of the thread starting an instruction trace
	RecordID
}

func (ir *ItraceStartRecord) DecodeFrom(raw *RawRecord, ev *Event) {
	ir.RecordHeader = raw.Header
	f := raw.fields()
	f.uint32(&ir.Pid, &ir.Tid)
	f.id(&ir.RecordID, ev)
}

// LostSamplesRecord (PERF_RECORD_LOST_SAMPLES) indicates some number of
// samples that may have been lost, when using hardware sampling such as
// Intel PEBS.
type LostSamplesRecord struct {
	RecordHeader
	Lost uint64 // the number of potentially lost samples
	RecordID
}

func (lr *LostSamplesRecord) DecodeFrom(raw *RawRecord, ev *Event) {
	lr.RecordHeader = raw.Header
	f := raw.fields()
	f.uint64(&lr.Lost)
	f.id(&lr.RecordID, ev)
}

// SwitchRecord (PERF_RECORD_SWITCH) indicates that a context switch has
// happened.
type SwitchRecord struct {
	RecordHeader
	RecordID
}

func (sr *SwitchRecord) DecodeFrom(raw *RawRecord, ev *Event) {
	sr.RecordHeader = raw.Header
	f := raw.fields()
	f.id(&sr.RecordID, ev)
}

// switchOutBit is PERF_RECORD_MISC_SWITCH_OUT
const switchOutBit = 1 << 13 // TODO(acln): add to x/sys/unix?

// switchOutPreemptBit is PERF_RECORD_MISC_SWITCH_OUT_PREEMPT
const switchOutPreemptBit = 1 << 14 // TODO(acln): add to x/sys/unix?

// Out returns a boolean indicating whether the context switch was
// out of the current process, or into the current process.
func (sr *SwitchRecord) Out() bool {
	return sr.RecordHeader.Misc&switchOutBit != 0
}

// Preempted indicates whether the thread was preempted in TASK_RUNNING state.
func (sr *SwitchRecord) Preempted() bool {
	return sr.RecordHeader.Misc&switchOutPreemptBit != 0
}

// SwitchCPUWideRecord (PERF_RECORD_SWITCH_CPU_WIDE) indicates a context
// switch, but only occurs when sampling in CPU-wide mode. It provides
// informatino on the process being switched to / from.
type SwitchCPUWideRecord struct {
	RecordHeader
	Pid uint32
	Tid uint32
	RecordID
}

func (sr *SwitchCPUWideRecord) DecodeFrom(raw *RawRecord, ev *Event) {
	sr.RecordHeader = raw.Header
	f := raw.fields()
	f.uint32(&sr.Pid, &sr.Tid)
	f.id(&sr.RecordID, ev)
}

// Out returns a boolean indicating whether the context switch was
// out of the current process, or into the current process.
func (sr *SwitchCPUWideRecord) Out() bool {
	return sr.RecordHeader.Misc&switchOutBit != 0
}

// Preempted indicates whether the thread was preempted in TASK_RUNNING state.
func (sr *SwitchCPUWideRecord) Preempted() bool {
	return sr.RecordHeader.Misc&switchOutPreemptBit != 0
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
	f := raw.fields()
	f.uint32(&nr.Pid, &nr.Tid)
	var num uint64
	f.uint64(&num)
	nr.Namespaces = make([]struct{ Dev, Inode uint64 }, num)
	for i := 0; i < int(num); i++ {
		f.uint64(&nr.Namespaces[i].Dev)
		f.uint64(&nr.Namespaces[i].Inode)
	}
	f.id(&nr.RecordID, ev)
}

type DataSource uint64 // TODO(acln): implement

// MemOp is a memory operation.
type MemOp uint8

// Known memory operations.
//
// TODO(acln): add these to x/sys/unix?
const (
	MemOpNA MemOp = 1 << iota
	MemOpLoad
	MemOpStore
	MemOpPrefetch
	MemOpExec

	memOpShift = 0
)

// MemLevel is a memory level.
type MemLevel uint32

// Known memory levels.
//
// TODO(acln): add these to x/sys/unix?
const (
	MemLevelNA MemLevel = 1 << iota
	MemLevelHit
	MemLevelMiss
	MemLevelL1
	MemLevelLFB
	MemLevelL2
	MemLevelL3
	MemLevelLocalDRAM
	MemLevelRemoteDRAM1
	MemLevelRemoteDRAM2
	MemLevelRemoteCache1
	MemLevelRemoteCache2
	MemLevelIO
	MemLevelUncached

	memLevelShift = 5
)

const memRemoteShift = 37

// MemLevelNumber is a memory level number.
type MemLevelNumber uint8

// Known memory level numbers.
//
// TODO(acln): add these to x/sys/unix?
const (
	MemLevelNumberL1 MemLevelNumber = iota
	MemLevelNumberL2
	MemLevelNumberL3
	MemLevelNumberL4

	MemLevelNumberAnyCache MemLevelNumber = iota + 0x0b
	MemLevelNumberLFB
	MemLevelNumberRAM
	MemLevelNumberPMem
	MemLevelNumberNA

	memLevelNumShift = 33
)

// MemSnoopMode is a memory snoop mode.
type MemSnoopMode uint8

// Known memory snoop modes.
const (
	MemSnoopModeNA MemSnoopMode = 1 << iota
	MemSnoopModeNone
	MemSnoopModeHit
	MemSnoopModeMiss
	MemSnoopModeHitModified

	memShoopModeShift = 19
)

// TODO: missing PERF_MEM_SNOOPX_*, PERF_MEM_LOCK_*, PERF_MEM_TLB_*

// Transaction describes a transactional memory abort.
type Transaction uint64

// Transaction bits: values should be &-ed with Transaction values.
//
// TODO(acln): add the corresponding values to x/sys/unix?
const (
	// Transaction Elision indicates an abort from an elision type
	// transaction (Intel CPU specific).
	TransactionElision Transaction = 1 << iota

	// TransactionGeneric indicates an abort from a generic transaction.
	TransactionGeneric

	// TransactionSync indicates a synchronous abort (related to the
	// reported instruction).
	TransactionSync

	// TransactionAsync indicates an asynchronous abort (unrelated to
	// the reported instruction).
	TransactionAsync

	// TransactionRetryable indicates whether retrying the transaction
	// may have succeeded.
	TransactionRetryable

	// TransactionConflict indicates an abort rue to memory conflicts
	// with other threads.
	TransactionConflict

	// TransactionWriteCapacity indicates an abort due to write capacity
	// overflow.
	TransactionWriteCapacity

	// TransactionReadCapacity indicates an abort due to read capacity
	// overflow.
	TransactionReadCapacity
)

// txnAbortMask is PERF_TXN_ABORT_MASK
const txnAbortMask = 0xffffffff // TODO(acln): add to x/sys/unix?

// txnAbortShift is PERF_TXN_ABORT_SHIFT
const txnAbortShift = 32 // TODO(acln): add to x/sys/unix?

// UserAbortCode returns the user-specified abort code associated with
// the transaction.
func (txn Transaction) UserAbortCode() uint32 {
	return uint32((txn >> txnAbortShift) & txnAbortMask)
}
