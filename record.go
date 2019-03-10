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
	DataSrc     bool
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
		st.DataSrc,
		st.Identifier,
		st.Transaction,
		st.RegsIntr,
		st.PhysAddr,
	}
	return marshalBitwiseUint64(fields)
}

// RecordID contains identifiers for when and where a record was collected.
//
// TODO(acln): elaborate on when fields are set based on SampleFormat and
// Options.SampleIDAll.
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
	f := raw.fields()
	f.uint32(&mr.Pid, &mr.Tid)
	f.uint64(&mr.Addr)
	f.uint64(&mr.Len)
	f.uint64(&mr.Pgoff)
	f.string(&mr.Filename)
	f.id(&mr.RecordID, ev)
}

type LostRecord struct {
	RecordHeader
	ID   uint64
	Lost uint64
	RecordID
}

func (lr *LostRecord) DecodeFrom(raw *RawRecord, ev *Event) {
	lr.RecordHeader = raw.Header
	f := raw.fields()
	f.uint64(&lr.ID)
	f.uint64(&lr.Lost)
	f.id(&lr.RecordID, ev)
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
	f := raw.fields()
	f.uint32(&cr.Pid, &cr.Tid)
	f.string(&cr.Comm)
	f.id(&cr.RecordID, ev)
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
	f := raw.fields()
	f.uint32(&er.Pid, &er.Ppid)
	f.uint32(&er.Tid, &er.Ptid)
	f.uint64(&er.Time)
	f.id(&er.RecordID, ev)
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
	f := raw.fields()
	f.uint64(&tr.Time)
	f.uint64(&tr.ID)
	f.uint64(&tr.StreamID)
	f.id(&tr.RecordID, ev)
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
	f := raw.fields()
	f.uint64(&ur.Time)
	f.uint64(&ur.ID)
	f.uint64(&ur.StreamID)
	f.id(&ur.RecordID, ev)
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
	f := raw.fields()
	f.uint32(&fr.Pid, &fr.Ppid)
	f.uint32(&fr.Tid, &fr.Ptid)
	f.uint64(&fr.Time)
	f.id(&fr.RecordID, ev)
}

type ReadRecord struct {
	RecordHeader
	Pid    uint32
	Tid    uint32
	Values Count
	RecordID
}

func (rr *ReadRecord) DecodeFrom(raw *RawRecord, ev *Event) {
	rr.RecordHeader = raw.Header
	f := raw.fields()
	f.uint32(&rr.Pid, &rr.Tid)
	f.count(&rr.Values, ev)
}

type ReadGroupRecord struct {
	RecordHeader
	Pid    uint32
	Tid    uint32
	Values GroupCount
	RecordID
}

func (rr *ReadGroupRecord) DecodeFrom(raw *RawRecord, ev *Event) {
	rr.RecordHeader = raw.Header
	f := raw.fields()
	f.uint32(&rr.Pid, &rr.Tid)
	f.groupCount(&rr.Values, ev)
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
	Values     Count
	Callchain  []uint64

	// Non-ABI fields:

	Data             []byte
	BranchStack      []BranchEntry
	UserRegsABI      uint64
	UserRegs         []uint64
	UserStack        []byte
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
	if ev.attr.SampleFormat.Read {
		f.count(&sr.Values, ev)
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
		f.uint32sizeBytes(&sr.Data)
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
	if ev.attr.SampleFormat.RegsUser {
		f.uint64(&sr.UserRegsABI)
		sr.UserRegs = make([]uint64, bits.OnesCount64(ev.attr.SampleRegsUser))
		for i := 0; i < len(sr.UserRegs); i++ {
			f.uint64(&sr.UserRegs[i])
		}
	}
	if ev.attr.SampleFormat.StackUser {
		f.uint64sizeBytes(&sr.UserStack)
		if len(sr.UserStack) > 0 {
			f.uint64(&sr.UserStackDynSize)
		}
	}
	f.uint64Cond(ev.attr.SampleFormat.Weight, &sr.Weight)
	f.uint64Cond(ev.attr.SampleFormat.DataSrc, &sr.DataSrc)
	f.uint64Cond(ev.attr.SampleFormat.Transaction, &sr.Transaction)
	if ev.attr.SampleFormat.RegsIntr {
		f.uint64(&sr.IntrRegsABI)
		sr.IntrRegs = make([]uint64, bits.OnesCount64(ev.attr.SampleRegsIntr))
		for i := 0; i < len(sr.IntrRegs); i++ {
			f.uint64(&sr.IntrRegs[i])
		}
	}
	f.uint64Cond(ev.attr.SampleFormat.PhysAddr, &sr.PhysAddr)
}

type SampleGroupRecord struct {
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
	Values     GroupCount
	Callchain  []uint64

	// Non-ABI fields:
	Data             []byte
	BranchStack      []BranchEntry
	UserRegsABI      uint64
	UserRegs         []uint64
	UserStack        []byte
	UserStackDynSize uint64
	Weight           uint64
	DataSrc          uint64
	Transaction      uint64
	IntrRegsABI      uint64
	IntrRegs         []uint64
	PhysAddr         uint64
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
	if ev.attr.SampleFormat.Read {
		f.groupCount(&sr.Values, ev)
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
		f.uint32sizeBytes(&sr.Data)
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
	if ev.attr.SampleFormat.RegsUser {
		f.uint64(&sr.UserRegsABI)
		sr.UserRegs = make([]uint64, bits.OnesCount64(ev.attr.SampleRegsUser))
		for i := 0; i < len(sr.UserRegs); i++ {
			f.uint64(&sr.UserRegs[i])
		}
	}
	if ev.attr.SampleFormat.StackUser {
		f.uint64sizeBytes(&sr.UserStack)
		if len(sr.UserStack) > 0 {
			f.uint64(&sr.UserStackDynSize)
		}
	}
	f.uint64Cond(ev.attr.SampleFormat.Weight, &sr.Weight)
	f.uint64Cond(ev.attr.SampleFormat.DataSrc, &sr.DataSrc)
	f.uint64Cond(ev.attr.SampleFormat.Transaction, &sr.Transaction)
	if ev.attr.SampleFormat.RegsIntr {
		f.uint64(&sr.IntrRegsABI)
		sr.IntrRegs = make([]uint64, bits.OnesCount64(ev.attr.SampleRegsIntr))
		for i := 0; i < len(sr.IntrRegs); i++ {
			f.uint64(&sr.IntrRegs[i])
		}
	}
	f.uint64Cond(ev.attr.SampleFormat.PhysAddr, &sr.PhysAddr)
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
	f := raw.fields()
	f.uint32(&mr.Pid, &mr.Tid)
	f.uint64(&mr.Addr)
	f.uint64(&mr.Len)
	f.uint64(&mr.Pgoff)
	f.uint32(&mr.Maj, &mr.Min)
	f.uint64(&mr.Ino)
	f.uint64(&mr.InoGeneration)
	f.uint32(&mr.Prot, &mr.Flags)
	f.string(&mr.Filename)
	f.id(&mr.RecordID, ev)
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
	f := raw.fields()
	f.uint64(&ar.AuxOffset)
	f.uint64(&ar.AuxSize)
	f.uint64(&ar.Flags)
	f.id(&ar.RecordID, ev)
}

type ItraceStartRecord struct {
	RecordHeader
	Pid uint32
	Tid uint32
	RecordID
}

func (ir *ItraceStartRecord) DecodeFrom(raw *RawRecord, ev *Event) {
	ir.RecordHeader = raw.Header
	f := raw.fields()
	f.uint32(&ir.Pid, &ir.Tid)
	f.id(&ir.RecordID, ev)
}

type LostSamplesRecord struct {
	RecordHeader
	Lost uint64
	RecordID
}

func (lr *LostSamplesRecord) DecodeFrom(raw *RawRecord, ev *Event) {
	lr.RecordHeader = raw.Header
	f := raw.fields()
	f.uint64(&lr.Lost)
	f.id(&lr.RecordID, ev)
}

type SwitchRecord struct {
	RecordHeader
	RecordID
}

func (sr *SwitchRecord) DecodeFrom(raw *RawRecord, ev *Event) {
	sr.RecordHeader = raw.Header
	f := raw.fields()
	f.id(&sr.RecordID, ev)
}

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
