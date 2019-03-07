// Copyright 2019 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package perf

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

type ring struct {
	rawfd    syscall.RawConn         // raw file descriptor
	meta     *unix.PerfEventMmapPage // metadata page: at &mapping[0]
	mapping  []byte                  // the memory mapping
	n        uint                    // size of mapping is 1 + 2^n pages
	evfd     int                     // unblocks poll on rawfd
	pollReq  chan time.Duration      // sends poll requests to polling goroutine
	pollResp chan pollResp           // receives poll results from polling goroutine
}

// newRing creates and maps a new ring buffer, of size 1+2^n pages.
func newRing(fd *os.File, n uint) (*ring, error) {
	rawfd, err := fd.SyscallConn()
	if err != nil {
		return nil, err
	}
	size := (1 + (1 << n)) * unix.Getpagesize()
	var mapping []byte
	var mmaperr error
	err = rawfd.Control(func(fd uintptr) {
		mapping, mmaperr = unix.Mmap(int(fd), 0, size, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED)
	})
	if err != nil {
		return nil, err
	}
	if mmaperr != nil {
		return nil, err
	}
	evfd, err := unix.Eventfd(0, unix.EFD_CLOEXEC|unix.EFD_NONBLOCK)
	if err != nil {
		return nil, err
	}
	r := &ring{
		rawfd:    rawfd,
		meta:     (*unix.PerfEventMmapPage)(unsafe.Pointer(&mapping[0])),
		mapping:  mapping,
		evfd:     evfd,
		pollReq:  make(chan time.Duration),
		pollResp: make(chan pollResp),
	}
	go r.poll()
	return r, nil
}

var (
	evfd1              = uint64(1)
	nativeEndian1Bytes = (*[8]byte)(unsafe.Pointer(&evfd1))[:]
)

func (r *ring) ReadRecord(ctx context.Context) (Record, error) {
	rec, ok := r.readRecord()
	if ok {
		return rec, nil
	}

	var timeout time.Duration
	deadline, ok := ctx.Deadline()
	if ok {
		timeout = deadline.Sub(time.Now())
		if timeout <= 0 {
			timeout = 1
		}
	}

	r.pollReq <- timeout

	select {
	case <-ctx.Done():
		// TODO(acln): document the wroteEvent + sawEvent machinery
		wroteEvent := false
		err := ctx.Err()
		if err == context.Canceled {
			unix.Write(r.evfd, nativeEndian1Bytes)
			wroteEvent = true
		}
		resp := <-r.pollResp
		if wroteEvent && !resp.sawEvent {
			r.drainEvent()
		}
		return nil, err
	case resp := <-r.pollResp:
		if resp.err != nil {
			return nil, resp.err
		}
		rec, _ := r.readRecord()
		return rec, nil
	}
}

func (r *ring) readRecord() (Record, bool) {
	base := r.meta.Data_offset
	head := atomic.LoadUint64(&r.meta.Data_head)
	tail := atomic.LoadUint64(&r.meta.Data_tail)

	// TODO(acln): implement

	fmt.Printf("base: %d\nhead: %d\ntail: %d\n", base, head, tail)
	return nil, false
}

func (r *ring) poll() {
	defer close(r.pollResp)

	for timeout := range r.pollReq {
		r.pollResp <- r.doPoll(timeout)
	}
}

func (r *ring) doPoll(timeout time.Duration) pollResp {
	var systimeout *unix.Timespec
	if timeout > 0 {
		sec := timeout / time.Second
		nsec := timeout - sec*time.Second
		systimeout = &unix.Timespec{
			Sec:  int64(sec),
			Nsec: int64(nsec),
		}
	}
	var (
		perfRevents int16
		pollErr     error
	)
	ctlErr := r.rawfd.Control(func(fd uintptr) {
		fds := []unix.PollFd{
			{
				Fd:     int32(fd),
				Events: unix.POLLIN,
			},
			{
				Fd:     int32(r.evfd),
				Events: unix.POLLIN,
			},
		}
		_, pollErr = unix.Ppoll(fds, systimeout, nil)
		perfRevents = fds[0].Revents
	})
	_ = perfRevents // TODO(acln): check these
	sawEvent := false
	evfdErr := r.drainEvent()
	if evfdErr == nil {
		sawEvent = true
	}
	if ctlErr != nil {
		return pollResp{sawEvent: sawEvent, err: ctlErr}
	}
	return pollResp{sawEvent: sawEvent, err: pollErr}
}

func (r *ring) drainEvent() error {
	var buf [8]byte
	_, err := unix.Read(r.evfd, buf[:])
	if err == nil && !bytes.Equal(buf[:], nativeEndian1Bytes) {
		panic("internal error: inconsistent eventfd state")
	}
	return err
}

func (r *ring) destroy() {
	close(r.pollReq)
	<-r.pollResp
	unix.Munmap(r.mapping)
	unix.Close(r.evfd)
}

type pollResp struct {
	sawEvent bool
	err      error
}
