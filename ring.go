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
	pollReq  chan pollReq            // sends poll requests to polling goroutine
	pollResp chan pollResp           // receives poll results from polling goroutine
}

const pageSize = 4096

// newRing creates and maps a new ring buffer, of size 1+2^n pages.
func newRing(fd *os.File, n uint) (*ring, error) {
	rawfd, err := fd.SyscallConn()
	if err != nil {
		return nil, err
	}
	size := (1 + (1 << n)) * pageSize
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
		pollReq:  make(chan pollReq),
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
	}

	r.pollReq <- pollReq{timeout: timeout}

	select {
	case <-ctx.Done():
		// If the context hit a deadline, we do nothing here: the
		// polling goroutine will wake up very soon, since we arranged
		// for our call to ppoll(2) to be aware of timeouts.
		//
		// If, instead, the context was canceled, then we need to
		// take active action. Raise POLLIN on r.evfd by setting the
		// value to 1.
		err := ctx.Err()
		if err == context.Canceled {
			unix.Write(r.evfd, nativeEndian1Bytes)
		}
		<-r.pollResp
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

	fmt.Printf("base: %d\nhead: %d\ntail: %d\n", base, head, tail)
	return nil, false
}

func (r *ring) poll() {
	defer close(r.pollResp)

	for req := range r.pollReq {
		r.pollResp <- r.doPoll(req)
	}
}

func (r *ring) doPoll(req pollReq) pollResp {
	var timeout *unix.Timespec
	if req.timeout > 0 {
		sec := req.timeout / time.Second
		nsec := req.timeout - time.Second*sec
		timeout = &unix.Timespec{
			Sec:  int64(sec),
			Nsec: int64(nsec),
		}
	}
	var (
		perfRevents int16
		evfdRevents int16
		pollErr     error
	)
	err := r.rawfd.Control(func(fd uintptr) {
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
		_, pollErr = unix.Ppoll(fds, timeout, nil)
		perfRevents = fds[0].Revents
		evfdRevents = fds[1].Revents
	})
	// If POLLIN was raised on r.evfd, consume the event.
	if evfdRevents&unix.POLLIN != 0 {
		var buf [8]byte
		unix.Read(r.evfd, buf[:])
		if !bytes.Equal(buf[:], nativeEndian1Bytes) {
			panic("internal error: inconsistent eventfd state")
		}
	}
	if err != nil {
		return pollResp{err: err}
	}
	return pollResp{
		perfRevents: perfRevents,
		err:         pollErr,
	}
}

func (r *ring) destroy() {
	close(r.pollReq)
	<-r.pollResp
	unix.Munmap(r.mapping)
	unix.Close(r.evfd)
}

type pollReq struct {
	timeout time.Duration
}

type pollResp struct {
	perfRevents int16
	err         error
}
