// Copyright 2019 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package perf

import (
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
	rawfd    syscall.RawConn
	meta     *unix.PerfEventMmapPage
	region   []byte
	prfd     int
	pwfd     int
	pollReq  chan pollReq
	pollResp chan pollResp
}

const pageSize = 4096

// newRing creates and maps a new ring buffer, of size 1+2^n pages.
func newRing(fd *os.File, n uint) (*ring, error) {
	rawfd, err := fd.SyscallConn()
	if err != nil {
		return nil, err
	}
	size := (1 + (1 << n)) * pageSize
	var region []byte
	var mmaperr error
	err = rawfd.Control(func(fd uintptr) {
		region, mmaperr = unix.Mmap(int(fd), 0, size, unix.PROT_READ, unix.MAP_SHARED)
	})
	if err != nil {
		return nil, err
	}
	if mmaperr != nil {
		return nil, err
	}
	var pipefds [2]int
	if err := unix.Pipe2(pipefds[:], unix.O_NONBLOCK|unix.O_CLOEXEC); err != nil {
		return nil, err
	}
	r := &ring{
		rawfd:    rawfd,
		meta:     (*unix.PerfEventMmapPage)(unsafe.Pointer(&region[0])),
		region:   region,
		prfd:     pipefds[0],
		pwfd:     pipefds[1],
		pollReq:  make(chan pollReq),
		pollResp: make(chan pollResp),
	}
	go r.poll()
	return r, nil
}

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
		// take active action. Write one byte to the pipe so that
		// POLLIN is raised on r.prfd.
		err := ctx.Err()
		if err == context.Canceled {
			var buf [1]byte
			unix.Write(r.pwfd, buf[:])
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
	version := atomic.LoadUint32(&r.meta.Version)
	capabilities := atomic.LoadUint64(&r.meta.Capabilities)
	head := atomic.LoadUint64(&r.meta.Data_head)
	tail := atomic.LoadUint64(&r.meta.Data_tail)
	offset := atomic.LoadUint64(&r.meta.Data_offset)
	size := atomic.LoadUint64(&r.meta.Data_offset)

	fmt.Printf("version: %d\n", version)
	fmt.Printf("capabilities: %08x\n", capabilities)
	fmt.Printf("data head: %d\n", head)
	fmt.Printf("data tail: %d\n", tail)
	fmt.Printf("data offset: %d\n", offset)
	fmt.Printf("data size: %d\n", size)

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
		pipeRevents int16
		pollErr     error
	)
	err := r.rawfd.Control(func(fd uintptr) {
		fds := []unix.PollFd{
			{
				Fd:     int32(fd),
				Events: unix.POLLIN,
			},
			{
				Fd:     int32(r.prfd),
				Events: unix.POLLIN,
			},
		}
		_, pollErr = unix.Ppoll(fds, timeout, nil)
		perfRevents = fds[0].Revents
		pipeRevents = fds[1].Revents
	})
	// If POLLIN was raised on r.prfd, drain the pipe. We can only ever
	// read one byte from the pipe here, since we write at most one byte
	// per call to doPoll from the other sied.
	if pipeRevents&unix.POLLIN == 1 {
		var buf [1]byte
		unix.Read(r.prfd, buf[:])
	}
	if err != nil {
		return pollResp{err: err}
	}
	return pollResp{
		perfRevents: perfRevents,
		pipeRevents: pipeRevents,
		err:         pollErr,
	}
}

func (r *ring) destroy() {
	close(r.pollReq)
	<-r.pollResp
	unix.Munmap(r.region)
	unix.Close(r.prfd)
	unix.Close(r.pwfd)
}

type pollReq struct {
	timeout time.Duration
}

func durationToTimespec(d time.Duration) unix.Timespec {
	return unix.Timespec{
		Sec:  int64(d / time.Second),
		Nsec: int64(d - time.Second*(d/time.Second)),
	}
}

type pollResp struct {
	perfRevents int16
	pipeRevents int16
	err         error
}
