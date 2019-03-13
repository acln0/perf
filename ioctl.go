// Copyright 2019 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package perf

// Perf file descriptor ioctls.

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/unix"
)

func ioctlEnable(fd int) error {
	err := ioctlNoArg(fd, unix.PERF_EVENT_IOC_ENABLE)
	return wrapIoctlError("PERF_EVENT_IOC_ENABLE", err)
}

func ioctlDisable(fd int) error {
	err := ioctlNoArg(fd, unix.PERF_EVENT_IOC_DISABLE)
	return wrapIoctlError("PERF_EVENT_IOC_DISABLE", err)
}

func ioctlRefresh(fd int, delta int) error {
	err := ioctlInt(fd, unix.PERF_EVENT_IOC_REFRESH, uintptr(delta))
	return wrapIoctlError("PERF_EVENT_IOC_REFRESH", err)
}

func ioctlReset(fd int) error {
	err := ioctlNoArg(fd, unix.PERF_EVENT_IOC_RESET)
	return wrapIoctlError("PERF_EVENT_IOC_RESET", err)
}

func ioctlPeriod(fd int, p *uint64) error {
	err := ioctlPointer(fd, unix.PERF_EVENT_IOC_PERIOD, unsafe.Pointer(p))
	return wrapIoctlError("PERF_EVENT_IOC_PERIOD", err)
}

func ioctlSetOutput(fd int, target int) error {
	err := ioctlInt(fd, unix.PERF_EVENT_IOC_SET_OUTPUT, uintptr(target))
	return wrapIoctlError("PERF_EVENT_IOC_SET_OUTPUT", err)
}

// TODO(acln): PERF_EVENT_IOC_SET_FILTER

func ioctlID(fd int, id *uint64) error {
	err := ioctlPointer(fd, unix.PERF_EVENT_IOC_ID, unsafe.Pointer(id))
	return wrapIoctlError("PERF_EVENT_IOC_ID", err)
}

func ioctlSetBPF(fd int, progfd uint32) error {
	err := ioctlInt(fd, unix.PERF_EVENT_IOC_SET_BPF, uintptr(progfd))
	return wrapIoctlError("PERF_EVENT_IOC_SET_BPF", err)
}

func ioctlPauseOutput(fd int, val uint32) error {
	err := ioctlInt(fd, unix.PERF_EVENT_IOC_PAUSE_OUTPUT, uintptr(val))
	return wrapIoctlError("PEF_EVENT_IOC_PAUSE_OUTPUT", err)
}

func ioctlQueryBPF(fd int, max uint32) ([]uint32, error) {
	buf := make([]uint32, 2+max)
	buf[0] = max
	bufp := unsafe.Pointer(&buf[0])
	err := ioctlPointer(fd, unix.PERF_EVENT_IOC_QUERY_BPF, bufp)
	if err != nil {
		return nil, err
	}
	count := buf[1]
	fds := make([]uint32, count)
	copy(fds, buf[2:2+count])
	return fds, nil
}

func ioctlModifyAttributes(fd int, attr *unix.PerfEventAttr) error {
	err := ioctlPointer(fd, unix.PERF_EVENT_IOC_MODIFY_ATTRIBUTES, unsafe.Pointer(attr))
	return wrapIoctlError("PERF_EVENT_IOC_MODIFY_ATTRIBUTES", err)
}

func ioctlNoArg(fd, number int) error {
	return ioctlInt(fd, number, 0)
}

func ioctlInt(fd int, number int, arg uintptr) error {
	_, _, e := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), uintptr(number), arg)
	if e != 0 {
		return e
	}
	return nil
}

func ioctlPointer(fd int, number int, arg unsafe.Pointer) error {
	_, _, e := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), uintptr(number), uintptr(arg))
	if e != 0 {
		return e
	}
	return nil
}

func wrapIoctlError(ioctl string, err error) error {
	if err == nil {
		return nil
	}
	return &ioctlError{ioctl: ioctl, err: err}
}

type ioctlError struct {
	ioctl string
	err   error
}

func (e *ioctlError) Error() string {
	return fmt.Sprintf("%s: %v", e.ioctl, e.err)
}

func (e *ioctlError) Unwrap() error { return e.err }
