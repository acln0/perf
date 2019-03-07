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

func ioctlReset(fd int) error {
	err := ioctlNoArg(fd, unix.PERF_EVENT_IOC_RESET)
	return wrapIoctlError("PERF_EVENT_IOC_RESET", err)
}

// TODO(acln): add remaining ioctls as needed

func ioctlNoArg(fd, number int) error {
	return ioctlInt(fd, number, 0)
}

func ioctlInt(fd int, number int, arg int) error {
	_, _, e := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), uintptr(number), uintptr(arg))
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
