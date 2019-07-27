// Copyright 2019 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//+build !amd64

package perf

import (
	"syscall"

	"golang.org/x/sys/unix"
)

// doEnableRunDisable enables the counters, executes f, and disables them. Where
// possible it is implemented in assembly to minimize non-deterministic
// overhead. It is assumed that perfFD is known to be a valid file descriptor at
// the time of the call, no error checking occurs.
func doEnableRunDisable(fd uintptr, f func()) {
	// syscall.RawSyscall is the most economic way we can do this
	// generically. It's one branch less than unix.RawSyscall, and many
	// instructions less than the generic unix.Syscall, which must notify
	// the runtime by eventually calling runtime.{enter,exit}syscall.
	syscall.RawSyscall(unix.SYS_IOCTL, fd, uintptr(unix.PERF_EVENT_IOC_ENABLE), 0)
	f()
	syscall.RawSyscall(unix.SYS_IOCTL, fd, uintptr(unix.PERF_EVENT_IOC_DISABLE), 0)
}
