//+build !amd64

package perf

import (
	"golang.org/x/sys/unix"
)

// doEnableRunDisable enables the counters, executes f, and disables them. Where
// possible it is implemented in assembly to minimize non-deterministic
// overhead. It is assumed that perfFD is known to be a valid file descriptor at
// the time of the call, no error checking occurs.
func doEnableRunDisable(fd uintptr, f func()) {
	unix.Syscall(unix.SYS_IOCTL, fd, uintptr(unix.PERF_EVENT_IOC_ENABLE), 0)
	f()
	unix.Syscall(unix.SYS_IOCTL, fd, uintptr(unix.PERF_EVENT_IOC_DISABLE), 0)
}
