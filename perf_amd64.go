package perf

// doEnableRunDisable enables the counters, executes f, and disables them. It is
// implemented in assembly to minimize non-deterministic overhead. It is assumed
// that perfFD is known to be a valid file descriptor at the time of the call,
// no error checking occurs.
func doEnableRunDisable(perfFD uintptr, f func())
