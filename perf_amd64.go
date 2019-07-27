// Copyright 2019 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package perf

// doEnableRunDisable enables the counters, executes f, and disables them. It is
// implemented in assembly to minimize non-deterministic overhead. It is assumed
// that perfFD is known to be a valid file descriptor at the time of the call,
// no error checking occurs.
func doEnableRunDisable(perfFD uintptr, f func())
