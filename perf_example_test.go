// Copyright 2019 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package perf_test

import (
	"log"
	"runtime"

	"acln.ro/perf"

	"golang.org/x/sys/unix"
)

func Example_Event_Measure_tracepoint() {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	getpidattr := new(perf.Attr)
	getpid := perf.Tracepoint("syscalls", "sys_enter_getpid")
	getpid.Configure(getpidattr)

	ev, err := perf.Open(getpidattr, perf.CallingThread, perf.AnyCPU, nil, 0)
	if err != nil {
		log.Fatal(err)
	}

	count, err := ev.Measure(func() {
		unix.Getpid()
		unix.Getpid()
		unix.Getpid()
	})
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("saw getpid(2) %d times", count.Value)
}
