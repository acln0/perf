// Copyright 2019 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package perf_test

import (
	"fmt"
	"log"
	"runtime"

	"acln.ro/perf"

	"golang.org/x/sys/unix"
)

func ExampleEvent_Measure_tracepoint() {
	getpidattr := new(perf.Attr)
	getpid := perf.Tracepoint("syscalls", "sys_enter_getpid")
	if err := getpid.Configure(getpidattr); err != nil {
		log.Fatal(err)
	}

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

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

	fmt.Printf("saw getpid(2) %d times", count.Value)
	// Output: saw getpid(2) 3 times
}
