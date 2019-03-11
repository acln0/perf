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

func ExampleEvent_Measure_hardware() {
	cyclesattr := &perf.Attr{
		CountFormat: perf.CountFormat{
			Running: true,
		},
	}
	perf.CPUCycles.Configure(cyclesattr)

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	ev, err := perf.Open(cyclesattr, perf.CallingThread, perf.AnyCPU, nil, 0)
	if err != nil {
		log.Fatal(err)
	}
	defer ev.Close()

	sum := 0

	c, err := ev.Measure(func() {
		for i := 0; i < 1000000; i++ {
			sum += i
		}
	})
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("got sum %d in %d CPU cycles (%v)", sum, c.Value, c.Running)
}

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
	defer ev.Close()

	unix.Getpid() // does not count towards the measurement

	c, err := ev.Measure(func() {
		unix.Getpid()
		unix.Getpid()
		unix.Getpid()
	})
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("saw getpid(2) %d times", c.Value)
	// Output: saw getpid(2) 3 times
}

func ExampleEvent_MeasureGroup_hardware() {
	var g perf.Group
	g.Add(perf.Instructions, perf.CPUCycles)

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	ev, err := g.Open(perf.CallingThread, perf.AnyCPU)
	if err != nil {
		log.Fatal(err)
	}
	defer ev.Close()

	sum := 0

	gc, err := ev.MeasureGroup(func() {
		for i := 0; i < 1000000; i++ {
			sum += i
		}
	})
	if err != nil {
		log.Fatal(err)
	}

	insns := gc.Values[0].Value
	cycles := gc.Values[1].Value
	fmt.Printf("got sum %d in %d instructions and %d CPU cycles", sum, insns, cycles)
}
