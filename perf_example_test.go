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

func ExampleHardwareCounter_iPC() {
	g := perf.Group{
		CountFormat: perf.CountFormat{
			Running: true,
		},
	}
	g.Add(perf.Instructions, perf.CPUCycles)

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	ipc, err := g.Open(perf.CallingThread, perf.AnyCPU)
	if err != nil {
		log.Fatal(err)
	}
	defer ipc.Close()

	sum := 0
	gc, err := ipc.MeasureGroup(func() {
		for i := 0; i < 100000; i++ {
			sum += i
		}
	})
	if err != nil {
		log.Fatal(err)
	}

	insns, cycles := gc.Values[0].Value, gc.Values[1].Value

	fmt.Printf("got sum = %d in %v: %d instructions, %d CPU cycles: %f IPC",
		sum, gc.Running, insns, cycles, float64(insns)/float64(cycles))
}

func ExampleSoftwareCounter_pageFaults() {
	pfa := new(perf.Attr)
	perf.PageFaults.Configure(pfa)

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	faults, err := perf.Open(pfa, perf.CallingThread, perf.AnyCPU, nil)
	if err != nil {
		log.Fatal(err)
	}
	defer faults.Close()

	var mem []byte
	const (
		size = 64 * 1024 * 1024
		pos  = 63 * 1024 * 1024
	)
	c, err := faults.Measure(func() {
		mem = make([]byte, size)
		mem[pos] = 42
	})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("saw %d page faults, wrote value %d", c.Value, mem[pos])
}

func ExampleTracepoint_getpid() {
	ga := new(perf.Attr)
	gtp := perf.Tracepoint("syscalls", "sys_enter_getpid")
	if err := gtp.Configure(ga); err != nil {
		log.Fatal(err)
	}

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	getpid, err := perf.Open(ga, perf.CallingThread, perf.AnyCPU, nil)
	if err != nil {
		log.Fatal(err)
	}
	defer getpid.Close()

	unix.Getpid() // does not count towards the measurement

	c, err := getpid.Measure(func() {
		unix.Getpid()
		unix.Getpid()
		unix.Getpid()
	})
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("saw getpid %d times\n", c.Value)
	// Output: saw getpid 3 times
}
