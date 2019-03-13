// Copyright 2019 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package perf_test

import (
	"os"
	"runtime"
	"testing"

	"acln.ro/perf"

	"golang.org/x/sys/unix"
)

func TestHardwareCounters(t *testing.T) {
	var g perf.Group
	g.Add(perf.CPUCycles, perf.Instructions)

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	hw, err := g.Open(perf.CallingThread, perf.AnyCPU)
	if err != nil {
		t.Fatal(err)
	}

	var sum int64
	gc, err := hw.MeasureGroup(func() {
		for i := int64(0); i < 1000000; i++ {
			sum += i
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range gc.Values {
		if c.Value == 0 {
			t.Fatalf("didn't count %q", c.Label)
		}
	}
}

var fault []byte

func TestSoftwareCounters(t *testing.T) {
	pfa := new(perf.Attr)
	perf.PageFaults.Configure(pfa)

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	faults, err := perf.Open(pfa, perf.CallingThread, perf.AnyCPU, nil, 0)
	if err != nil {
		t.Fatal(err)
	}

	runtime.GC()

	c, err := faults.Measure(func() {
		fault = make([]byte, 64*1024*1024)
		fault[0] = 1
		fault[63*1024*1024] = 1
	})
	if err != nil {
		t.Fatal(err)
	}
	if c.Value == 0 {
		t.Fatal("didn't see a page fault")
	}
}

type singleTracepointTest struct {
	category string
	event    string
	trigger  func()
}

func (tt singleTracepointTest) run(t *testing.T) {
	tp := perf.Tracepoint(tt.category, tt.event)
	attr := new(perf.Attr)
	if err := tp.Configure(attr); err != nil {
		t.Fatal(err)
	}

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	ev, err := perf.Open(attr, perf.CallingThread, perf.AnyCPU, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer ev.Close()

	c, err := ev.Measure(func() {
		tt.trigger()
	})
	if err != nil {
		t.Fatal(err)
	}
	if c.Value != 1 {
		t.Fatalf("got %d hits for %q, want 1 hit", c.Value, c.Label)
	}
}

func (tt singleTracepointTest) String() string {
	return tt.category + ":" + tt.event
}

func TestSingleTracepoint(t *testing.T) {
	tests := []singleTracepointTest{
		{
			category: "syscalls",
			event:    "sys_enter_getpid",
			trigger:  getpidTrigger,
		},
		{
			category: "syscalls",
			event:    "sys_enter_read",
			trigger:  readTrigger,
		},
		{
			category: "syscalls",
			event:    "sys_enter_write",
			trigger:  writeTrigger,
		},
	}
	for _, tt := range tests {
		t.Run(tt.String(), tt.run)
	}
}

func getpidTrigger() {
	unix.Getpid()
}

func readTrigger() {
	zero, err := os.Open("/dev/zero")
	if err != nil {
		panic(err)
	}
	buf := make([]byte, 8)
	if _, err := zero.Read(buf); err != nil {
		panic(err)
	}
}

func writeTrigger() {
	null, err := os.OpenFile("/dev/null", os.O_WRONLY, 0200)
	if err != nil {
		panic(err)
	}
	if _, err := null.Write([]byte("big data")); err != nil {
		panic(err)
	}
}
