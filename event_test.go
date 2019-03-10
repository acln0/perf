// Copyright 2019 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package perf_test

import (
	"fmt"
	"os"
	"runtime"
	"testing"
	"time"

	"acln.ro/perf"
	"acln.ro/perf/internal/testasm"

	"golang.org/x/sys/unix"
)

type singleTracepointTest struct {
	category string
	event    string
	trigger  func() error
}

func (tt singleTracepointTest) run(t *testing.T) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	attr, err := perf.NewTracepoint(tt.category, tt.event)
	if err != nil {
		t.Fatalf("NewTracepoint: %v", err)
	}

	ev, err := perf.Open(attr, perf.CallingThread, perf.AnyCPU, nil, 0)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer ev.Close()

	const hits = 5 // TODO(acln): don't hard code, perhaps

	count, err := ev.Measure(func() {
		for i := 0; i < hits; i++ {
			if err := tt.trigger(); err != nil {
				t.Fatalf("trigger: %v", err)
			}
		}
	})
	if err != nil {
		t.Fatalf("Measure: %v", err)
	}
	if count.Value != hits {
		t.Fatalf("got %d %s hits, want %d", count.Value, tt.String(), hits)
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

func getpidTrigger() error {
	unix.Getpid()
	return nil
}

func readTrigger() error {
	zero, err := os.Open("/dev/zero")
	if err != nil {
		return err
	}
	buf := make([]byte, 8)
	if _, err := zero.Read(buf); err != nil {
		return err
	}
	return zero.Close()
}

func writeTrigger() error {
	null, err := os.OpenFile("/dev/null", os.O_WRONLY, 0200)
	if err != nil {
		return err
	}
	if _, err := null.Write([]byte("big data")); err != nil {
		return err
	}
	return null.Close()
}

func TestSumIPC(t *testing.T) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	insns := perf.Instructions.MarshalAttr()
	insns.CountFormat = perf.CountFormat{
		TotalTimeEnabled: true,
		TotalTimeRunning: true,
		Group:            true,
		ID:               true,
	}
	insns.Options = perf.Options{
		Disabled: true,
	}

	cycles := perf.CPUCycles.MarshalAttr()

	iev, err := perf.Open(insns, perf.CallingThread, perf.AnyCPU, nil, 0)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer iev.Close()

	cev, err := perf.Open(cycles, perf.CallingThread, perf.AnyCPU, iev, 0)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer cev.Close()

	Nvalues := []uint64{
		1,
		10,
		100,
		1000,
		10000,
		100000,
		1000000,
		10000000,
		100000000,
		1000000000,
	}
	for _, N := range Nvalues {
		counts, err := iev.MeasureGroup(func() {
			testasm.SumN(N)
		})
		if err != nil {
			t.Fatalf("ReadGroupCount: %v", err)
		}
		instructions := counts.Counts[0].Value
		cycles := counts.Counts[1].Value
		ipc := sumIPC{
			N:            N,
			instructions: instructions,
			cycles:       cycles,
			ipc:          float64(instructions) / float64(cycles),
			running:      counts.TimeRunning,
		}
		t.Log(ipc)
	}
}

type sumIPC struct {
	N            uint64
	instructions uint64
	cycles       uint64
	ipc          float64
	running      time.Duration
}

func (i sumIPC) String() string {
	return fmt.Sprintf("N = %11d | instructions = %11d | cycles = %11d | ipc = %6.3f | %v", i.N, i.instructions, i.cycles, i.ipc, i.running)
}

func TestSumOverhead(t *testing.T) {
	a := perf.Instructions.MarshalAttr()
	a.CountFormat = perf.CountFormat{
		TotalTimeEnabled: true,
		TotalTimeRunning: true,
		ID:               true,
	}
	a.Options = perf.Options{
		Disabled: true,
	}

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	ev, err := perf.Open(a, perf.CallingThread, perf.AnyCPU, nil, 0)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer ev.Close()

	Nvalues := []uint64{
		1,
		10,
		100,
		1000,
		10000,
		100000,
		1000000,
		10000000,
		100000000,
		1000000000,
	}
	for _, N := range Nvalues {
		count, err := ev.Measure(func() {
			testasm.SumN(N)
		})
		if err != nil {
			t.Fatal(err)
		}
		ideal := 5 + 4*N
		if count.Value < ideal {
			t.Fatalf("got count %d with ideal %d", count.Value, ideal)
		}
		o := sumOverhead{
			N:        N,
			got:      count.Value,
			ideal:    ideal,
			overhead: float64(count.Value) / float64(ideal),
			running:  count.TimeRunning,
		}
		t.Log(o)
	}
}

type sumOverhead struct {
	N        uint64
	got      uint64
	ideal    uint64
	overhead float64
	running  time.Duration
}

func (o sumOverhead) String() string {
	return fmt.Sprintf("N = %11d | instructions = %11d | ideal = %11d | overhead = %10.6f | %v", o.N, o.got, o.ideal, o.overhead, o.running)
}
