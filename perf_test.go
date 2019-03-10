// Copyright 2019 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package perf

import (
	"context"
	"runtime"
	"testing"
	"time"

	"acln.ro/perf/internal/testasm"

	"golang.org/x/sys/unix"
)

func TestManualGroupWire(t *testing.T) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	insns := Instructions.MarshalAttr()
	insns.CountFormat = CountFormat{
		TotalTimeEnabled: true,
		TotalTimeRunning: true,
		Group:            true,
		ID:               true,
	}
	insns.Options.Disabled = true
	insns.Options.ExcludeKernel = true
	insns.Options.ExcludeHypervisor = true

	cycles := CPUCycles.MarshalAttr()
	cycles.Options.ExcludeKernel = true
	cycles.Options.ExcludeHypervisor = true

	iev, err := Open(insns, CallingThread, AnyCPU, nil, 0)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer iev.Close()

	cev, err := Open(cycles, CallingThread, AnyCPU, iev, 0)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer cev.Close()

	counts, err := iev.MeasureGroup(func() {
		testasm.SumN(50000)
	})
	if err != nil {
		t.Fatalf("ReadGroupCount: %v", err)
	}

	t.Logf("%+v instructions, %+v CPU cycles in %v %v", counts.Counts[0], counts.Counts[1], counts.TimeEnabled, counts.TimeRunning)
}

func TestTracepoint(t *testing.T) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	attr, err := NewTracepoint("syscalls", "sys_enter_getpid")
	if err != nil {
		t.Fatalf("NewTracepoint: %v", err)
	}

	attr.Sample = 1
	attr.Wakeup = 1
	attr.RecordFormat = RecordFormat{
		Identifier: true,
		IP:         true,
		Tid:        true,
		Time:       true,
	}
	attr.Options = Options{
		Watermark: true,
	}

	ev, err := Open(attr, CallingThread, AnyCPU, nil, 0)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer ev.Close()

	if err := ev.Enable(); err != nil {
		t.Fatalf("Enable: %v", err)
	}

	const N = 2

	for i := 0; i < N; i++ {
		unix.Getpid()
		time.Sleep(100 * time.Millisecond)
	}

	count, err := ev.ReadCount()
	if err != nil {
		t.Fatalf("ReadCount: %v", err)
	}

	t.Logf("got count value %d", count.Value)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errc := make(chan error)

	go func() {
		defer close(errc)

		for i := 0; i < N; i++ {
			rec, err := ev.ReadRecord(ctx)
			if err != nil {
				errc <- err
				return
			}
			t.Logf("got record %+v", rec)
		}
	}()

	time.Sleep(100 * time.Millisecond)
	cancel()
	t.Log(<-errc)
}
