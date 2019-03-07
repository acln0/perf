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

func TestInstructionCount(t *testing.T) {
	attr := Instructions.EventAttr()
	attr.ReadFormat = ReadFormat{
		TotalTimeEnabled: true,
		TotalTimeRunning: true,
		ID:               true,
	}
	attr.Options.Disabled = true
	attr.Options.ExcludeKernel = true
	attr.Options.ExcludeHypervisor = true

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	ev, err := Open(attr, CallingThread, AnyCPU, nil, 0)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer ev.Close()

	if err := ev.Reset(); err != nil {
		t.Fatalf("Reset: %v", err)
	}
	if err := ev.Enable(); err != nil {
		t.Fatalf("Enable: %v", err)
	}

	testasm.SumN(50000)

	if err := ev.Disable(); err != nil {
		t.Fatalf("Disable: %v", err)
	}

	count, err := ev.ReadCount()
	if err != nil {
		t.Fatalf("ReadCount: %v", err)
	}

	t.Logf("got %+v\n", count)
}

func TestGroup(t *testing.T) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	insns := Instructions.EventAttr()
	insns.ReadFormat = ReadFormat{
		TotalTimeEnabled: true,
		TotalTimeRunning: true,
		Group:            true,
		ID:               true,
	}
	insns.Options.Disabled = true
	insns.Options.ExcludeKernel = true
	insns.Options.ExcludeHypervisor = true

	cycles := CPUCycles.EventAttr()
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

	if err := iev.Reset(); err != nil {
		t.Fatalf("Reset: %v", err)
	}
	if err := iev.Enable(); err != nil {
		t.Fatalf("Enable: %v", err)
	}

	testasm.SumN(50000)

	if err := iev.Disable(); err != nil {
		t.Fatalf("Disable: %v", err)
	}
	counts, err := iev.ReadGroupCount()
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

	attr.SampleFormat.Identifier = true
	attr.Options.Disabled = true
	attr.Options.ExcludeGuest = true
	attr.Options.EnableOnExec = true

	ev, err := Open(attr, CallingThread, AnyCPU, nil, 0)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer ev.Close()

	r, err := newRing(ev.fd, 128)
	if err != nil {
		t.Fatalf("newRing: %v", err)
	}

	if err := ev.Enable(); err != nil {
		t.Fatalf("Enable: %v", err)
	}

	unix.Getpid()

	count, err := ev.ReadCount()
	if err != nil {
		t.Fatalf("ReadCount: %v", err)
	}

	t.Logf("got count value %d", count.Value)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errc := make(chan error)

	go func() {
		_, err := r.ReadRecord(ctx)
		errc <- err
	}()

	time.Sleep(100 * time.Millisecond)
	cancel()
	t.Log(<-errc)
}
