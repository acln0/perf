// Copyright 2019 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package perf

import (
	"context"
	"os/exec"
	"runtime"
	"testing"
	"time"

	"acln.ro/perf/internal/testasm"
)

func TestInstructionCount(t *testing.T) {
	attr := Instructions.EventAttr()
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

	res := testasm.SumN(50000)

	if err := ev.Disable(); err != nil {
		t.Fatalf("Disable: %v", err)
	}

	count, err := ev.ReadCount()
	if err != nil {
		t.Fatalf("ReadCount: %v", err)
	}

	t.Logf("used %d instructions, got result %d", count.Value, res)
}

func TestRing(t *testing.T) {
	attr := EventAttr{
		Type:   HardwareEvent,
		Config: uint64(CPUCycles),
		Wakeup: 1,
		Options: EventOptions{
			Disabled:          true,
			ExcludeKernel:     true,
			ExcludeHypervisor: true,
			Watermark:         true,
			SampleIDAll:       true,
		},
	}

	ev, err := Open(&attr, CallingThread, AnyCPU, nil, 0)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer ev.Close()

	r, err := newRing(ev.fd, 1)
	if err != nil {
		t.Fatalf("newRing: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errch := make(chan error)
	go func() {
		_, err = r.ReadRecord(ctx)
		errch <- err
	}()

	_, err = exec.Command("echo", "something").Output()
	if err != nil {
		t.Fatalf("exec: %v", err)
	}

	time.Sleep(1 * time.Second)
	cancel()
	err = <-errch
	t.Log(err)
}
