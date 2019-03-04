// Copyright 2019 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package perf_test

import (
	"runtime"
	"testing"

	"acln.ro/perf"
	"acln.ro/perf/internal/testasm"
)

func TestInstructionCount(t *testing.T) {
	attr := perf.Instructions.EventAttr()
	attr.Options.Disabled = true
	attr.Options.ExcludeKernel = true
	attr.Options.ExcludeHypervisor = true

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	ev, err := perf.Open(attr, perf.CallingThread, perf.AnyCPU, nil, 0)
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
