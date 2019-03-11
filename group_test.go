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

func TestGroup(t *testing.T) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	g := perf.Group{
		CountFormat: perf.CountFormat{
			TotalTimeEnabled: true,
			TotalTimeRunning: true,
		},
	}
	g.Add(perf.CPUCycles, perf.Instructions)

	dummy := new(perf.Attr)
	perf.Dummy.Configure(dummy)
	dummy.Sample = 1

	g.AddAttr(dummy)

	ev, err := g.Open(perf.CallingThread, perf.AnyCPU)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	counts, err := ev.MeasureGroup(func() {
		testasm.SumN(50000)
	})
	if err != nil {
		t.Fatalf("MeasureGroup: %v", err)
	}
	_ = counts // TODO(acln): find a way to write a test for these
}
