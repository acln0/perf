// Copyright 2019 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package perf_test

import (
	"runtime"
	"testing"

	"acln.ro/perf"
)

func TestGroup(t *testing.T) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	g := perf.Group{
		CountFormat: perf.CountFormat{
			Enabled: true,
			Running: true,
		},
	}
	g.Add(perf.CPUCycles, perf.Instructions)

	dummy := new(perf.Attr)
	perf.Dummy.Configure(dummy)
	dummy.Sample = 1

	g.Add(dummy)

	ev, err := g.Open(perf.CallingThread, perf.AnyCPU)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	sum := int64(0)
	gc, err := ev.MeasureGroup(func() {
		for i := int64(0); i < 50000; i++ {
			sum += i
		}
	})
	if err != nil {
		t.Fatalf("MeasureGroup: %v", err)
	}
	_ = sum
	_ = gc // TODO(acln): find a way to write a test for these
}
