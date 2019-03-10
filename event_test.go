// Copyright 2019 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package perf_test

import (
	"fmt"
	"runtime"
	"sort"
	"testing"
	"time"

	"acln.ro/perf"
	"acln.ro/perf/internal/testasm"
)

func TestMeasurementOverhead(t *testing.T) {
	if testing.Short() {
		t.Skip()
	}
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
		10000000000,
	}
	var measurements []overheadMeasurement

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
		measurements = append(measurements, overheadMeasurement{
			N:        N,
			got:      count.Value,
			ideal:    ideal,
			enabled:  count.TimeEnabled,
			running:  count.TimeRunning,
			overhead: float64(count.Value) / float64(ideal),
		})
	}

	decreasing := sort.SliceIsSorted(measurements, func(i, j int) bool {
		return measurements[i].overhead > measurements[j].overhead
	})
	t.Logf("monotonically decreasing: %t", decreasing)
	for _, m := range measurements {
		t.Log(m)
	}
}

type overheadMeasurement struct {
	N        uint64
	got      uint64
	ideal    uint64
	overhead float64
	enabled  time.Duration
	running  time.Duration
}

func (m overheadMeasurement) String() string {
	return fmt.Sprintf("N = %11d | overhead = %10.6f | running: %v",
		m.N, m.overhead, m.running)
}
