// Copyright 2019 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package perf_test

import (
	"context"
	"runtime"
	"testing"
	"time"

	"acln.ro/perf"
)

func TestSampleGetpid(t *testing.T) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	getpid := perf.Tracepoint("syscalls", "sys_enter_getpid")
	attr := new(perf.Attr)
	if err := getpid.Configure(attr); err != nil {
		t.Fatalf("Configure: %v", err)
	}
	attr.Sample = 1
	attr.RecordFormat = perf.RecordFormat{
		Tid:  true,
		Time: true,
		CPU:  true,
		Addr: true,
	}
	ev, err := perf.Open(attr, perf.CallingThread, perf.AnyCPU, nil, 0)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer ev.Close()

	type result struct {
		rec perf.Record
		err error
	}
	ch := make(chan result)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
		defer cancel()

		rec, err := ev.ReadRecord(ctx)
		ch <- result{rec, err}
	}()
	count, err := ev.Measure(func() {
		getpidTrigger()
	})
	if err != nil {
		t.Fatalf("Measure: %v", err)
	}

	if count.Value != 1 {
		t.Fatalf("got %d hits for %q, want 1 hit", count.Value, count.Label)
	}
	res := <-ch
	if res.err != nil {
		t.Fatalf("did not get record: %v", res.err)
	}
	t.Logf("got record %#v", res.rec)
	t.Logf("CPU mode: %v", res.rec.Header().CPUMode())
}

/*
TODO(acln): fix and enable when I actually understand PERF_EVENT_IOC_SET_OUTPUT

func TestSampleRedirectManualWire(t *testing.T) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	getpid := perf.Tracepoint("syscalls", "sys_enter_getpid")
	attr := new(perf.Attr)
	if err := getpid.Configure(attr); err != nil {
		t.Fatalf("Configure: %v", err)
	}
	attr.Sample = 1
	attr.Options.Disabled = true
	attr.Wakeup = 1
	attr.RecordFormat = perf.RecordFormat{
		Tid:  true,
		Time: true,
		CPU:  true,
		Addr: true,
	}
	attr.CountFormat = perf.CountFormat{
		Group: true,
	}
	leader, err := perf.Open(attr, perf.CallingThread, perf.AnyCPU, nil, 0)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer leader.Close()

	write := perf.Tracepoint("syscalls", "sys_enter_write")
	attr = new(perf.Attr)
	if err := write.Configure(attr); err != nil {
		t.Fatalf("Configure: %v", err)
	}
	attr.Sample = 1
	attr.Wakeup = 1
	attr.RecordFormat = perf.RecordFormat{
		Tid:  true,
		Time: true,
		CPU:  true,
		Addr: true,
	}
	ev, err := perf.Open(attr, perf.CallingThread, perf.AnyCPU, leader, 0)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer ev.Close()

	type result struct {
		rec perf.Record
		err error
	}
	ch := make(chan result)
	go func() {
		for i := 0; i < 2; i++ {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
			defer cancel()
			rec, err := ev.ReadRecord(ctx)
			ch <- result{rec, err}
		}
	}()
	count, err := leader.MeasureGroup(func() {
		getpidTrigger()
		writeTrigger()
	})
	if err != nil {
		t.Fatalf("Measure: %v", err)
	}

	if got := count.Values[0]; got.Value != 1 {
		t.Fatalf("got %d hits for %q, want 1 hit", got.Value, got.Label)
	}
	if got := count.Values[1]; got.Value != 1 {
		t.Fatalf("got %d hits for %q, want 1 hit", got.Value, got.Label)
	}
	for i := 0; i < 2; i++ {
		res := <-ch
		if res.err != nil {
			t.Fatalf("did not get record: %v", res.err)
		}
		t.Logf("got record %#v", res.rec)
		t.Logf("CPU mode: %v", res.rec.Header().CPUMode())
	}
}

*/
