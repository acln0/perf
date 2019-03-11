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

func TestRecordGetpid(t *testing.T) {
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
	if err := ev.MapRing(); err != nil {
		t.Fatalf("MapRing: %v", err)
	}

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
	_ = res.rec // TODO(acln): find a way to write a test for this
}

func TestRecordRedirectManualWire(t *testing.T) {
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

	if err := leader.MapRing(); err != nil {
		t.Fatalf("MapRing: %v", err)
	}

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
	follower, err := perf.Open(attr, perf.CallingThread, perf.AnyCPU, leader, 0)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer follower.Close()

	if err := follower.SetOutput(leader); err != nil {
		t.Fatalf("SetOutput: %v", err)
	}

	type result struct {
		rec perf.Record
		err error
	}
	ch := make(chan result)
	go func() {
		for i := 0; i < 2; i++ {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
			defer cancel()
			rec, err := leader.ReadRecord(ctx)
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
		_ = res.rec // TODO(acln): find a way to write a test for these
	}
}

func TestGroupRecordRedirect(t *testing.T) {
	getpidattr := &perf.Attr{
		Sample: 1,
		Wakeup: 1,
		Options: perf.Options{
			Disabled: true,
		},
		RecordFormat: perf.RecordFormat{
			Tid:  true,
			Time: true,
			CPU:  true,
			IP:   true,
		},
	}
	getpidtp := perf.Tracepoint("syscalls", "sys_enter_getpid")
	if err := getpidtp.Configure(getpidattr); err != nil {
		t.Fatal(err)
	}

	writeattr := &perf.Attr{
		Sample: 1,
		Wakeup: 1,
		RecordFormat: perf.RecordFormat{
			Tid:  true,
			Time: true,
			CPU:  true,
			IP:   true,
		},
	}
	writetp := perf.Tracepoint("syscalls", "sys_enter_write")
	if err := writetp.Configure(writeattr); err != nil {
		t.Fatal(err)
	}

	g := perf.Group{
		CountFormat: perf.CountFormat{
			TotalTimeEnabled: true,
			TotalTimeRunning: true,
		},
	}
	g.AddAttr(getpidattr, writeattr)

	ev, err := g.Open(perf.CallingThread, perf.AnyCPU)
	if err != nil {
		t.Fatal(err)
	}
	defer ev.Close()

	counts, err := ev.MeasureGroup(func() {
		if err := getpidTrigger(); err != nil {
			t.Fatal(err)
		}
		if err := writeTrigger(); err != nil {
			t.Fatal(err)
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range counts.Values {
		if v.Value != 1 {
			t.Fatalf("want 1 hit for %q, got %d", v.Label, v.Value)
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	getpidrec, err := ev.ReadRecord(ctx)
	if err != nil {
		t.Fatal(err)
	}
	writerec, err := ev.ReadRecord(ctx)
	if err != nil {
		t.Fatal(err)
	}
	getpidip := getpidrec.(*perf.SampleGroupRecord).IP
	writeip := writerec.(*perf.SampleGroupRecord).IP
	if getpidip == writeip {
		t.Fatalf("suspicious equal instruction pointers 0x%x for samples", getpidip)
	}
}
