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

	"golang.org/x/sys/unix"
)

func TestPollTimeout(t *testing.T) {
	requires(t, tracepointPMU, debugfs) // TODO(acln): paranoid

	ga := new(perf.Attr)
	gtp := perf.Tracepoint("syscalls", "sys_enter_getpid")
	if err := gtp.Configure(ga); err != nil {
		t.Fatal(err)
	}

	ga.SetSamplePeriod(1)
	ga.SampleFormat.Tid = true

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	getpid, err := perf.Open(ga, perf.CallingThread, perf.AnyCPU, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer getpid.Close()
	if err := getpid.MapRing(); err != nil {
		t.Fatal(err)
	}

	errch := make(chan error)

	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
		defer cancel()

		for i := 0; i < 2; i++ {
			_, err := getpid.ReadRecord(ctx)
			errch <- err
		}
	}()

	c, err := getpid.Measure(getpidTrigger)
	if err != nil {
		t.Fatal(err)
	}
	if c.Value != 1 {
		t.Fatalf("got %d hits for %q, want 1", c.Value, c.Label)
	}

	// For the first event, we should get a valid sample.
	if err := <-errch; err != nil {
		t.Fatalf("got %v, want valid first sample", err)
	}

	// Now, we should get a timeout.
	if err := <-errch; err != context.DeadlineExceeded {
		t.Fatalf("got %v, want %v", err, context.DeadlineExceeded)
	}
}

func TestSampleGetpid(t *testing.T) {
	requires(t, tracepointPMU, debugfs) // TODO(acln): paranoid

	ga := new(perf.Attr)
	gtp := perf.Tracepoint("syscalls", "sys_enter_getpid")
	if err := gtp.Configure(ga); err != nil {
		t.Fatal(err)
	}

	ga.SetSamplePeriod(1)
	ga.SampleFormat.Tid = true

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	getpid, err := perf.Open(ga, perf.CallingThread, perf.AnyCPU, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer getpid.Close()
	if err := getpid.MapRing(); err != nil {
		t.Fatal(err)
	}

	c, err := getpid.Measure(getpidTrigger)
	if err != nil {
		t.Fatal(err)
	}

	if c.Value != 1 {
		t.Fatalf("got %d hits for %q, want 1 hit", c.Value, c.Label)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Millisecond)
	defer cancel()
	rec, err := getpid.ReadRecord(ctx)
	if err != nil {
		t.Fatalf("got %v, want a valid sample record", err)
	}
	sr, ok := rec.(*perf.SampleRecord)
	if !ok {
		t.Fatalf("got a %T, want a SampleRecord", rec)
	}
	pid, tid := unix.Getpid(), unix.Gettid()
	if int(sr.Pid) != pid || int(sr.Tid) != tid {
		t.Fatalf("got pid=%d tid=%d, want pid=%d tid=%d", sr.Pid, sr.Tid, pid, tid)
	}
}

func TestConcurrentSampling(t *testing.T) {
	requires(t, tracepointPMU, debugfs) // TODO(acln): paranoid

	ga := new(perf.Attr)
	gtp := perf.Tracepoint("syscalls", "sys_enter_getpid")
	if err := gtp.Configure(ga); err != nil {
		t.Fatal(err)
	}

	ga.Sample = 1
	ga.SampleFormat.Tid = true
	ga.Wakeup = 1

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	getpid, err := perf.Open(ga, perf.CallingThread, perf.AnyCPU, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer getpid.Close()
	if err := getpid.MapRing(); err != nil {
		t.Fatal(err)
	}

	const n = 6
	sawSample := make(chan bool)

	go func() {
		for i := 0; i < n; i++ {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
			defer cancel()
			rec, err := getpid.ReadRecord(ctx)
			_, isSample := rec.(*perf.SampleRecord)
			if err == nil && isSample {
				sawSample <- true
			} else {
				sawSample <- false
			}
		}
	}()

	seen := 0

	c, err := getpid.Measure(func() {
		for i := 0; i < n; i++ {
			getpidTrigger()
			if ok := <-sawSample; ok {
				seen++
			}
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	if c.Value != n {
		t.Fatalf("got %d hits for %q, want %d", c.Value, c.Label, n)
	}
	if seen != n {
		t.Fatalf("saw %d samples, want %d", seen, n)
	}
}

func TestRecordRedirectManualWire(t *testing.T) {
	requires(t, tracepointPMU, debugfs) // TODO(acln): paranoid

	getpid := perf.Tracepoint("syscalls", "sys_enter_getpid")
	attr := new(perf.Attr)
	if err := getpid.Configure(attr); err != nil {
		t.Fatalf("Configure: %v", err)
	}
	attr.SetSamplePeriod(1)
	attr.Options.Disabled = true
	attr.SetWakeupEvents(1)
	attr.SampleFormat = perf.SampleFormat{
		Tid:  true,
		Time: true,
		CPU:  true,
		Addr: true,
	}
	attr.CountFormat = perf.CountFormat{
		Group: true,
	}

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	leader, err := perf.Open(attr, perf.CallingThread, perf.AnyCPU, nil)
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
	attr.SampleFormat = perf.SampleFormat{
		Tid:  true,
		Time: true,
		CPU:  true,
		Addr: true,
	}

	follower, err := perf.Open(attr, perf.CallingThread, perf.AnyCPU, leader)
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

	gc, err := leader.MeasureGroup(func() {
		getpidTrigger()
		writeTrigger()
	})
	if err != nil {
		t.Fatalf("Measure: %v", err)
	}

	if got := gc.Values[0]; got.Value != 1 {
		t.Fatalf("got %d hits for %q, want 1 hit", got.Value, got.Label)
	}
	if got := gc.Values[1]; got.Value != 1 {
		t.Fatalf("got %d hits for %q, want 1 hit", got.Value, got.Label)
	}
	for i := 0; i < 2; i++ {
		res := <-ch
		if res.err != nil {
			t.Fatalf("did not get sample record: %v", res.err)
		}
	}
}

func TestGroupRecordRedirect(t *testing.T) {
	requires(t, tracepointPMU, debugfs) // TODO(acln): paranoid

	getpidattr := &perf.Attr{
		Sample: 1,
		Wakeup: 1,
		Options: perf.Options{
			Disabled: true,
		},
		SampleFormat: perf.SampleFormat{
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
		SampleFormat: perf.SampleFormat{
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
			Enabled: true,
			Running: true,
		},
	}
	g.Add(getpidattr, writeattr)

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	ev, err := g.Open(perf.CallingThread, perf.AnyCPU)
	if err != nil {
		t.Fatal(err)
	}
	defer ev.Close()

	gc, err := ev.MeasureGroup(func() {
		getpidTrigger()
		writeTrigger()
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, got := range gc.Values {
		if got.Value != 1 {
			t.Fatalf("want 1 hit for %q, got %d", got.Label, got.Value)
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
		t.Fatalf("equal instruction pointers 0x%x for samples of different events", getpidip)
	}
}

func TestRecordStack(t *testing.T) {
	requires(t, tracepointPMU, debugfs) // TODO(acln): paranoid

	getpidattr := &perf.Attr{
		Sample: 1,
		Wakeup: 1,
		Options: perf.Options{
			Disabled: true,
		},
		SampleFormat: perf.SampleFormat{
			Tid:       true,
			Time:      true,
			CPU:       true,
			IP:        true,
			Callchain: true,
		},
	}
	getpidtp := perf.Tracepoint("syscalls", "sys_enter_getpid")
	if err := getpidtp.Configure(getpidattr); err != nil {
		t.Fatal(err)
	}

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	ev, err := perf.Open(getpidattr, perf.CallingThread, perf.AnyCPU, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer ev.Close()

	if err := ev.MapRing(); err != nil {
		t.Fatal(err)
	}

	pcs := make([]uintptr, 10)
	var n int

	c, err := ev.Measure(func() {
		n = runtime.Callers(2, pcs)
		getpidTrigger()
	})
	if err != nil {
		t.Fatal(err)
	}
	if c.Value != 1 {
		t.Fatalf("want 1 hit for %q, got %d", c.Label, c.Value)
	}

	pcs = pcs[:n]

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	rec, err := ev.ReadRecord(ctx)
	if err != nil {
		t.Fatal(err)
	}
	getpidsample := rec.(*perf.SampleRecord)

	i := len(pcs) - 1
	j := len(getpidsample.Callchain) - 1

	for i >= 0 && j >= 0 {
		gopc := pcs[i]
		kpc := getpidsample.Callchain[j]
		if gopc != uintptr(kpc) {
			t.Fatalf("Go (%#x) and kernel (%#x) PC differ", gopc, kpc)
		}
		i--
		j--
	}

	logFrame := func(pc uintptr) {
		fn := runtime.FuncForPC(pc)
		if fn == nil {
			t.Logf("%#x <nil>", pc)
		} else {
			file, line := fn.FileLine(pc)
			t.Logf("%#x %s:%d %s", pc, file, line, fn.Name())
		}
	}

	t.Log("kernel callchain:")
	for _, kpc := range getpidsample.Callchain {
		logFrame(uintptr(kpc))
	}

	t.Log()

	t.Logf("Go stack:")
	for _, gopc := range pcs {
		logFrame(gopc)
	}
}
