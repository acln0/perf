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

func TestPoll(t *testing.T) {
	t.Run("Timeout", testPollTimeout)
	t.Run("Cancel", testPollCancel)
}

func testPollTimeout(t *testing.T) {
	requires(t, tracepointPMU, debugfs) // TODO(acln): paranoid

	ga := new(perf.Attr)
	ga.SetSamplePeriod(1)
	ga.SetWakeupEvents(1)
	gtp := perf.Tracepoint("syscalls", "sys_enter_getpid")
	if err := gtp.Configure(ga); err != nil {
		t.Fatal(err)
	}

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
	timeout := 20 * time.Millisecond

	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
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

	// For the first event, we should get a valid sample immediately.
	select {
	case <-time.After(10 * time.Millisecond):
		t.Fatalf("didn't get the first sample: timeout")
	case err := <-errch:
		if err != nil {
			t.Fatalf("got %v, want valid first sample", err)
		}
	}

	// Now, we should get a timeout.
	select {
	case <-time.After(2 * timeout):
		t.Fatalf("didn't time out")
	case err := <-errch:
		if err != context.DeadlineExceeded {
			t.Fatalf("got %v, want %v", err, context.DeadlineExceeded)
		}
	}
}

func testPollCancel(t *testing.T) {
	requires(t, tracepointPMU, debugfs) // TODO(acln): paranoid

	ga := new(perf.Attr)
	ga.SetSamplePeriod(1)
	ga.SetWakeupEvents(1)
	gtp := perf.Tracepoint("syscalls", "sys_enter_getpid")
	if err := gtp.Configure(ga); err != nil {
		t.Fatal(err)
	}

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

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errch := make(chan error)

	go func() {
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
	select {
	case <-time.After(10 * time.Millisecond):
		t.Fatalf("didn't get the first sample: timeout")
	case err := <-errch:
		if err != nil {
			t.Fatalf("got %v, want valid first sample", err)
		}
	}

	// The goroutine reading the records is now blocked in ReadRecord.
	// Cancel the context and observe the results. We should see
	// context.Canceled quite quickly.
	cancel()

	select {
	case <-time.After(10 * time.Millisecond):
		t.Fatalf("context cancel didn't unblock ReadRecord")
	case err := <-errch:
		if err != context.Canceled {
			t.Fatalf("got %v, want %v", err, context.Canceled)
		}
	}
}

func TestSampleGetpid(t *testing.T) {
	requires(t, tracepointPMU, debugfs) // TODO(acln): paranoid

	ga := &perf.Attr{
		SampleFormat: perf.SampleFormat{
			Tid: true,
		},
	}
	ga.SetSamplePeriod(1)
	ga.SetWakeupEvents(1)
	gtp := perf.Tracepoint("syscalls", "sys_enter_getpid")
	if err := gtp.Configure(ga); err != nil {
		t.Fatal(err)
	}

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

	ga := &perf.Attr{
		SampleFormat: perf.SampleFormat{
			Tid: true,
		},
	}
	ga.SetSamplePeriod(1)
	ga.SetWakeupEvents(1)
	gtp := perf.Tracepoint("syscalls", "sys_enter_getpid")
	if err := gtp.Configure(ga); err != nil {
		t.Fatal(err)
	}

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

	ga := &perf.Attr{
		SampleFormat: perf.SampleFormat{
			Tid:  true,
			Time: true,
			CPU:  true,
			Addr: true,
		},
		CountFormat: perf.CountFormat{
			Group: true,
		},
		Options: perf.Options{
			Disabled: true,
		},
	}
	ga.SetSamplePeriod(1)
	ga.SetWakeupEvents(1)
	gtp := perf.Tracepoint("syscalls", "sys_enter_getpid")
	if err := gtp.Configure(ga); err != nil {
		t.Fatalf("Configure: %v", err)
	}

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	leader, err := perf.Open(ga, perf.CallingThread, perf.AnyCPU, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer leader.Close()
	if err := leader.MapRing(); err != nil {
		t.Fatal(err)
	}

	wa := &perf.Attr{
		SampleFormat: perf.SampleFormat{
			Tid:  true,
			Time: true,
			CPU:  true,
			Addr: true,
		},
	}
	wa.SetSamplePeriod(1)
	wa.SetWakeupEvents(1)
	wtp := perf.Tracepoint("syscalls", "sys_enter_write")
	if err := wtp.Configure(wa); err != nil {
		t.Fatal(err)
	}

	follower, err := perf.Open(wa, perf.CallingThread, perf.AnyCPU, leader)
	if err != nil {
		t.Fatal(err)
	}
	defer follower.Close()
	if err := follower.SetOutput(leader); err != nil {
		t.Fatal(err)
	}

	type result struct {
		rec perf.Record
		err error
	}

	errch := make(chan error)
	go func() {
		for i := 0; i < 2; i++ {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
			defer cancel()
			_, err := leader.ReadRecord(ctx)
			errch <- err
		}
	}()

	gc, err := leader.MeasureGroup(func() {
		getpidTrigger()
		writeTrigger()
	})
	if err != nil {
		t.Fatal(err)
	}

	if got := gc.Values[0]; got.Value != 1 {
		t.Fatalf("got %d hits for %q, want 1 hit", got.Value, got.Label)
	}
	if got := gc.Values[1]; got.Value != 1 {
		t.Fatalf("got %d hits for %q, want 1 hit", got.Value, got.Label)
	}

	for i := 0; i < 2; i++ {
		select {
		case <-time.After(10 * time.Millisecond):
			t.Errorf("did not get sample record: timeout")
		case err := <-errch:
			if err != nil {
				t.Fatalf("did not get sample record: %v", err)
			}
		}
	}
}

func TestGroupRecordRedirect(t *testing.T) {
	requires(t, tracepointPMU, debugfs) // TODO(acln): paranoid

	ga := &perf.Attr{
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
	ga.SetSamplePeriod(1)
	ga.SetWakeupEvents(1)
	gtp := perf.Tracepoint("syscalls", "sys_enter_getpid")
	if err := gtp.Configure(ga); err != nil {
		t.Fatal(err)
	}

	wa := &perf.Attr{
		SampleFormat: perf.SampleFormat{
			Tid:  true,
			Time: true,
			CPU:  true,
			IP:   true,
		},
	}
	wa.SetSamplePeriod(1)
	wa.SetWakeupEvents(1)
	wtp := perf.Tracepoint("syscalls", "sys_enter_write")
	if err := wtp.Configure(wa); err != nil {
		t.Fatal(err)
	}

	g := perf.Group{
		CountFormat: perf.CountFormat{
			Enabled: true,
			Running: true,
		},
	}
	g.Add(ga, wa)

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

	grec, err := ev.ReadRecord(ctx)
	if err != nil {
		t.Fatal(err)
	}
	gsr, ok := grec.(*perf.SampleGroupRecord)
	if !ok {
		t.Fatalf("got %T, want SampleGroupRecord", grec)
	}

	wrec, err := ev.ReadRecord(ctx)
	if err != nil {
		t.Fatal(err)
	}
	wsr, ok := wrec.(*perf.SampleGroupRecord)
	if !ok {
		t.Fatalf("got %T, want SampleGroupRecord", wrec)
	}

	if gip, wip := gsr.IP, wsr.IP; gip == wip {
		t.Fatalf("equal IP 0x%x for samples of different events", wip)
	}
}

func TestSampleStack(t *testing.T) {
	requires(t, tracepointPMU, debugfs) // TODO(acln): paranoid

	ga := &perf.Attr{
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
	ga.SetSamplePeriod(1)
	ga.SetWakeupEvents(1)
	gtp := perf.Tracepoint("syscalls", "sys_enter_getpid")
	if err := gtp.Configure(ga); err != nil {
		t.Fatal(err)
	}

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

	pcs := make([]uintptr, 10)
	var n int

	c, err := getpid.Measure(func() {
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
	rec, err := getpid.ReadRecord(ctx)
	if err != nil {
		t.Fatal(err)
	}
	getpidsample, ok := rec.(*perf.SampleRecord)
	if !ok {
		t.Fatalf("got a %T, want a *SampleRecord", rec)
	}

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
