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
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	ga := new(perf.Attr)
	gtp := perf.Tracepoint("syscalls", "sys_enter_getpid")
	if err := gtp.Configure(ga); err != nil {
		t.Fatal(err)
	}

	ga.Sample = 1
	ga.SampleFormat.Tid = true

	getpid, err := perf.Open(ga, perf.CallingThread, perf.AnyCPU, nil, 0)
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

	c, err := getpid.Measure(func() {
		unix.Getpid()
	})
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

type recordReadResult struct {
	rec perf.Record
	err error
}

func TestSampleGetpid(t *testing.T) {
	ga := new(perf.Attr)
	gtp := perf.Tracepoint("syscalls", "sys_enter_getpid")
	if err := gtp.Configure(ga); err != nil {
		t.Fatal(err)
	}

	ga.Sample = 1
	ga.SampleFormat.Tid = true

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	getpid, err := perf.Open(ga, perf.CallingThread, perf.AnyCPU, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer getpid.Close()
	if err := getpid.MapRing(); err != nil {
		t.Fatal(err)
	}

	c, err := getpid.Measure(func() {
		unix.Getpid()
	})
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

	getpid, err := perf.Open(ga, perf.CallingThread, perf.AnyCPU, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer getpid.Close()
	if err := getpid.MapRing(); err != nil {
		t.Fatal(err)
	}

	const n = 5
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

	var bad bool

	c, err := getpid.Measure(func() {
		for i := 0; i < n; i++ {
			unix.Getpid()
			if ok := <-sawSample; !ok {
				bad = true
			}
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	if c.Value != n {
		t.Fatalf("got %d hits for %q, want %d", c.Value, c.Label, n)
	}
	if bad {
		t.Fatalf("didn't see all samples on ring during measurement")
	}
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
	attr.SampleFormat = perf.SampleFormat{
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
	attr.SampleFormat = perf.SampleFormat{
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

	ev, err := g.Open(perf.CallingThread, perf.AnyCPU)
	if err != nil {
		t.Fatal(err)
	}
	defer ev.Close()

	counts, err := ev.MeasureGroup(func() {
		getpidTrigger()
		writeTrigger()
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

func TestRecordStack(t *testing.T) {
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

	ev, err := perf.Open(getpidattr, perf.CallingThread, perf.AnyCPU, nil, 0)
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
		unix.Getpid()
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

	t.Log("sampled callchain:")
	for _, pc := range getpidsample.Callchain {
		fn := runtime.FuncForPC(uintptr(pc))
		if fn == nil {
			t.Logf("%#x: <nil>\n", pc)
		} else {
			file, line := fn.FileLine(uintptr(pc))
			t.Logf("%#x: %s:%d %s\n", pc, file, line, fn.Name())
		}
	}

	t.Log()

	t.Log("Go PCs:")
	for _, pc := range pcs {
		fn := runtime.FuncForPC(pc)
		if fn == nil {
			t.Logf("%#x: <nil>\n", pc)
		} else {
			file, line := fn.FileLine(pc)
			t.Logf("%#x: %s:%d %s\n", pc, file, line, fn.Name())
		}
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
}
