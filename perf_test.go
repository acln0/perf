// Copyright 2019 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package perf

import (
	"context"
	"runtime"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestTracepoint(t *testing.T) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	attr, err := NewTracepoint("syscalls", "sys_enter_getpid")
	if err != nil {
		t.Fatalf("NewTracepoint: %v", err)
	}

	attr.Sample = 1
	attr.Wakeup = 1
	attr.RecordFormat = RecordFormat{
		Identifier: true,
		IP:         true,
		Tid:        true,
		Time:       true,
	}
	attr.Options = Options{
		Watermark: true,
	}

	ev, err := Open(attr, CallingThread, AnyCPU, nil, 0)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer ev.Close()

	if err := ev.Enable(); err != nil {
		t.Fatalf("Enable: %v", err)
	}

	const N = 2

	for i := 0; i < N; i++ {
		unix.Getpid()
		time.Sleep(100 * time.Millisecond)
	}

	count, err := ev.ReadCount()
	if err != nil {
		t.Fatalf("ReadCount: %v", err)
	}

	t.Logf("got count value %d", count.Value)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errc := make(chan error)

	go func() {
		defer close(errc)

		for i := 0; i < N; i++ {
			rec, err := ev.ReadRecord(ctx)
			if err != nil {
				errc <- err
				return
			}
			t.Logf("got record %+v", rec)
		}
	}()

	time.Sleep(100 * time.Millisecond)
	cancel()
	t.Log(<-errc)
}
