// Copyright 2019 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package perf_test

import (
	"context"
	"os"
	"runtime"
	"testing"
	"time"
	"unsafe"

	"acln.ro/perf"
)

func TestSampleUserRegisters(t *testing.T) {
	requires(t, tracepointPMU, debugfs) // TODO(acln): paranoid

	wa := new(perf.Attr)
	wtp := perf.Tracepoint("syscalls", "sys_enter_write")
	if err := wtp.Configure(wa); err != nil {
		t.Fatal(err)
	}

	wa.SetSamplePeriod(1)
	wa.SampleFormat.IP = true
	wa.SampleFormat.UserRegisters = true
	wa.Options.RecordIDAll = true

	// RDI, RSI, RDX. See arch/x86/include/uapi/asm/perf_regs.h.
	wa.SampleRegistersUser = 0x38

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	write, err := perf.Open(wa, perf.CallingThread, perf.AnyCPU, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer write.Close()
	if err := write.MapRing(); err != nil {
		t.Fatal(err)
	}

	null, err := os.OpenFile("/dev/null", os.O_WRONLY, 0200)
	if err != nil {
		t.Fatal(err)
	}
	defer null.Close()

	buf := make([]byte, 8)

	var werr error
	c, err := write.Measure(func() {
		_, werr = null.Write(buf)
	})
	if err != nil {
		t.Fatal(err)
	}
	if werr != nil {
		t.Fatal(err)
	}
	if c.Value != 1 {
		t.Fatalf("got %d hits for write, want 1", c.Value)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	rec, err := write.ReadRecord(ctx)
	if err != nil {
		t.Fatalf("got %v, want a valid record", err)
	}
	sr, ok := rec.(*perf.SampleRecord)
	if !ok {
		t.Fatalf("got %T, want a SampleRecord", rec)
	}
	if nregs := len(sr.UserRegisters); nregs != 3 {
		t.Fatalf("got %d registers, want 3", nregs)
	}

	var (
		rdi = sr.UserRegisters[2]
		rsi = sr.UserRegisters[1]
		rdx = sr.UserRegisters[0]

		nullfd  = uint64(null.Fd())
		bufp    = uint64(uintptr(unsafe.Pointer(&buf[0])))
		bufsize = uint64(len(buf))
	)

	if rdi != nullfd {
		t.Errorf("fd: rdi = %d, want %d", rdi, nullfd)
	}
	if rsi != bufp {
		t.Errorf("buf: rsi = %#x, want %#x", rsi, bufp)
	}
	if rdx != bufsize {
		t.Errorf("count: rdx = %d, want %d", rdx, bufsize)
	}
}
