// Copyright 2019 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package perf_test

import (
	"math/rand"
	"os"
	"runtime"
	"testing"
	"time"

	"acln.ro/perf"

	"golang.org/x/sys/unix"
)

func TestOpen(t *testing.T) {
	t.Run("BadGroup", testOpenBadGroup)
	t.Run("BadAttrType", testOpenBadAttrType)
	t.Run("PopulatesLabel", testOpenPopulatesLabel)
}

func testOpenBadGroup(t *testing.T) {
	requires(t, paranoid(1), hardwarePMU)

	ca := new(perf.Attr)
	perf.CPUCycles.Configure(ca)
	ca.CountFormat.Group = true

	cycles, err := perf.Open(ca, perf.CallingThread, perf.AnyCPU, nil)
	if err != nil {
		t.Fatal(err)
	}
	cycles.Close()

	_, err = perf.Open(ca, perf.CallingThread, perf.AnyCPU, cycles)
	if err == nil {
		t.Fatal("successful Open with closed group *Event")
	}

	cycles = new(perf.Event) // uninitialized
	_, err = perf.Open(ca, perf.CallingThread, perf.AnyCPU, cycles)
	if err == nil {
		t.Fatal("successful Open with closed group *Event")
	}
}

func testOpenBadAttrType(t *testing.T) {
	a := &perf.Attr{
		Type: 42,
	}

	_, err := perf.Open(a, perf.CallingThread, perf.AnyCPU, nil)
	if err == nil {
		t.Fatal("got a valid *Event for bad Attr.Type 42")
	}
}

func testOpenPopulatesLabel(t *testing.T) {
	// TODO(acln): extend when we implement general label lookup
	requires(t, paranoid(1), hardwarePMU)

	ca := &perf.Attr{
		Type:   perf.HardwareEvent,
		Config: uint64(perf.CPUCycles),
	}

	cycles, err := perf.Open(ca, perf.CallingThread, perf.AnyCPU, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer cycles.Close()

	c, err := cycles.Measure(getpidTrigger)
	if err != nil {
		t.Fatal(err)
	}
	if c.Label == "" {
		t.Fatal("Open did not set label on *Attr")
	}
}

func TestHardwareCounters(t *testing.T) {
	requires(t, paranoid(1), hardwarePMU)

	t.Run("IPC", testIPC)
}

func testIPC(t *testing.T) {
	var g perf.Group
	g.Add(perf.Instructions, perf.CPUCycles)

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	hw, err := g.Open(perf.CallingThread, perf.AnyCPU)
	if err != nil {
		t.Fatal(err)
	}
	defer hw.Close()

	var sum int64
	gc, err := hw.MeasureGroup(func() {
		for i := int64(0); i < 1000000; i++ {
			sum += i
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range gc.Values {
		if c.Value == 0 {
			t.Fatalf("didn't count %q", c.Label)
		}
	}
	insns := gc.Values[0].Value
	cycles := gc.Values[1].Value
	ipc := float64(insns) / float64(cycles)
	t.Logf("got %d instructions, %d cycles: %f IPC", insns, cycles, ipc)
}

func TestSoftwareCounters(t *testing.T) {
	requires(t, paranoid(1), softwarePMU)

	t.Run("PageFaults", testPageFaults)
}

var fault []byte

func testPageFaults(t *testing.T) {
	pfa := new(perf.Attr)
	perf.PageFaults.Configure(pfa)

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	faults, err := perf.Open(pfa, perf.CallingThread, perf.AnyCPU, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer faults.Close()

	runtime.GC()

	c, err := faults.Measure(func() {
		fault = make([]byte, 64*1024*1024)
		fault[0] = 1
		fault[63*1024*1024] = 1
	})
	if err != nil {
		t.Fatal(err)
	}
	if c.Value == 0 {
		t.Fatal("didn't see a page fault")
	}
	t.Logf("saw %d page faults", c.Value)
}

func TestHardwareCacheCounters(t *testing.T) {
	// TODO(acln): add PMU requirement? but how?
	//
	// $ ls /sys/bus/event_source/devices/*/type | xargs cat
	//
	// does not contain a 3, which is the value of perf.HardwareCacheEvent
	requires(t, paranoid(1))

	t.Run("L1DataMissesBadLocality", testL1DataMissesBadLocality)
	t.Run("L1DataMissesGoodLocality", testL1DataMissesGoodLocality)
}

func testL1DataMissesBadLocality(t *testing.T) {
	hwca := new(perf.Attr)
	hwcc := perf.HardwareCacheCounter{
		Cache:  perf.L1D,
		Op:     perf.Read,
		Result: perf.Miss,
	}
	hwcc.Configure(hwca)

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	l1dmisses, err := perf.Open(hwca, perf.CallingThread, perf.AnyCPU, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer l1dmisses.Close()

	rng := rand.New(rand.NewSource(time.Now().Unix()))

	max := 1000

	var bad []interface{}
	for i := 0; i < 10000; i++ {
		bad = append(bad, rng.Intn(max))
	}

	sink := 0
	c, err := l1dmisses.Measure(func() {
		for _, v := range bad {
			if v.(int) < max/2 {
				sink++
			}
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	if c.Value == 0 {
		t.Fatalf("recorded no L1 data cache misses")
	}

	t.Logf("bad locality: got %d L1 data cache misses", c.Value)
}

func testL1DataMissesGoodLocality(t *testing.T) {
	hwca := new(perf.Attr)
	hwcc := perf.HardwareCacheCounter{
		Cache:  perf.L1D,
		Op:     perf.Read,
		Result: perf.Miss,
	}
	hwcc.Configure(hwca)

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	l1dmisses, err := perf.Open(hwca, perf.CallingThread, perf.AnyCPU, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer l1dmisses.Close()

	rng := rand.New(rand.NewSource(time.Now().Unix()))

	max := 1000

	var contiguous []int
	for i := 0; i < 10000; i++ {
		contiguous = append(contiguous, rng.Intn(max))
	}

	sink := 0
	c, err := l1dmisses.Measure(func() {
		for _, v := range contiguous {
			if v < max/2 {
				sink++
			}
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	if c.Value == 0 {
		t.Fatalf("recorded no L1 data cache misses")
	}

	t.Logf("good locality: got %d L1 data cache misses", c.Value)
}

func TestCountFormatID(t *testing.T) {
	requires(t, paranoid(1), softwarePMU)

	pfa := new(perf.Attr)
	perf.PageFaults.Configure(pfa)
	pfa.CountFormat.ID = true

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	faults, err := perf.Open(pfa, perf.CallingThread, perf.AnyCPU, nil)
	if err != nil {
		t.Fatal(err)
	}

	runtime.GC()

	c, err := faults.Measure(func() {
		fault = make([]byte, 64*1024*1024)
		fault[0] = 1
		fault[63*1024*1024] = 1
	})
	if err != nil {
		t.Fatal(err)
	}
	if c.Value == 0 {
		t.Fatal("didn't see a page fault")
	}
	id, err := faults.ID()
	if err != nil {
		t.Fatal(err)
	}
	if id != c.ID {
		t.Fatalf("got ID %d from ioctl, but %d from count read", id, c.ID)
	}
}

type singleTracepointTest struct {
	category string
	event    string
	trigger  func()
}

func (tt singleTracepointTest) run(t *testing.T) {
	tp := perf.Tracepoint(tt.category, tt.event)
	attr := new(perf.Attr)
	if err := tp.Configure(attr); err != nil {
		t.Fatal(err)
	}

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	ev, err := perf.Open(attr, perf.CallingThread, perf.AnyCPU, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer ev.Close()

	c, err := ev.Measure(func() {
		tt.trigger()
	})
	if err != nil {
		t.Fatal(err)
	}
	if c.Value != 1 {
		t.Fatalf("got %d hits for %q, want 1 hit", c.Value, c.Label)
	}
}

func (tt singleTracepointTest) String() string {
	return tt.category + ":" + tt.event
}

func TestSingleTracepoint(t *testing.T) {
	requires(t, paranoid(1), tracepointPMU, debugfs)

	tests := []singleTracepointTest{
		{
			category: "syscalls",
			event:    "sys_enter_getpid",
			trigger:  getpidTrigger,
		},
		{
			category: "syscalls",
			event:    "sys_enter_read",
			trigger:  readTrigger,
		},
		{
			category: "syscalls",
			event:    "sys_enter_write",
			trigger:  writeTrigger,
		},
	}
	for _, tt := range tests {
		t.Run(tt.String(), tt.run)
	}
}

func getpidTrigger() {
	unix.Getpid()
}

func readTrigger() {
	zero, err := os.Open("/dev/zero")
	if err != nil {
		panic(err)
	}
	buf := make([]byte, 8)
	if _, err := zero.Read(buf); err != nil {
		panic(err)
	}
}

func writeTrigger() {
	null, err := os.OpenFile("/dev/null", os.O_WRONLY, 0200)
	if err != nil {
		panic(err)
	}
	if _, err := null.Write([]byte("big data")); err != nil {
		panic(err)
	}
}
