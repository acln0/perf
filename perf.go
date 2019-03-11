// Copyright 2019 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

/*
Package perf provides access to the Linux perf API.

A Group represents a set of perf events measured together.

	var g perf.Group
	g.Add(perf.Instructions, perf.CPUCycles)

	hw, err := g.Open(targetpid, perf.AnyCPU)
	// ...
	gc, err := hw.MeasureGroup(func() { ... })

Attr is a low level configuration structure:

	fattr := &perf.Attr{
		Type:   perf.SoftwareEvent,
		Config: uint64(perf.PageFaults),
		CountFormat: perf.CountFormat{
			Running: true,
			ID:      true,
		},
	}

	faults, err := perf.Open(fattr, perf.CallingThread, perf.AnyCPU, nil, 0)
	// ...
	c, err := faults.Measure(func() { ... })

Overflow records are available once the MapRing method on
Event is called:

	var ev perf.Event // initialized previously
	ev.MapRing()

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	for {
		rec, err := ev.ReadRecord(ctx)
		// ...
	}

Tracepoints are also supported:

	wattr := &perf.Attr{
		Sample: 1,
		RecordFormat: perf.SampleFormat{
			Pid: true,
			Tid: true,
			IP:  true,
		},
	}
	writetp := perf.Tracepoint("syscalls", "sys_enter_write")
	writetp.Configure(wattr)

	writes, err := perf.Open(wattr, targetpid, perf.AnyCPU, nil, 0)
	// ...
	c, err := writes.Measure(func() { ... })

For more detailed information, see the examples, and man 2 perf_event_open.
*/
package perf

import (
	"time"
	"unsafe"
)

// fields is a collection of 32-bit or 64-bit fields.
type fields []byte

// uint64 decodes the next 64 bit field into v.
func (f *fields) uint64(v *uint64) {
	*v = *(*uint64)(unsafe.Pointer(&(*f)[0]))
	f.advance(8)
}

// uint64Cond decodes the next 64 bit field into v, if cond is true.
func (f *fields) uint64Cond(cond bool, v *uint64) {
	if cond {
		f.uint64(v)
	}
}

// uint32 decodes a pair of uint32s into a and b.
func (f *fields) uint32(a, b *uint32) {
	*a = *(*uint32)(unsafe.Pointer(&(*f)[0]))
	*b = *(*uint32)(unsafe.Pointer(&(*f)[4]))
	f.advance(8)
}

// uint32 decodes a pair of uint32s into a and b, if cond is true.
func (f *fields) uint32Cond(cond bool, a, b *uint32) {
	if cond {
		f.uint32(a, b)
	}
}

func (f *fields) uint32sizeBytes(b *[]byte) {
	size := *(*uint32)(unsafe.Pointer(&(*f)[0]))
	f.advance(4)
	data := make([]byte, size)
	copy(data, *f)
	f.advance(int(size))
}

func (f *fields) uint64sizeBytes(b *[]byte) {
	size := *(*uint64)(unsafe.Pointer(&(*f)[0]))
	f.advance(8)
	data := make([]byte, size)
	copy(data, *f)
	f.advance(int(size))
}

// duration decodes a duration into d.
func (f *fields) duration(d *time.Duration) {
	*d = *(*time.Duration)(unsafe.Pointer(&(*f)[0]))
	f.advance(8)
}

// string decodes a null-terminated string into s. The null terminator
// is not included in the string written to s.
func (f *fields) string(s *string) {
	for i := 0; i < len(*f); i++ {
		if (*f)[i] == 0 {
			*s = string((*f)[:i])
			if i+1 <= len(*f) {
				f.advance(i + 1)
			}
			return
		}
	}
}

// id decodes a RecordID based on the SampleFormat ev was configured with.
func (f *fields) id(id *RecordID, ev *Event) {
	if !ev.attr.Options.RecordIDAll {
		return
	}
	f.uint32Cond(ev.attr.SampleFormat.Tid, &id.Pid, &id.Tid)
	f.uint64Cond(ev.attr.SampleFormat.Time, &id.Time)
	f.uint64Cond(ev.attr.SampleFormat.ID, &id.ID)
	f.uint64Cond(ev.attr.SampleFormat.StreamID, &id.StreamID)
	f.uint32Cond(ev.attr.SampleFormat.CPU, &id.CPU, &id.Res)
	f.uint64Cond(ev.attr.SampleFormat.Identifier, &id.Identifier)
}

// count decodes a Count into c.
func (f *fields) count(c *Count, ev *Event) {
	f.uint64(&c.Value)
	if ev.attr.CountFormat.Enabled {
		f.duration(&c.Enabled)
	}
	if ev.attr.CountFormat.Running {
		f.duration(&c.Running)
	}
	f.uint64Cond(ev.attr.CountFormat.ID, &c.ID)
}

// groupCount decodes a GroupCount into gc.
func (f *fields) groupCount(gc *GroupCount, ev *Event) {
	var nr uint64
	f.uint64(&nr)
	if ev.attr.CountFormat.Enabled {
		f.duration(&gc.TimeEnabled)
	}
	if ev.attr.CountFormat.Running {
		f.duration(&gc.TimeRunning)
	}
	gc.Values = make([]struct {
		Value, ID uint64
		Label     string
	}, nr)
	for i := 0; i < int(nr); i++ {
		f.uint64(&gc.Values[i].Value)
		f.uint64Cond(ev.attr.CountFormat.ID, &gc.Values[i].ID)
	}
}

// advance advances through the fields by n bytes.
func (f *fields) advance(n int) {
	*f = (*f)[n:]
}

// marshalBitwiseUint64 marshals a set of bitwise flags into a
// uint64, LSB first.
func marshalBitwiseUint64(fields []bool) uint64 {
	var res uint64
	for shift, set := range fields {
		if set {
			res |= 1 << uint(shift)
		}
	}
	return res
}
