// Copyright 2019 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package perf provides access to the Linux perf API. See man 2 perf_event_open.
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

// uint64If decodes the next 64 bit field into v, if cond is true.
func (f *fields) uint64If(cond bool, v *uint64) {
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
func (f *fields) uint32If(cond bool, a, b *uint32) {
	if cond {
		f.uint32(a, b)
	}
}

// duration decodes a duration into d.
func (f *fields) duration(d *time.Duration) {
	*d = *(*time.Duration)(unsafe.Pointer(&(*f)[0]))
	f.advance(8)
}

// durationIf decodes a duration into d, if cond is true.
func (f *fields) durationIf(cond bool, d *time.Duration) {
	if cond {
		f.duration(d)
	}
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
	if !ev.attr.Options.SampleIDAll {
		return
	}
	f.uint32If(ev.attr.SampleFormat.Tid, &id.Pid, &id.Tid)
	f.uint64If(ev.attr.SampleFormat.Time, &id.Time)
	f.uint64If(ev.attr.SampleFormat.ID, &id.ID)
	f.uint64If(ev.attr.SampleFormat.StreamID, &id.StreamID)
	f.uint32If(ev.attr.SampleFormat.CPU, &id.CPU, &id.Res)
	f.uint64If(ev.attr.SampleFormat.Identifier, &id.Identifier)
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
