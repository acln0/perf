// Copyright 2019 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package perf

// A Group is a group of perf counters.
type Group struct {
	// ...
}

func (g *Group) Open(pid int, cpu int, flags Flag) (*Event, error) {
	panic("not implemented")
}

// Add adds counters to the group.
func (g *Group) Add(counters ...TODOInterfaceName) {
}

type TODOInterfaceName interface {
	MarshalAttr() Attr
}
