// Copyright 2019 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package perf

import (
	"errors"
	"fmt"
)

// Group configures a group of events.
type Group struct {
	// CountFormat configures the format of counts read from the event
	// leader. The Group option is set automatically.
	CountFormat CountFormat

	// Options configures options for all events in the group.
	Options Options

	err   error // sticky configuration error
	attrs []*Attr
}

// Add adds events to the group, as configured by cfgs.
//
// For each Configurator, a new *Attr is created, the group-specific settings
// are applied, then Configure is called on the *Attr to produce the final
// event attributes.
func (g *Group) Add(cfgs ...Configurator) {
	for _, cfg := range cfgs {
		g.add(cfg)
	}
}

func (g *Group) add(cfg Configurator) {
	if g.err != nil {
		return
	}
	attr := new(Attr)
	attr.Options = g.Options
	err := cfg.Configure(attr)
	if err != nil {
		g.err = err
		return
	}
	g.attrs = append(g.attrs, attr)
}

// Open opens all the events in the group, and returns their leader.
func (g *Group) Open(pid int, cpu int) (*Event, error) {
	if len(g.attrs) == 0 {
		return nil, errors.New("perf: empty event group")
	}
	if g.err != nil {
		return nil, fmt.Errorf("perf: configuration error: %v", g.err)
	}
	leaderattr := g.attrs[0]
	leaderattr.CountFormat = g.CountFormat
	leaderattr.CountFormat.Group = true
	leader, err := Open(leaderattr, pid, cpu, nil, 0)
	if err != nil {
		return nil, fmt.Errorf("perf: failed to open event leader: %v", err)
	}
	if len(g.attrs) < 2 {
		return leader, nil
	}
	// TODO(acln): figure out how to re-route samples to leader
	for idx, attr := range g.attrs[1:] {
		ev, err := Open(attr, pid, cpu, leader, 0)
		if err != nil {
			leader.Close()
			return nil, fmt.Errorf("perf: failed to open group event #%d (%q): %v", idx, attr.Label, err)
		}
		leader.owned = append(leader.owned, ev)
	}
	return leader, nil
}

// A Configurator configures event attributes. Implementations should only
// set the fields they need. See (*Group).Add for more details.
type Configurator interface {
	Configure(attr *Attr) error
}

type configuratorFunc func(attr *Attr) error

func (cf configuratorFunc) Configure(attr *Attr) error { return cf(attr) }
