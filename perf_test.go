// Copyright 2019 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package perf_test

import (
	"fmt"
	"os"
	"testing"

	"acln.ro/perf"
)

func TestMain(m *testing.M) {
	if !perf.Supported() {
		fmt.Fprintln(os.Stderr, "perf_event_open not supported")
		os.Exit(2)
	}
	os.Exit(m.Run())
}

// paranoid specifies a perf_event_paranoid level requirement for a test.
//
// For example, a value of 1 for paranoid means that the test requires a
// perf_event_paranoid level of 1 or less.
type paranoid int

func (p paranoid) String() string {
	return fmt.Sprintf("perf_event_paranoid <= %d", int(p))
}

func (p paranoid) Met() bool {
	// TODO(acln): implement
	return true
}

// debugfsreq specifies a debugfs requirement for a test: debugfs must be
// mounted at /sys/kernel/debug, and it must be readable.
type debugfsreq struct{}

func (debugfsreq) String() string {
	return fmt.Sprintf("permission to read /sys/kernel/debug")
}

func (debugfsreq) Met() bool {
	// TODO(acln): implement
	return true
}

var debugfs = debugfsreq{}

// pmu specifies a PMU requirement for a test.
type pmu string

var (
	hardwarePMU   = pmu("hardware")
	softwarePMU   = pmu("software")
	tracepointPMU = pmu("tracepoint")
)

func (u pmu) String() string {
	return fmt.Sprintf("%s PMU", string(u))
}

func (u pmu) Met() bool {
	// TODO(acln): implement, see /sys/bus/event_source/devices
	return true
}

type testRequirement interface {
	String() string
	Met() bool
}

func requires(t *testing.T, reqs ...testRequirement) {
	t.Helper()

	for _, req := range reqs {
		if !req.Met() {
			t.Skipf("unmet requirement: %v", req)
		}
	}
}
