// Copyright 2019 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package perf_test

import (
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"strconv"
	"strings"
	"sync"
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

// perfTestEnv holds and caches information about the testing environment
// for package perf.
type perfTestEnv struct {
	paranoid struct {
		sync.Once
		value int
	}

	debugfs struct {
		sync.Once
		mounted  bool
		readable bool
		readErr  error
	}

	pmu struct {
		sync.Mutex
		ok      map[string]struct{}
		missing map[string]error
	}
}

func (env *perfTestEnv) paranoidLevel() int {
	env.paranoid.Once.Do(env.initParanoid)
	return env.paranoid.value
}

func (env *perfTestEnv) initParanoid() {
	content, err := ioutil.ReadFile("/proc/sys/kernel/perf_event_paranoid")
	if err != nil {
		env.paranoid.value = 3
		return
	}
	nr := strings.TrimSpace(string(content))
	paranoid, err := strconv.ParseInt(nr, 10, 32)
	if err != nil {
		env.paranoid.value = 3
		return
	}
	env.paranoid.value = int(paranoid)
}

func (env *perfTestEnv) initDebugfs() {
	_, err := os.Stat("/sys/kernel/debug")
	if err != nil {
		return
	}
	env.debugfs.mounted = true
	_, err = ioutil.ReadDir("/sys/kernel/debug")
	if err != nil {
		env.debugfs.readErr = err
		return
	}
	env.debugfs.readable = true
}

func (env *perfTestEnv) debugfsMounted() bool {
	env.debugfs.Once.Do(env.initDebugfs)
	return env.debugfs.mounted
}

func (env *perfTestEnv) debugfsReadable() (bool, error) {
	env.debugfs.Once.Do(env.initDebugfs)
	return env.debugfs.readable, env.debugfs.readErr
}

func (env *perfTestEnv) havePMU(u string) (bool, error) {
	env.pmu.Lock()
	defer env.pmu.Unlock()

	if env.pmu.ok == nil {
		env.pmu.ok = map[string]struct{}{}
	}
	if env.pmu.missing == nil {
		env.pmu.missing = map[string]error{}
	}

	if _, ok := env.pmu.ok[u]; ok {
		return true, nil
	}
	if err, ok := env.pmu.missing[u]; ok {
		return false, err
	}

	_, err := perf.LookupEventType(u)
	if err != nil {
		env.pmu.missing[u] = err
		return false, err
	}

	env.pmu.ok[u] = struct{}{}
	return true, nil
}

var testenv perfTestEnv

// paranoid specifies a perf_event_paranoid level requirement for a test.
//
// For example, a value of 1 for paranoid means that the test requires a
// perf_event_paranoid level of 1 or less.
type paranoid int

func (p paranoid) Evaluate() error {
	want, have := int(p), testenv.paranoidLevel()
	if have > want {
		return fmt.Errorf("want perf_event_paranoid <= %d, have %d", want, have)
	}
	return nil
}

// debugfsreq specifies a debugfs requirement for a test: debugfs must be
// mounted at /sys/kernel/debug, and it must be readable.
type debugfsreq struct{}

func (debugfsreq) Evaluate() error {
	if !testenv.debugfsMounted() {
		return errors.New("debugfs is not mounted at /sys/kernel/debug")
	}
	if ok, err := testenv.debugfsReadable(); !ok {
		return fmt.Errorf("debugfs is not readable: %v", err)
	}
	return nil
}

var debugfs = debugfsreq{}

// pmu specifies a PMU requirement for a test.
type pmu string

var (
	hardwarePMU   = pmu("hardware")
	softwarePMU   = pmu("software")
	tracepointPMU = pmu("tracepoint")
)

func (u pmu) Evaluate() error {
	device := string(u)
	if device == "hardware" {
		device = "cpu" // TODO(acln): investigate
	}
	if ok, err := testenv.havePMU(device); !ok {
		return fmt.Errorf("%s PMU not supported: %v", device, err)
	}
	return nil
}

type testRequirement interface {
	Evaluate() error
}

func requires(t *testing.T, reqs ...testRequirement) {
	t.Helper()

	sb := new(strings.Builder)
	unmet := 0

	for _, req := range reqs {
		if err := req.Evaluate(); err != nil {
			if unmet > 0 {
				sb.WriteString("; ")
			}
			fmt.Fprint(sb, err)
			unmet++
		}
	}

	switch unmet {
	case 0:
		return
	case 1:
		t.Skipf("unmet requirement: %s", sb.String())
	default:
		t.Skipf("unmet requirements: %s", sb.String())
	}
}
