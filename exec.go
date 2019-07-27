// Copyright 2019 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package perf

import (
	"fmt"
	"os/exec"
	"syscall"
)

// command implements shared functionality between Command() and
// (*Group).Command().
func command(cmd *exec.Cmd, setupCounters func() error) error {
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.Ptrace = true

	err := cmd.Start()
	if err != nil {
		return err
	}

	state, err := cmd.Process.Wait()
	if err != nil {
		// For good measure to avoid leaking a process.
		_ = cmd.Process.Kill()
		return err
	}
	if state.Sys().(syscall.WaitStatus).TrapCause() == -1 {
		// For good measure to avoid leaking a process.
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		return fmt.Errorf("tracee did not trap as expected")
	}

	// Note unusual error flow - if this fails, we still need to detach from
	// the process and wait on it.
	errCounters := setupCounters()

	err = syscall.PtraceDetach(cmd.Process.Pid)
	if err != nil {
		// For good measure to avoid leaking a process.
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		return err
	}

	err = cmd.Wait()
	// Note unusual error flow - it's necessary need to detach and wait to
	// avoid leaking a process, but if there was an error setting up the
	// counters, this is what the caller needs to know about.
	if errCounters != nil {
		return errCounters
	}
	return err
}

// Command invokes the given exec.Cmd and measures the given counter,
// analogously to Measure().
func Command(a *Attr, cmd *exec.Cmd, cpu int, event *Event) (Count, error) {
	var event2 *Event
	err := command(cmd, func() (err2 error) {
		event2, err2 = Open(a, cmd.Process.Pid, cpu, event)
		if err2 != nil {
			return err2
		}

		return event2.Enable()
	})
	if err != nil {
		return Count{}, err
	}
	defer event2.Close()

	return event2.ReadCount()
}

// Command invokes the given exec.Cmd and measures the given counter,
// analogously to MeasureGroup().
func (g *Group) Command(cmd *exec.Cmd, cpu int) (GroupCount, error) {
	var event2 *Event
	err := command(cmd, func() (err2 error) {
		event2, err2 = g.Open(cmd.Process.Pid, cpu)
		if err2 != nil {
			return err2
		}

		return event2.Enable()
	})
	if err != nil {
		return GroupCount{}, err
	}
	defer event2.Close()

	return event2.ReadGroupCount()
}
