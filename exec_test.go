package perf_test

import (
	"os/exec"
	"testing"

	"acln.ro/perf"
)

func TestCommand(t *testing.T) {
	cmd := exec.Command("echo", "hello world")

	fa := &perf.Attr{
		CountFormat: perf.CountFormat{
			Running: true,
			ID:      true,
		},
	}
	perf.Instructions.Configure(fa)
	fa.Options.ExcludeKernel = true
	fa.Options.ExcludeHypervisor = true

	count, err := perf.Command(fa, cmd, perf.AnyCPU, nil)
	if err != nil {
		t.Fatal(err)
	}

	t.Logf("count = %v", count.Value)

	// A primitive test to ensure the counter measured something, since we
	// don't know the "correct" value.
	if count.Value < 1000 {
		t.Fatal("counter read less than 1000 - should be > 1M")
	}
}

func TestCommandGroup(t *testing.T) {
	cmd := exec.Command("echo", "hello world")

	var g perf.Group
	g.CountFormat = perf.CountFormat{
		Running: true,
		ID:      true,
	}
	g.Options.ExcludeKernel = true
	g.Options.ExcludeHypervisor = true
	g.Add(perf.Instructions, perf.CPUCycles)

	counts, err := g.Command(cmd, perf.AnyCPU)
	if err != nil {
		t.Fatal(err)
	}

	t.Log("counts:", counts)

	// A primitive test to ensure the counter measured something, since we
	// don't know the "correct" value.
	if counts.Values[0].Value < 1000 || counts.Values[1].Value < 1000 {
		t.Fatal("counter read less than 1000 - should be > 1M")
	}
}
