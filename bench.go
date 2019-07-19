//+build go1.13

package perf

import (
	"runtime"
	"testing"
)

// Stopper implements the Stop() method.
type Stopper func()

// Stop calls the given stopper.
func (s Stopper) Stop() { s() }

func Benchmark(b *testing.B) Stopper {
	var g Group
	g.CountFormat = CountFormat{}
	g.Options.ExcludeKernel = true
	g.Options.ExcludeHypervisor = true
	g.Add(Instructions, CPUCycles)

	ev, err := g.Open(CallingThread, AnyCPU)
	if err != nil {
		b.Fatal(err)
	}

	if err := ev.Disable(); err != nil {
		b.Fatal(err)
	}
	if err := ev.Reset(); err != nil {
		b.Fatal(err)
	}
	runtime.LockOSThread()

	if err := ev.Enable(); err != nil {
		runtime.UnlockOSThread()
		b.Fatal(err)
	}

	return Stopper(func() {
		err := ev.Disable()
		runtime.UnlockOSThread()
		if err != nil {
			b.Fatal(err)
		}

		gc, err := ev.ReadGroupCount()
		if err != nil {
			b.Fatal(err)
		}

		b.ReportMetric(float64(gc.Values[0].Value)/float64(gc.Values[1].Value), "instrs/cycle")
		b.ReportMetric(float64(gc.Values[0].Value)/float64(b.N), "instrs/op")
		b.ReportMetric(float64(gc.Values[1].Value)/float64(b.N), "cycles/op")
	})
}

// var (
// 	Result, v, x int
// )
//
// func ExampleBenchmarkMultiply(b *testing.B) {
// 	defer perf.Benchmark(b).Stop()
//
// 	for i := 0; i < b.N; i++ {
// 		v += 10 * x
// 	}
// 	Result = v
// }
//
// BenchmarkMultiply2-16    	1000000000	         1.04 ns/op	         5.20 cycles/op	         1.35 instrs/cycle	         7.00 instrs/op
