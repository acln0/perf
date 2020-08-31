//+build !go1.13

package perf

import "testing"

// Stopper implements the Stop() method.
type Stopper func()

// Stop calls the given stopper.
func (s Stopper) Stop() { s() }

// Benchmark ...
func Benchmark(b *testing.B) Stopper {
	b.Skipf("b.ReportMetric is only available in go1.13 and later")
	return nil
}
