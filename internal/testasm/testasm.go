// Copyright 2019 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package testasm

// SumN computes the sum of integers from 1 to N.
//
// It executes ~4*N + 5 instructions.
func SumN(N uint64) uint64
