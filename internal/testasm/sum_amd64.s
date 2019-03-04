// Copyright 2019 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

TEXT ·Sum(SB), 0, $0-24
	MOVQ a+0(FP), AX
	MOVQ b+8(FP), BX
	ADDQ BX, AX
	MOVQ AX, ret+16(FP)
	RET
