// Copyright 2017 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package argon3

import (
	"github.com/zeebo/blake3"
)

// blake3Hash computes an arbitrary long hash value of in
// and writes the hash to out.
func blake3Hash(out []byte, in []byte) {
	hasher := blake3.New()

	hasher.Write(in)
	hasher.Digest().Read(out)
}
