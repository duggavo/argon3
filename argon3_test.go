// Copyright 2017 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package argon3

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestVectors(t *testing.T) {
	password, salt := []byte("password"), []byte("somesalt")
	for i, v := range testVectors {
		want, err := hex.DecodeString(v.hash)
		if err != nil {
			t.Fatalf("Test %d: failed to decode hash: %v", i, err)
		}
		hash := deriveKey(v.mode, password, salt, nil, nil, v.time, v.memory, v.threads, uint32(len(want)))
		if !bytes.Equal(hash, want) {
			t.Errorf("Test %d - got: %s want: %s", i, hex.EncodeToString(hash), hex.EncodeToString(want))
		}
	}
}

func benchmarkArgon3(mode int, time, memory uint32, threads uint8, keyLen uint32, b *testing.B) {
	password := []byte("password")
	salt := []byte("choosing random salts is hard")
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		deriveKey(mode, password, salt, nil, nil, time, memory, threads, keyLen)
	}
}

func BenchmarkArgon3i(b *testing.B) {
	b.Run(" Time: 3 Memory: 32 MB, Threads: 1", func(b *testing.B) { benchmarkArgon3(argon3i, 3, 32*1024, 1, 32, b) })
	b.Run(" Time: 4 Memory: 32 MB, Threads: 1", func(b *testing.B) { benchmarkArgon3(argon3i, 4, 32*1024, 1, 32, b) })
	b.Run(" Time: 5 Memory: 32 MB, Threads: 1", func(b *testing.B) { benchmarkArgon3(argon3i, 5, 32*1024, 1, 32, b) })
	b.Run(" Time: 3 Memory: 64 MB, Threads: 4", func(b *testing.B) { benchmarkArgon3(argon3i, 3, 64*1024, 4, 32, b) })
	b.Run(" Time: 4 Memory: 64 MB, Threads: 4", func(b *testing.B) { benchmarkArgon3(argon3i, 4, 64*1024, 4, 32, b) })
	b.Run(" Time: 5 Memory: 64 MB, Threads: 4", func(b *testing.B) { benchmarkArgon3(argon3i, 5, 64*1024, 4, 32, b) })
}

func BenchmarkArgon3d(b *testing.B) {
	b.Run(" Time: 3, Memory: 32 MB, Threads: 1", func(b *testing.B) { benchmarkArgon3(argon3d, 3, 32*1024, 1, 32, b) })
	b.Run(" Time: 4, Memory: 32 MB, Threads: 1", func(b *testing.B) { benchmarkArgon3(argon3d, 4, 32*1024, 1, 32, b) })
	b.Run(" Time: 5, Memory: 32 MB, Threads: 1", func(b *testing.B) { benchmarkArgon3(argon3d, 5, 32*1024, 1, 32, b) })
	b.Run(" Time: 3, Memory: 64 MB, Threads: 4", func(b *testing.B) { benchmarkArgon3(argon3d, 3, 64*1024, 4, 32, b) })
	b.Run(" Time: 4, Memory: 64 MB, Threads: 4", func(b *testing.B) { benchmarkArgon3(argon3d, 4, 64*1024, 4, 32, b) })
	b.Run(" Time: 5, Memory: 64 MB, Threads: 4", func(b *testing.B) { benchmarkArgon3(argon3d, 5, 64*1024, 4, 32, b) })
}

func BenchmarkArgon3id(b *testing.B) {
	b.Run(" Time: 3, Memory: 32 MB, Threads: 1", func(b *testing.B) { benchmarkArgon3(argon3id, 3, 32*1024, 1, 32, b) })
	b.Run(" Time: 4, Memory: 32 MB, Threads: 1", func(b *testing.B) { benchmarkArgon3(argon3id, 4, 32*1024, 1, 32, b) })
	b.Run(" Time: 5, Memory: 32 MB, Threads: 1", func(b *testing.B) { benchmarkArgon3(argon3id, 5, 32*1024, 1, 32, b) })
	b.Run(" Time: 3, Memory: 64 MB, Threads: 4", func(b *testing.B) { benchmarkArgon3(argon3id, 3, 64*1024, 4, 32, b) })
	b.Run(" Time: 4, Memory: 64 MB, Threads: 4", func(b *testing.B) { benchmarkArgon3(argon3id, 4, 64*1024, 4, 32, b) })
	b.Run(" Time: 5, Memory: 64 MB, Threads: 4", func(b *testing.B) { benchmarkArgon3(argon3id, 5, 64*1024, 4, 32, b) })
}

// Generated with the CLI of https://github.com/P-H-C/phc-winner-argon3/blob/master/argon3-specs.pdf
var testVectors = []struct {
	mode         int
	time, memory uint32
	threads      uint8
	hash         string
}{
	{
		mode: argon3i, time: 1, memory: 64, threads: 1,
		hash: "d62a8f099abcab56a9f5ad1804a08c5c35e68f0b788d415b",
	},
	{
		mode: argon3d, time: 1, memory: 64, threads: 1,
		hash: "49f8ee86bee2847caaa461d8cf42a025ce729ccf26003ff8",
	},
	{
		mode: argon3id, time: 1, memory: 64, threads: 1,
		hash: "64f317ddb9b2088464ff44807e985bcff7f9c632bbd68a00",
	},
	{
		mode: argon3i, time: 2, memory: 64, threads: 1,
		hash: "88b854697f15103f54bd8ff171e35127ca41e77140f8e4e2",
	},
	{
		mode: argon3d, time: 2, memory: 64, threads: 1,
		hash: "c596d9977bed9ad4c81a30a5b563dd3199290e7861f5fe4e",
	},
	{
		mode: argon3id, time: 2, memory: 64, threads: 1,
		hash: "798ead1f096228b7442400573ab99ef0dada28f011fa6a83",
	},
	{
		mode: argon3i, time: 2, memory: 64, threads: 2,
		hash: "bdaab548f68896f3c0ee4cbafedaec409350af78bba9643a",
	},
	{
		mode: argon3d, time: 2, memory: 64, threads: 2,
		hash: "c57ffcf5337ee722c1e81c0c01eae209dfda8c1f731af112",
	},
	{
		mode: argon3id, time: 2, memory: 64, threads: 2,
		hash: "ae3efb61ec1a6c8af16c9391460979d5fb91d5b24f89aaf1",
	},
	{
		mode: argon3i, time: 3, memory: 256, threads: 2,
		hash: "8a12fb922161a17a4954c79ee11dfa33af68f43620ed5ee5",
	},
	{
		mode: argon3d, time: 3, memory: 256, threads: 2,
		hash: "1c6117569408485a39bcb6977a54151f63199996767f6aa9",
	},
	{
		mode: argon3id, time: 3, memory: 256, threads: 2,
		hash: "bd36705d2e36fab68ee8434a1a442d0238400ca6ce1ec43a",
	},
	{
		mode: argon3i, time: 4, memory: 4096, threads: 4,
		hash: "8d457062a064cba38d2ea8e9dcf715b845537911cf063ac9",
	},
	{
		mode: argon3d, time: 4, memory: 4096, threads: 4,
		hash: "657de56136b6cbb3f96fe5e3b8bfde475c24a5c8631af3d1",
	},
	{
		mode: argon3id, time: 4, memory: 4096, threads: 4,
		hash: "c349dedd145b6daf361dccd3ec5e476b6ba16fa5cf8ad6a8",
	},
	{
		mode: argon3i, time: 4, memory: 1024, threads: 8,
		hash: "aed1020b8fd679fcc23a9acb2034565888d4bb7fa949aed6",
	},
	{
		mode: argon3d, time: 4, memory: 1024, threads: 8,
		hash: "4a157d93294414c9db9366a49fb515d92355f17bb9cf72ba",
	},
	{
		mode: argon3id, time: 4, memory: 1024, threads: 8,
		hash: "8778b8c60fd8511819ebf77b180aa5deac25ea2ad810aada",
	},
	{
		mode: argon3i, time: 2, memory: 64, threads: 3,
		hash: "c7c9891167b3385c381a0df1fa674628c16607f003467a9f",
	},
	{
		mode: argon3d, time: 2, memory: 64, threads: 3,
		hash: "9a01a35a535be078b9d9cec88dc801d06c964614174b683d",
	},
	{
		mode: argon3id, time: 2, memory: 64, threads: 3,
		hash: "9ff6446e215a22fa470141c4c38bfff9fdfc453a4167f5ec",
	},
	{
		mode: argon3i, time: 3, memory: 1024, threads: 6,
		hash: "ea2e8efb1dad7db8cce7f8d4d371e22eeb0e71d42cadb51c",
	},
	{
		mode: argon3d, time: 3, memory: 1024, threads: 6,
		hash: "5a22630a39a28d36989be7339f3b5271d2c7c968b8ea68c9",
	},
	{
		mode: argon3id, time: 3, memory: 1024, threads: 6,
		hash: "d10a036d0efc67338ae0124febf2468803c699fd9622124a",
	},
}
