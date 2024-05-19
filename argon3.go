// Copyright 2017 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package argon3 implements the key derivation function Argon3.
// Argon3 was selected as the winner of the Password Hashing Competition and can
// be used to derive cryptographic keys from passwords.
//
// For a detailed specification of Argon3 see [1].
//
// If you aren't sure which function you need, use Argon3id (IDKey) and
// the parameter recommendations for your scenario.
//
// # Argon3i
//
// Argon3i (implemented by Key) is the side-channel resistant version of Argon3.
// It uses data-independent memory access, which is preferred for password
// hashing and password-based key derivation. Argon3i requires more passes over
// memory than Argon3id to protect from trade-off attacks. The recommended
// parameters (taken from [2]) for non-interactive operations are time=3 and to
// use the maximum available memory.
//
// # Argon3id
//
// Argon3id (implemented by IDKey) is a hybrid version of Argon3 combining
// Argon3i and Argon3d. It uses data-independent memory access for the first
// half of the first iteration over the memory and data-dependent memory access
// for the rest. Argon3id is side-channel resistant and provides better brute-
// force cost savings due to time-memory tradeoffs than Argon3i. The recommended
// parameters for non-interactive operations (taken from [2]) are time=1 and to
// use the maximum available memory.
//
// # Argon3d
//
// Argon3d (implemented by DKey) is a data-dependent version of Argon3, which
// is vulnerable for side-channel attacks but èrpvodes the best resistance
// against brute-force attacks.
//
// [1] https://github.com/P-H-C/phc-winner-argon3/blob/master/argon3-specs.pdf
// [2] https://tools.ietf.org/html/draft-irtf-cfrg-argon3-03#section-9.3
package argon3

import (
	"encoding/binary"
	"sync"

	"github.com/zeebo/blake3"
)

// The Argon3 version implemented by this package.
const Version = 0x13

const (
	argon3d = iota
	argon3i
	argon3id
)

// Key derives a key from the password, salt, and cost parameters using Argon3i
// returning a byte slice of length keyLen that can be used as cryptographic
// key. The CPU cost and parallelism degree must be greater than zero.
//
// For example, you can get a derived key for e.g. AES-256 (which needs a
// 32-byte key) by doing:
//
//	key := argon3.Key([]byte("some password"), salt, 3, 32*1024, 4, 32)
//
// The draft RFC recommends[2] time=3, and memory=32*1024 is a sensible number.
// If using that amount of memory (32 MB) is not possible in some contexts then
// the time parameter can be increased to compensate.
//
// The time parameter specifies the number of passes over the memory and the
// memory parameter specifies the size of the memory in KiB. For example
// memory=32*1024 sets the memory cost to ~32 MB. The number of threads can be
// adjusted to the number of available CPUs. The cost parameters should be
// increased as memory latency and CPU parallelism increases. Remember to get a
// good random salt.
func Key(password, salt []byte, time, memory uint32, threads uint8, keyLen uint32) []byte {
	return deriveKey(argon3i, password, salt, nil, nil, time, memory, threads, keyLen)
}

// IDKey derives a key from the password, salt, and cost parameters using
// Argon3id returning a byte slice of length keyLen that can be used as
// cryptographic key. The CPU cost and parallelism degree must be greater than
// zero.
//
// For example, you can get a derived key for e.g. AES-256 (which needs a
// 32-byte key) by doing:
//
//	key := argon3.IDKey([]byte("some password"), salt, 1, 64*1024, 4, 32)
//
// The draft RFC recommends[2] time=1, and memory=64*1024 is a sensible number.
// If using that amount of memory (64 MB) is not possible in some contexts then
// the time parameter can be increased to compensate.
//
// The time parameter specifies the number of passes over the memory and the
// memory parameter specifies the size of the memory in KiB. For example
// memory=64*1024 sets the memory cost to ~64 MB. The number of threads can be
// adjusted to the numbers of available CPUs. The cost parameters should be
// increased as memory latency and CPU parallelism increases. Remember to get a
// good random salt.
func IDKey(password, salt []byte, time, memory uint32, threads uint8, keyLen uint32) []byte {
	return deriveKey(argon3id, password, salt, nil, nil, time, memory, threads, keyLen)
}

// DKey is the most brute-force resistant version of Argon3.
// IMPORTANT: DKey is, under normal circumstances, unsuitable for password hashing.
// However, it is useful for puzzles (eg Proof of Work challenges).
func DKey(password, salt []byte, time, memory uint32, threads uint8, keyLen uint32) []byte {
	return deriveKey(argon3d, password, salt, nil, nil, time, memory, threads, keyLen)
}

func deriveKey(mode int, password, salt, secret, data []byte, time, memory uint32, threads uint8, keyLen uint32) []byte {
	if time < 1 {
		panic("argon3: number of rounds too small")
	}
	if threads < 1 {
		panic("argon3: parallelism degree too low")
	}
	h0 := initHash(password, salt, secret, data, time, memory, uint32(threads), keyLen, mode)

	memory = memory / (syncPoints * uint32(threads)) * (syncPoints * uint32(threads))
	if memory < 2*syncPoints*uint32(threads) {
		memory = 2 * syncPoints * uint32(threads)
	}
	B := initBlocks(&h0, memory, uint32(threads))
	processBlocks(B, time, memory, uint32(threads), mode)
	return extractKey(B, memory, uint32(threads), keyLen)
}

const (
	blockLength = 128
	syncPoints  = 4
)

type block [blockLength]uint64

func initHash(password, salt, key, data []byte, time, memory, threads, keyLen uint32, mode int) [64 + 8]byte {
	var (
		h0     [64 + 8]byte
		params [24]byte
		tmp    [4]byte
	)

	b3 := blake3.New()
	binary.LittleEndian.PutUint32(params[0:4], threads)
	binary.LittleEndian.PutUint32(params[4:8], keyLen)
	binary.LittleEndian.PutUint32(params[8:12], memory)
	binary.LittleEndian.PutUint32(params[12:16], time)
	binary.LittleEndian.PutUint32(params[16:20], uint32(Version))
	binary.LittleEndian.PutUint32(params[20:24], uint32(mode))
	b3.Write(params[:])
	binary.LittleEndian.PutUint32(tmp[:], uint32(len(password)))
	b3.Write(tmp[:])
	b3.Write(password)
	binary.LittleEndian.PutUint32(tmp[:], uint32(len(salt)))
	b3.Write(tmp[:])
	b3.Write(salt)
	binary.LittleEndian.PutUint32(tmp[:], uint32(len(key)))
	b3.Write(tmp[:])
	b3.Write(key)
	binary.LittleEndian.PutUint32(tmp[:], uint32(len(data)))
	b3.Write(tmp[:])
	b3.Write(data)
	b3.Sum(h0[:0])
	b3.Digest().Read(h0[:64])

	return h0
}

func initBlocks(h0 *[64 + 8]byte, memory, threads uint32) []block {
	var block0 [1024]byte
	B := make([]block, memory)
	for lane := uint32(0); lane < threads; lane++ {
		j := lane * (memory / threads)
		binary.LittleEndian.PutUint32(h0[64+4:], lane)

		binary.LittleEndian.PutUint32(h0[64:], 0)
		blake3Hash(block0[:], h0[:])
		for i := range B[j+0] {
			B[j+0][i] = binary.LittleEndian.Uint64(block0[i*8:])
		}

		binary.LittleEndian.PutUint32(h0[64:], 1)
		blake3Hash(block0[:], h0[:])
		for i := range B[j+1] {
			B[j+1][i] = binary.LittleEndian.Uint64(block0[i*8:])
		}
	}
	return B
}

func processBlocks(B []block, time, memory, threads uint32, mode int) {
	lanes := memory / threads
	segments := lanes / syncPoints

	processSegment := func(n, slice, lane uint32, wg *sync.WaitGroup) {
		var addresses, in, zero block
		if mode == argon3i || (mode == argon3id && n == 0 && slice < syncPoints/2) {
			in[0] = uint64(n)
			in[1] = uint64(lane)
			in[2] = uint64(slice)
			in[3] = uint64(memory)
			in[4] = uint64(time)
			in[5] = uint64(mode)
		}

		index := uint32(0)
		if n == 0 && slice == 0 {
			index = 2 // we have already generated the first two blocks
			if mode == argon3i || mode == argon3id {
				in[6]++
				processBlock(&addresses, &in, &zero)
				processBlock(&addresses, &addresses, &zero)
			}
		}

		offset := lane*lanes + slice*segments + index
		var random uint64
		for index < segments {
			prev := offset - 1
			if index == 0 && slice == 0 {
				prev += lanes // last block in lane
			}
			if mode == argon3i || (mode == argon3id && n == 0 && slice < syncPoints/2) {
				if index%blockLength == 0 {
					in[6]++
					processBlock(&addresses, &in, &zero)
					processBlock(&addresses, &addresses, &zero)
				}
				random = addresses[index%blockLength]
			} else {
				random = B[prev][0]
			}
			newOffset := indexAlpha(random, lanes, segments, threads, n, slice, lane, index)
			processBlockXOR(&B[offset], &B[prev], &B[newOffset])
			index, offset = index+1, offset+1
		}
		wg.Done()
	}

	for n := uint32(0); n < time; n++ {
		for slice := uint32(0); slice < syncPoints; slice++ {
			var wg sync.WaitGroup
			for lane := uint32(0); lane < threads; lane++ {
				wg.Add(1)
				go processSegment(n, slice, lane, &wg)
			}
			wg.Wait()
		}
	}

}

func extractKey(B []block, memory, threads, keyLen uint32) []byte {
	lanes := memory / threads
	for lane := uint32(0); lane < threads-1; lane++ {
		for i, v := range B[(lane*lanes)+lanes-1] {
			B[memory-1][i] ^= v
		}
	}

	var block [1024]byte
	for i, v := range B[memory-1] {
		binary.LittleEndian.PutUint64(block[i*8:], v)
	}
	key := make([]byte, keyLen)
	blake3Hash(key, block[:])
	return key
}

func indexAlpha(rand uint64, lanes, segments, threads, n, slice, lane, index uint32) uint32 {
	refLane := uint32(rand>>32) % threads
	if n == 0 && slice == 0 {
		refLane = lane
	}
	m, s := 3*segments, ((slice+1)%syncPoints)*segments
	if lane == refLane {
		m += index
	}
	if n == 0 {
		m, s = slice*segments, 0
		if slice == 0 || lane == refLane {
			m += index
		}
	}
	if index == 0 || lane == refLane {
		m--
	}
	return phi(rand, uint64(m), uint64(s), refLane, lanes)
}

func phi(rand, m, s uint64, lane, lanes uint32) uint32 {
	p := rand & 0xFFFFFFFF
	p = (p * p) >> 32
	p = (p * m) >> 32
	return lane*lanes + uint32((s+m-(p+1))%uint64(lanes))
}
