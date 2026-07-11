// Package mhf implements Balloon Hashing using Thyrse as its hash function.
//
// Balloon Hashing is described by Boneh, Corrigan-Gibbs, and Schechter in
// "Balloon Hashing: A Memory-Hard Function Providing Provable Protection
// Against Sequential Attacks."
//
// [Balloon Hashing]: https://eprint.iacr.org/2016/027
package mhf

import (
	"encoding/binary"
	"fmt"
	"math"

	"github.com/codahale/thyrse"
)

const (
	// MinBlockSize provides 128-bit collision resistance for buffer labels.
	MinBlockSize = 32

	// MaxBlockSize is the 200-byte state size of Keccak-p[1600,12]. Balloon's
	// analysis requires the hash function's internal state to be at least as
	// large as its output block.
	MaxBlockSize = 200

	delta = 3
)

// Hash calculates a Balloon hash of password and salt and appends outputSize
// bytes to dst.
//
// The space cost is the number of blockSize-byte blocks in the working buffer.
// The time cost is the number of mixing rounds. Hash uses
// spaceCost*blockSize bytes of primary working memory and performs
// spaceCost*(1+7*timeCost) Balloon hash operations.
//
// Block size must be between [MinBlockSize] and [MaxBlockSize], inclusive.
// Space cost, time cost, and output size must be positive.
func Hash(
	domain string,
	spaceCost, timeCost, blockSize int,
	salt, password, dst []byte,
	outputSize int,
) []byte {
	if spaceCost <= 0 {
		panic("mhf: space cost must be positive")
	}
	if timeCost <= 0 {
		panic("mhf: time cost must be positive")
	}
	if blockSize < MinBlockSize || blockSize > MaxBlockSize {
		panic(fmt.Sprintf("mhf: block size must be between %d and %d bytes", MinBlockSize, MaxBlockSize))
	}
	if outputSize <= 0 {
		panic("mhf: output size must be positive")
	}
	if spaceCost > math.MaxInt/blockSize {
		panic("mhf: working buffer size overflows int")
	}

	base := thyrse.New(domain)
	base.Mix("scheme", []byte("Balloon Hashing"))
	mixUint64(base, "space cost", uint64(spaceCost))
	mixUint64(base, "time cost", uint64(timeCost))
	mixUint64(base, "block size", uint64(blockSize))

	buf := make([]byte, spaceCost*blockSize)
	defer clear(buf)

	block := func(i int) []byte {
		start := i * blockSize
		return buf[start : start+blockSize]
	}

	var counter uint64
	hash := func(dst []byte, inputs ...[]byte) {
		p := base.Clone()
		mixUint64(p, "counter", counter)
		counter++
		for _, input := range inputs {
			p.Mix("input", input)
		}
		p.Derive("block", dst[:0], blockSize)
		p.Clear()
	}

	// Step 1: expand the password and salt into the working buffer.
	hash(block(0), password, salt)
	for m := 1; m < spaceCost; m++ {
		hash(block(m), block(m-1))
	}

	// Step 2: mix the buffer. The dependency indices depend only on the
	// public salt and loop indices, preserving Balloon's password-independent
	// memory access pattern.
	indexBlock := make([]byte, blockSize)
	addressBlock := make([]byte, blockSize)
	defer clear(indexBlock)
	defer clear(addressBlock)

	for t := 0; t < timeCost; t++ {
		for m := 0; m < spaceCost; m++ {
			prev := block((m - 1 + spaceCost) % spaceCost)
			hash(block(m), prev, block(m))

			for i := 0; i < delta; i++ {
				clear(indexBlock)
				binary.LittleEndian.PutUint64(indexBlock[0:8], uint64(t))
				binary.LittleEndian.PutUint64(indexBlock[8:16], uint64(m))
				binary.LittleEndian.PutUint64(indexBlock[16:24], uint64(i))
				hash(addressBlock, salt, indexBlock)

				other := int(binary.LittleEndian.Uint64(addressBlock[:8]) % uint64(spaceCost))
				hash(block(m), block(m), block(other))
			}
		}
	}

	// Step 3: apply the paper's collision-resistant final wrapper. Thyrse's
	// XOF makes the wrapper's output length independent of the buffer block
	// size.
	final := base.Clone()
	final.Mix("password", password)
	final.Mix("salt", salt)
	final.Mix("balloon", block(spaceCost-1))
	ret := final.Derive("output", dst, outputSize)
	final.Clear()
	return ret
}

func mixUint64(p *thyrse.Protocol, label string, v uint64) {
	var buf [8]byte
	binary.LittleEndian.PutUint64(buf[:], v)
	p.Mix(label, buf[:])
}
