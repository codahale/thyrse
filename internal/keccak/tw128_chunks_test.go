package keccak

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestEncryptChunksTW128(t *testing.T) {
	const blockSize = 8192

	// Build deterministic State8.
	var s State8
	for lane := range 25 {
		for inst := range 8 {
			s.a[lane][inst] = uint64(lane*8+inst)*0x0123456789ABCDEF + uint64(inst)
		}
	}

	// Build deterministic input.
	src := make([]byte, 8*blockSize)
	for i := range src {
		src[i] = byte(i*7 + i>>8)
	}

	// Run generic path.
	s1 := s
	dst1 := make([]byte, 8*blockSize)
	var cvs1 [256]byte
	encryptChunksTW128Generic(&s1, src, dst1, &cvs1)

	// Run arch-dispatched path.
	s2 := s
	dst2 := make([]byte, 8*blockSize)
	var cvs2 [256]byte
	EncryptChunksTW128(&s2, src, dst2, &cvs2)

	if !bytes.Equal(dst1, dst2) {
		t.Error("ciphertext mismatch between generic and arch paths")
	}
	if cvs1 != cvs2 {
		for inst := range 8 {
			for lane := range 4 {
				w := binary.LittleEndian.Uint64(cvs1[inst*32+lane*8:])
				g := binary.LittleEndian.Uint64(cvs2[inst*32+lane*8:])
				if w != g {
					t.Errorf("encrypt: instance %d, lane %d: got %016x, want %016x", inst, lane, g, w)
				}
			}
		}
	}
}

func TestDecryptChunksTW128(t *testing.T) {
	const blockSize = 8192

	// Build deterministic State8.
	var s State8
	for lane := range 25 {
		for inst := range 8 {
			s.a[lane][inst] = uint64(lane*8+inst)*0xFEDCBA9876543210 + uint64(inst)
		}
	}

	// Build deterministic input (ciphertext).
	src := make([]byte, 8*blockSize)
	for i := range src {
		src[i] = byte(i*13 + i>>8)
	}

	// Run generic path.
	s1 := s
	dst1 := make([]byte, 8*blockSize)
	var cvs1 [256]byte
	decryptChunksTW128Generic(&s1, src, dst1, &cvs1)

	// Run arch-dispatched path.
	s2 := s
	dst2 := make([]byte, 8*blockSize)
	var cvs2 [256]byte
	DecryptChunksTW128(&s2, src, dst2, &cvs2)

	if !bytes.Equal(dst1, dst2) {
		t.Error("plaintext mismatch between generic and arch paths")
	}
	if cvs1 != cvs2 {
		for inst := range 8 {
			for lane := range 4 {
				w := binary.LittleEndian.Uint64(cvs1[inst*32+lane*8:])
				g := binary.LittleEndian.Uint64(cvs2[inst*32+lane*8:])
				if w != g {
					t.Errorf("decrypt: instance %d, lane %d: got %016x, want %016x", inst, lane, g, w)
				}
			}
		}
	}
}

func BenchmarkEncryptChunksTW128(b *testing.B) {
	const blockSize = 8192
	src := make([]byte, 8*blockSize)
	dst := make([]byte, 8*blockSize)
	for i := range src {
		src[i] = byte(i)
	}
	var s State8
	var cvs [256]byte
	b.SetBytes(8 * blockSize)
	for b.Loop() {
		EncryptChunksTW128(&s, src, dst, &cvs)
	}
}

func BenchmarkDecryptChunksTW128(b *testing.B) {
	const blockSize = 8192
	src := make([]byte, 8*blockSize)
	dst := make([]byte, 8*blockSize)
	for i := range src {
		src[i] = byte(i)
	}
	var s State8
	var cvs [256]byte
	b.SetBytes(8 * blockSize)
	for b.Loop() {
		DecryptChunksTW128(&s, src, dst, &cvs)
	}
}
