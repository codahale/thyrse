package keccak

import (
	"bytes"
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
	s1.EncryptAll(src, dst1, blockSize, 0x0B)

	// Run arch-dispatched path.
	s2 := s
	dst2 := make([]byte, 8*blockSize)
	EncryptChunksTW128(&s2, src, dst2)

	if !bytes.Equal(dst1, dst2) {
		t.Error("ciphertext mismatch between generic and arch paths")
	}
	// Verify state matches (CVs are in lanes 0-3).
	for lane := range 25 {
		for inst := range 8 {
			if s1.a[lane][inst] != s2.a[lane][inst] {
				t.Errorf("encrypt: state mismatch at lane %d, inst %d: got %016x, want %016x",
					lane, inst, s2.a[lane][inst], s1.a[lane][inst])
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
	s1.DecryptAll(src, dst1, blockSize, 0x0B)

	// Run arch-dispatched path.
	s2 := s
	dst2 := make([]byte, 8*blockSize)
	DecryptChunksTW128(&s2, src, dst2)

	if !bytes.Equal(dst1, dst2) {
		t.Error("plaintext mismatch between generic and arch paths")
	}
	for lane := range 25 {
		for inst := range 8 {
			if s1.a[lane][inst] != s2.a[lane][inst] {
				t.Errorf("decrypt: state mismatch at lane %d, inst %d: got %016x, want %016x",
					lane, inst, s2.a[lane][inst], s1.a[lane][inst])
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
	b.SetBytes(8 * blockSize)
	for b.Loop() {
		EncryptChunksTW128(&s, src, dst)
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
	b.SetBytes(8 * blockSize)
	for b.Loop() {
		DecryptChunksTW128(&s, src, dst)
	}
}
