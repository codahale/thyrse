package keccak

import "encoding/binary"

// EncryptChunksTW128 encrypts 8 × 8192-byte chunks from src into dst,
// initializing 8 parallel tree nodes from base at consecutive indices
// starting at baseIndex, and writing the 8×32-byte chain values to cvs.
// Src and dst must each be exactly 8×8192 = 65536 bytes.
func EncryptChunksTW128(base *State1, baseIndex uint64, src, dst []byte, cvs *[256]byte) {
	var s state8
	initChunksTW128(&s, base, baseIndex)
	if encryptChunksTW128Arch(&s, src, dst, cvs) {
		return
	}
	encryptChunksTW128Generic(&s, src, dst, cvs)
}

// DecryptChunksTW128 decrypts 8 × 8192-byte chunks from src into dst,
// initializing 8 parallel tree nodes from base at consecutive indices
// starting at baseIndex, and writing the 8×32-byte chain values to cvs.
// Src and dst must each be exactly 8×8192 = 65536 bytes.
func DecryptChunksTW128(base *State1, baseIndex uint64, src, dst []byte, cvs *[256]byte) {
	var s state8
	initChunksTW128(&s, base, baseIndex)
	if decryptChunksTW128Arch(&s, src, dst, cvs) {
		return
	}
	decryptChunksTW128Generic(&s, src, dst, cvs)
}

// initChunksTW128 broadcasts base into all 8 lanes, XORs consecutive
// indices starting at baseIndex, and pad-permutes with initDS=0x08.
func initChunksTW128(s *state8, base *State1, baseIndex uint64) {
	s.setAll(base)
	s.absorbWords([8]uint64{
		baseIndex, baseIndex + 1, baseIndex + 2, baseIndex + 3,
		baseIndex + 4, baseIndex + 5, baseIndex + 6, baseIndex + 7,
	})
	s.padPermute(0x08)
}

func encryptChunksTW128Generic(s *state8, src, dst []byte, cvs *[256]byte) {
	const blockSize = 8192
	s.encryptAll(src, dst, blockSize, 0x0B)
	for inst := range 8 {
		binary.LittleEndian.PutUint64(cvs[inst*32:], s.a[0][inst])
		binary.LittleEndian.PutUint64(cvs[inst*32+8:], s.a[1][inst])
		binary.LittleEndian.PutUint64(cvs[inst*32+16:], s.a[2][inst])
		binary.LittleEndian.PutUint64(cvs[inst*32+24:], s.a[3][inst])
	}
}

func decryptChunksTW128Generic(s *state8, src, dst []byte, cvs *[256]byte) {
	const blockSize = 8192
	s.decryptAll(src, dst, blockSize, 0x0B)
	for inst := range 8 {
		binary.LittleEndian.PutUint64(cvs[inst*32:], s.a[0][inst])
		binary.LittleEndian.PutUint64(cvs[inst*32+8:], s.a[1][inst])
		binary.LittleEndian.PutUint64(cvs[inst*32+16:], s.a[2][inst])
		binary.LittleEndian.PutUint64(cvs[inst*32+24:], s.a[3][inst])
	}
}
