package keccak

import "encoding/binary"

// EncryptChunksTW128 encrypts 8 × 8192-byte chunks from src into dst using
// the pre-initialized State8, producing 8 × 32-byte chain values in cvs.
// Src and dst must each be exactly 8×8192 = 65536 bytes.
func EncryptChunksTW128(s *State8, src, dst []byte, cvs *[256]byte) {
	if encryptChunksTW128Arch(s, src, dst, cvs) {
		return
	}
	encryptChunksTW128Generic(s, src, dst, cvs)
}

// DecryptChunksTW128 decrypts 8 × 8192-byte chunks from src into dst using
// the pre-initialized State8, producing 8 × 32-byte chain values in cvs.
// Src and dst must each be exactly 8×8192 = 65536 bytes.
func DecryptChunksTW128(s *State8, src, dst []byte, cvs *[256]byte) {
	if decryptChunksTW128Arch(s, src, dst, cvs) {
		return
	}
	decryptChunksTW128Generic(s, src, dst, cvs)
}

func encryptChunksTW128Generic(s *State8, src, dst []byte, cvs *[256]byte) {
	const blockSize = 8192
	s.EncryptAll(src, dst, blockSize, 0x0B)
	for inst := range 8 {
		binary.LittleEndian.PutUint64(cvs[inst*32:], s.a[0][inst])
		binary.LittleEndian.PutUint64(cvs[inst*32+8:], s.a[1][inst])
		binary.LittleEndian.PutUint64(cvs[inst*32+16:], s.a[2][inst])
		binary.LittleEndian.PutUint64(cvs[inst*32+24:], s.a[3][inst])
	}
}

func decryptChunksTW128Generic(s *State8, src, dst []byte, cvs *[256]byte) {
	const blockSize = 8192
	s.DecryptAll(src, dst, blockSize, 0x0B)
	for inst := range 8 {
		binary.LittleEndian.PutUint64(cvs[inst*32:], s.a[0][inst])
		binary.LittleEndian.PutUint64(cvs[inst*32+8:], s.a[1][inst])
		binary.LittleEndian.PutUint64(cvs[inst*32+16:], s.a[2][inst])
		binary.LittleEndian.PutUint64(cvs[inst*32+24:], s.a[3][inst])
	}
}
