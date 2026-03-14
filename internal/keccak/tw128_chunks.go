package keccak

// EncryptChunksTW128 encrypts 8 × 8192-byte chunks from src into dst using
// the pre-initialized State8. After return, the chain values remain in the
// State8 lanes (lanes 0-3 of each instance) for direct consumption via
// AbsorbCVx8. Src and dst must each be exactly 8×8192 = 65536 bytes.
func EncryptChunksTW128(s *State8, src, dst []byte) {
	if encryptChunksTW128Arch(s, src, dst) {
		return
	}
	s.EncryptAll(src, dst, 8192, 0x0B)
}

// DecryptChunksTW128 decrypts 8 × 8192-byte chunks from src into dst using
// the pre-initialized State8. After return, the chain values remain in the
// State8 lanes (lanes 0-3 of each instance) for direct consumption via
// AbsorbCVx8. Src and dst must each be exactly 8×8192 = 65536 bytes.
func DecryptChunksTW128(s *State8, src, dst []byte) {
	if decryptChunksTW128Arch(s, src, dst) {
		return
	}
	s.DecryptAll(src, dst, 8192, 0x0B)
}
