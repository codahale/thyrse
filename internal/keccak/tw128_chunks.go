package keccak

import "encoding/binary"

const (
	tw128ChunkSize     = 8128
	tw128ChunkBodySize = (tw128ChunkSize / Rate) * Rate
	tw128ChunkTailSize = tw128ChunkSize - tw128ChunkBodySize
)

// EncryptChunksTW128 encrypts 8 × 8128-byte chunks from src into dst,
// initializing 8 parallel leaf duplexes with key and iv(nonce, baseIndex+i),
// and writing the 8×32-byte leaf tags to tags.
// Src and dst must each be exactly 8×8128 = 65024 bytes.
func EncryptChunksTW128(key, nonce []byte, baseIndex uint64, src, dst []byte, tags *[256]byte) {
	var s state8
	initChunksTW128(&s, key, nonce, baseIndex)
	if encryptChunksTW128Arch(&s, src, dst, tags) {
		return
	}
	encryptChunksTW128Generic(&s, src, dst, tags)
}

// DecryptChunksTW128 decrypts 8 × 8128-byte chunks from src into dst,
// initializing 8 parallel leaf duplexes with key and iv(nonce, baseIndex+i),
// and writing the 8×32-byte leaf tags to tags.
// Src and dst must each be exactly 8×8128 = 65024 bytes.
func DecryptChunksTW128(key, nonce []byte, baseIndex uint64, src, dst []byte, tags *[256]byte) {
	var s state8
	initChunksTW128(&s, key, nonce, baseIndex)
	if decryptChunksTW128Arch(&s, src, dst, tags) {
		return
	}
	decryptChunksTW128Generic(&s, src, dst, tags)
}

// initChunksTW128 initializes 8 parallel leaf duplexes: S[i] = K || iv(nonce, baseIndex+i), then permute.
func initChunksTW128(s *state8, key, nonce []byte, baseIndex uint64) {
	// Load key into lanes 0-3 (shared across all 8 instances).
	for lane := range 4 {
		w := binary.LittleEndian.Uint64(key[lane<<3 : lane<<3+8])
		for inst := range 8 {
			s.a[lane][inst] = w
		}
	}

	// Compute and load per-instance IVs into lanes 4-24.
	// IV = 0^{168-16-|ν(j)|} || nonce || ν(j)
	// Since all instances share the same nonce prefix, most lanes are identical.
	// Only the lanes containing ν(j) differ.
	for inst := range 8 {
		var ivBuf [Rate]byte
		j := baseIndex + uint64(inst)
		var nu [10]byte // max right_encode size
		nuLen := rightEncodeInto(nu[:], j)
		off := Rate - 16 - nuLen
		copy(ivBuf[off:], nonce)
		copy(ivBuf[off+16:], nu[:nuLen])
		for lane := range 21 {
			s.a[4+lane][inst] = binary.LittleEndian.Uint64(ivBuf[lane<<3 : lane<<3+8])
		}
	}

	s.permute12()
	s.pos = 0
}

// rightEncodeInto encodes value as right_encode into buf and returns the length used.
func rightEncodeInto(buf []byte, value uint64) int {
	if value == 0 {
		buf[0] = 0x00
		buf[1] = 0x01
		return 2
	}
	// Count bytes needed.
	n := 0
	v := value
	for v > 0 {
		n++
		v >>= 8
	}
	// Write big-endian.
	for i := n - 1; i >= 0; i-- {
		buf[i] = byte(value)
		value >>= 8
	}
	buf[n] = byte(n)
	return n + 1
}

func extractChunkTagsTW128(s *state8, tags *[256]byte) {
	for inst := range 8 {
		binary.LittleEndian.PutUint64(tags[inst*32:], s.a[0][inst])
		binary.LittleEndian.PutUint64(tags[inst*32+8:], s.a[1][inst])
		binary.LittleEndian.PutUint64(tags[inst*32+16:], s.a[2][inst])
		binary.LittleEndian.PutUint64(tags[inst*32+24:], s.a[3][inst])
	}
}

func finishEncryptChunksTW128(s *state8, src, dst []byte, tags *[256]byte) {
	if tw128ChunkTailSize > 0 {
		for inst := range 8 {
			off := inst*tw128ChunkSize + tw128ChunkBodySize
			s.encryptBytes(inst, src[off:off+tw128ChunkTailSize], dst[off:off+tw128ChunkTailSize])
		}
	}
	s.pos = tw128ChunkTailSize
	s.bodyPadStarPermute()
	extractChunkTagsTW128(s, tags)
}

func finishDecryptChunksTW128(s *state8, src, dst []byte, tags *[256]byte) {
	if tw128ChunkTailSize > 0 {
		for inst := range 8 {
			off := inst*tw128ChunkSize + tw128ChunkBodySize
			s.decryptBytes(inst, src[off:off+tw128ChunkTailSize], dst[off:off+tw128ChunkTailSize])
		}
	}
	s.pos = tw128ChunkTailSize
	s.bodyPadStarPermute()
	extractChunkTagsTW128(s, tags)
}

func encryptChunksTW128Generic(s *state8, src, dst []byte, tags *[256]byte) {
	// Body: 48 full rate stripes followed by a 64-byte tail.
	s.bodyEncryptAll8(src, dst, tw128ChunkSize)
	finishEncryptChunksTW128(s, src, dst, tags)
}

func decryptChunksTW128Generic(s *state8, src, dst []byte, tags *[256]byte) {
	// Body: 48 full rate stripes followed by a 64-byte tail.
	s.bodyDecryptAll8(src, dst, tw128ChunkSize)
	finishDecryptChunksTW128(s, src, dst, tags)
}
