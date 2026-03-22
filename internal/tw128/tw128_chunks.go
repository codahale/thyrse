package tw128

import (
	"encoding/binary"
)

const (
	chunkSize     = ChunkSize
	chunkBodySize = (chunkSize / rate) * rate
	chunkTailSize = chunkSize - chunkBodySize
)

// encryptChunks encrypts 8 × 8128-byte chunks from src into dst,
// initializing 8 parallel leaf duplexes with key and iv(nonce, baseIndex+i),
// and writing the 8×32-byte leaf tags to tags.
// Src and dst must each be exactly 8×8128 = 65024 bytes.
func encryptChunks(key, nonce []byte, baseIndex uint64, src, dst []byte, tags *[256]byte) {
	var s state8
	initChunks(&s, key, nonce, baseIndex)
	if encryptChunksArch(&s, src, dst, tags) {
		return
	}
	encryptChunksGeneric(&s, src, dst, tags)
}

// decryptChunks decrypts 8 × 8128-byte chunks from src into dst,
// initializing 8 parallel leaf duplexes with key and iv(nonce, baseIndex+i),
// and writing the 8×32-byte leaf tags to tags.
// Src and dst must each be exactly 8×8128 = 65024 bytes.
func decryptChunks(key, nonce []byte, baseIndex uint64, src, dst []byte, tags *[256]byte) {
	var s state8
	initChunks(&s, key, nonce, baseIndex)
	if decryptChunksArch(&s, src, dst, tags) {
		return
	}
	decryptChunksGeneric(&s, src, dst, tags)
}

// initChunks initializes 8 parallel leaf duplexes: S[i] = K || iv(nonce, baseIndex+i), then permute.
func initChunks(s *state8, key, nonce []byte, baseIndex uint64) {
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
		j := baseIndex + uint64(inst)
		ivBuf := iv(nonce, j)
		for lane := range 21 {
			s.a[4+lane][inst] = binary.LittleEndian.Uint64(ivBuf[lane<<3 : lane<<3+8])
		}
	}

	s.permute12()
	s.pos = 0
}

func extractChunkTags(s *state8, tags *[256]byte) {
	for inst := range 8 {
		binary.LittleEndian.PutUint64(tags[inst*32:], s.a[0][inst])
		binary.LittleEndian.PutUint64(tags[inst*32+8:], s.a[1][inst])
		binary.LittleEndian.PutUint64(tags[inst*32+16:], s.a[2][inst])
		binary.LittleEndian.PutUint64(tags[inst*32+24:], s.a[3][inst])
	}
}

func finishEncryptChunks(s *state8, src, dst []byte, tags *[256]byte) {
	for inst := range 8 {
		off := inst*chunkSize + chunkBodySize
		s.encryptBytes(inst, src[off:off+chunkTailSize], dst[off:off+chunkTailSize])
	}
	s.pos = chunkTailSize
	s.bodyPadStarPermute()
	extractChunkTags(s, tags)
}

func finishDecryptChunks(s *state8, src, dst []byte, tags *[256]byte) {
	for inst := range 8 {
		off := inst*chunkSize + chunkBodySize
		s.decryptBytes(inst, src[off:off+chunkTailSize], dst[off:off+chunkTailSize])
	}
	s.pos = chunkTailSize
	s.bodyPadStarPermute()
	extractChunkTags(s, tags)
}

func encryptChunksGeneric(s *state8, src, dst []byte, tags *[256]byte) {
	// Body: 48 full rate stripes followed by a 64-byte tail.
	s.bodyEncryptAll8(src, dst, chunkSize)
	finishEncryptChunks(s, src, dst, tags)
}

func decryptChunksGeneric(s *state8, src, dst []byte, tags *[256]byte) {
	// Body: 48 full rate stripes followed by a 64-byte tail.
	s.bodyDecryptAll8(src, dst, chunkSize)
	finishDecryptChunks(s, src, dst, tags)
}
