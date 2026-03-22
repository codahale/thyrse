package tw128

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func testChunkNonce() []byte {
	nonce := make([]byte, 16)
	for i := range nonce {
		nonce[i] = byte(i + 0x10)
	}
	return nonce
}

func TestEncryptChunksTW128(t *testing.T) {
	const blockSize = tw128ChunkSize
	key := testKey()
	nonce := testChunkNonce()

	// Build deterministic input.
	src := make([]byte, 8*blockSize)
	for i := range src {
		src[i] = byte(i*7 + i>>8)
	}

	// Run generic path: init + encrypt + extract tags.
	var s1 state8
	initChunksTW128(&s1, key, nonce, 1)
	dst1 := make([]byte, 8*blockSize)
	var tags1 [256]byte
	encryptChunksTW128Generic(&s1, src, dst1, &tags1)

	// Run arch-dispatched path.
	dst2 := make([]byte, 8*blockSize)
	var tags2 [256]byte
	encryptChunksTW128(key, nonce, 1, src, dst2, &tags2)

	if !bytes.Equal(dst1, dst2) {
		t.Error("ciphertext mismatch between generic and arch paths")
	}
	if tags1 != tags2 {
		for inst := range 8 {
			for lane := range 4 {
				w := binary.LittleEndian.Uint64(tags1[inst*32+lane*8:])
				g := binary.LittleEndian.Uint64(tags2[inst*32+lane*8:])
				if w != g {
					t.Errorf("encrypt: instance %d, lane %d: got %016x, want %016x", inst, lane, g, w)
				}
			}
		}
	}
}

func TestDecryptChunksTW128(t *testing.T) {
	const blockSize = tw128ChunkSize
	key := testKey()
	nonce := testChunkNonce()

	// Build deterministic input (ciphertext).
	src := make([]byte, 8*blockSize)
	for i := range src {
		src[i] = byte(i*13 + i>>8)
	}

	// Run generic path.
	var s1 state8
	initChunksTW128(&s1, key, nonce, 1)
	dst1 := make([]byte, 8*blockSize)
	var tags1 [256]byte
	decryptChunksTW128Generic(&s1, src, dst1, &tags1)

	// Run arch-dispatched path.
	dst2 := make([]byte, 8*blockSize)
	var tags2 [256]byte
	decryptChunksTW128(key, nonce, 1, src, dst2, &tags2)

	if !bytes.Equal(dst1, dst2) {
		t.Error("plaintext mismatch between generic and arch paths")
	}
	if tags1 != tags2 {
		for inst := range 8 {
			for lane := range 4 {
				w := binary.LittleEndian.Uint64(tags1[inst*32+lane*8:])
				g := binary.LittleEndian.Uint64(tags2[inst*32+lane*8:])
				if w != g {
					t.Errorf("decrypt: instance %d, lane %d: got %016x, want %016x", inst, lane, g, w)
				}
			}
		}
	}
}

func BenchmarkEncryptChunksTW128(b *testing.B) {
	const blockSize = tw128ChunkSize
	key := testKey()
	nonce := testChunkNonce()
	src := make([]byte, 8*blockSize)
	dst := make([]byte, 8*blockSize)
	for i := range src {
		src[i] = byte(i)
	}
	var tags [256]byte
	b.SetBytes(8 * blockSize)
	for b.Loop() {
		encryptChunksTW128(key, nonce, 1, src, dst, &tags)
	}
}

func BenchmarkDecryptChunksTW128(b *testing.B) {
	const blockSize = tw128ChunkSize
	key := testKey()
	nonce := testChunkNonce()
	src := make([]byte, 8*blockSize)
	dst := make([]byte, 8*blockSize)
	for i := range src {
		src[i] = byte(i)
	}
	var tags [256]byte
	b.SetBytes(8 * blockSize)
	for b.Loop() {
		decryptChunksTW128(key, nonce, 1, src, dst, &tags)
	}
}
