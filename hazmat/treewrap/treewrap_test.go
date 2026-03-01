package treewrap

import (
	"bytes"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/codahale/thyrse/internal/testdata"
)

func testKey() *[KeySize]byte {
	var key [KeySize]byte
	for i := range key {
		key[i] = byte(i)
	}
	return &key
}

func TestRoundTrip(t *testing.T) {
	key := testKey()

	sizes := []struct {
		name string
		size int
	}{
		{"empty", 0},
		{"1 byte", 1},
		{"167 bytes", blockRate},
		{"168 bytes", blockRate + 1},
		{"one chunk", ChunkSize},
		{"one chunk plus one", ChunkSize + 1},
		{"two chunks", 2 * ChunkSize},
		{"three chunks", 3 * ChunkSize},
		{"four chunks", 4 * ChunkSize},
		{"five chunks", 5 * ChunkSize},
		{"four chunks plus one", 4*ChunkSize + 1},
		{"six chunks plus 100", 6*ChunkSize + 100},
	}

	for _, tt := range sizes {
		t.Run(tt.name, func(t *testing.T) {
			pt := make([]byte, tt.size)
			for i := range pt {
				pt[i] = byte(i)
			}

			ct, encryptTag := EncryptAndMAC(nil, key, pt)

			if len(ct) != len(pt) {
				t.Fatalf("ciphertext length %d, want %d", len(ct), len(pt))
			}

			if tt.size > 0 && bytes.Equal(ct, pt) {
				t.Error("ciphertext equals plaintext")
			}

			got, decryptTag := DecryptAndMAC(nil, key, ct)

			if subtle.ConstantTimeCompare(encryptTag[:], decryptTag[:]) != 1 {
				t.Fatal("DecryptAndMAC tag does not match EncryptAndMAC tag")
			}

			if !bytes.Equal(got, pt) {
				t.Error("decrypted plaintext does not match original")
			}
		})
	}
}

func TestRoundTripInPlace(t *testing.T) {
	key := testKey()

	sizes := []struct {
		name string
		size int
	}{
		{"empty", 0},
		{"1 byte", 1},
		{"167 bytes", blockRate},
		{"one chunk", ChunkSize},
		{"one chunk plus one", ChunkSize + 1},
		{"two chunks", 2 * ChunkSize},
		{"four chunks", 4 * ChunkSize},
	}

	for _, tt := range sizes {
		t.Run(tt.name, func(t *testing.T) {
			pt := make([]byte, tt.size)
			for i := range pt {
				pt[i] = byte(i)
			}

			// Keep a copy of the original plaintext.
			orig := make([]byte, len(pt))
			copy(orig, pt)

			// In-place encrypt: reuse pt's storage.
			ct, encryptTag := EncryptAndMAC(pt[:0], key, pt)

			// In-place decrypt: reuse ct's storage.
			got, decryptTag := DecryptAndMAC(ct[:0], key, ct)

			if subtle.ConstantTimeCompare(encryptTag[:], decryptTag[:]) != 1 {
				t.Fatal("DecryptAndMAC tag does not match EncryptAndMAC tag")
			}

			if !bytes.Equal(got, orig) {
				t.Error("in-place round-trip failed")
			}
		})
	}
}

func TestDecryptAndMAC(t *testing.T) {
	t.Run("wrong key", func(t *testing.T) {
		key := testKey()
		pt := []byte("hello world")

		_, encryptTag := EncryptAndMAC(nil, key, pt)

		// A different key produces a different tag.
		var wrongKey [KeySize]byte
		for i := range wrongKey {
			wrongKey[i] = byte(i + 1)
		}

		ct2, _ := EncryptAndMAC(nil, &wrongKey, pt)
		_, decryptTag := DecryptAndMAC(nil, key, ct2)

		if subtle.ConstantTimeCompare(encryptTag[:], decryptTag[:]) == 1 {
			t.Error("tags should not match for different keys")
		}
	})

	t.Run("modified ciphertext", func(t *testing.T) {
		key := testKey()
		pt := make([]byte, ChunkSize)
		for i := range pt {
			pt[i] = byte(i)
		}

		ct, encryptTag := EncryptAndMAC(nil, key, pt)

		// Flip a bit in the ciphertext.
		ct[0] ^= 1

		_, decryptTag := DecryptAndMAC(nil, key, ct)

		if subtle.ConstantTimeCompare(encryptTag[:], decryptTag[:]) == 1 {
			t.Error("tags should not match for modified ciphertext")
		}
	})

	t.Run("chunk swapped", func(t *testing.T) {
		key := testKey()
		pt := make([]byte, 2*ChunkSize)
		for i := range pt {
			pt[i] = byte(i)
		}

		ct, encryptTag := EncryptAndMAC(nil, key, pt)

		// Swap the two chunks.
		swapped := make([]byte, len(ct))
		copy(swapped[:ChunkSize], ct[ChunkSize:])
		copy(swapped[ChunkSize:], ct[:ChunkSize])

		_, decryptTag := DecryptAndMAC(nil, key, swapped)

		if subtle.ConstantTimeCompare(encryptTag[:], decryptTag[:]) == 1 {
			t.Error("tags should not match for swapped chunks")
		}
	})

	t.Run("empty", func(t *testing.T) {
		key := testKey()

		// Empty ciphertext with valid tag should round-trip.
		ct, encryptTag := EncryptAndMAC(nil, key, nil)
		got, decryptTag := DecryptAndMAC(nil, key, ct)

		if subtle.ConstantTimeCompare(encryptTag[:], decryptTag[:]) != 1 {
			t.Fatal("DecryptAndMAC tag does not match EncryptAndMAC tag")
		}
		if len(got) != 0 {
			t.Errorf("got %d bytes, want 0", len(got))
		}
	})
}

func TestEncryptX2MatchesX1(t *testing.T) {
	key := testKey()

	// x1 path: two separate calls.
	cv1 := make([]byte, 2*cvSize)
	pt := make([]byte, 2*ChunkSize)
	for i := range pt {
		pt[i] = byte(i)
	}

	ct1 := make([]byte, 2*ChunkSize)
	encryptX1(key, 0, pt[:ChunkSize], ct1[:ChunkSize], cv1[:cvSize])
	encryptX1(key, 1, pt[ChunkSize:], ct1[ChunkSize:], cv1[cvSize:])

	// x2 path: single call.
	cv2 := make([]byte, 2*cvSize)
	ct2 := make([]byte, 2*ChunkSize)
	encryptX2(key, 0, pt, ct2, cv2)

	if !bytes.Equal(ct1, ct2) {
		t.Error("encryptX2 ciphertext does not match encryptX1")
	}
	if !bytes.Equal(cv1, cv2) {
		t.Error("encryptX2 chain values do not match encryptX1")
	}
}

func TestEncryptX4MatchesX1(t *testing.T) {
	key := testKey()

	pt := make([]byte, 4*ChunkSize)
	for i := range pt {
		pt[i] = byte(i)
	}

	// x1 path.
	cv1 := make([]byte, 4*cvSize)
	ct1 := make([]byte, 4*ChunkSize)
	for i := range 4 {
		encryptX1(key, uint64(i), pt[i*ChunkSize:(i+1)*ChunkSize], ct1[i*ChunkSize:(i+1)*ChunkSize], cv1[i*cvSize:(i+1)*cvSize])
	}

	// x4 path.
	cv4 := make([]byte, 4*cvSize)
	ct4 := make([]byte, 4*ChunkSize)
	encryptX4(key, 0, pt, ct4, cv4)

	if !bytes.Equal(ct1, ct4) {
		t.Error("encryptX4 ciphertext does not match encryptX1")
	}
	if !bytes.Equal(cv1, cv4) {
		t.Error("encryptX4 chain values do not match encryptX1")
	}
}

func TestDecryptX2MatchesX1(t *testing.T) {
	key := testKey()

	// First encrypt to get ciphertext.
	pt := make([]byte, 2*ChunkSize)
	for i := range pt {
		pt[i] = byte(i)
	}
	ct, _ := EncryptAndMAC(nil, key, pt)

	// x1 path.
	cv1 := make([]byte, 2*cvSize)
	pt1 := make([]byte, 2*ChunkSize)
	decryptX1(key, 0, ct[:ChunkSize], pt1[:ChunkSize], cv1[:cvSize])
	decryptX1(key, 1, ct[ChunkSize:], pt1[ChunkSize:], cv1[cvSize:])

	// x2 path.
	cv2 := make([]byte, 2*cvSize)
	pt2 := make([]byte, 2*ChunkSize)
	decryptX2(key, 0, ct, pt2, cv2)

	if !bytes.Equal(pt1, pt2) {
		t.Error("decryptX2 plaintext does not match decryptX1")
	}
	if !bytes.Equal(cv1, cv2) {
		t.Error("decryptX2 chain values do not match decryptX1")
	}
}

func TestDecryptX4MatchesX1(t *testing.T) {
	key := testKey()

	pt := make([]byte, 4*ChunkSize)
	for i := range pt {
		pt[i] = byte(i)
	}
	ct, _ := EncryptAndMAC(nil, key, pt)

	// x1 path.
	cv1 := make([]byte, 4*cvSize)
	pt1 := make([]byte, 4*ChunkSize)
	for i := range 4 {
		decryptX1(key, uint64(i), ct[i*ChunkSize:(i+1)*ChunkSize], pt1[i*ChunkSize:(i+1)*ChunkSize], cv1[i*cvSize:(i+1)*cvSize])
	}

	// x4 path.
	cv4 := make([]byte, 4*cvSize)
	pt4 := make([]byte, 4*ChunkSize)
	decryptX4(key, 0, ct, pt4, cv4)

	if !bytes.Equal(pt1, pt4) {
		t.Error("decryptX4 plaintext does not match decryptX1")
	}
	if !bytes.Equal(cv1, cv4) {
		t.Error("decryptX4 chain values do not match decryptX1")
	}
}

func TestLengthEncode(t *testing.T) {
	tests := []struct {
		input uint64
		want  string
	}{
		{0, "00"},
		{1, "0101"},
		{255, "ff01"},
		{256, "010002"},
		{65535, "ffff02"},
	}
	for _, tt := range tests {
		got := hex.EncodeToString(lengthEncode(tt.input))
		if got != tt.want {
			t.Errorf("lengthEncode(%d) = %s, want %s", tt.input, got, tt.want)
		}
	}
}

func TestEncryptAndMAC(t *testing.T) {
	key := testKey()

	// Test vectors generated from the reference x1 implementation.
	// Each entry records the first min(32, len) bytes of ciphertext (hex) and the full tag (hex).
	tests := []struct {
		name    string
		ptSize  int
		wantCT  string
		wantTag string
	}{
		{"empty", 0, "", "668f373328d7bb108592d3aaf3dacdabcccff2ca302677c6ea33addf4f72990d"},
		{"1 byte", 1, "f1", "c04761e374ccb3a926eeabbe49698122b5d72d362deb35c04a22132676309c35"},
		{"one chunk", ChunkSize, "f13513b1112a5cf6cfd4fe007a73351cc808c4837321b9860843b2ef40c06163", "16ca20542882e63361f8dce572834de742e828f3046cdffc90b5b79faa8e86e2"},
		{"one chunk plus one", ChunkSize + 1, "f13513b1112a5cf6cfd4fe007a73351cc808c4837321b9860843b2ef40c06163", "b55dda0960670702b54d962a06a4dc526126c56a57d517eb527be1dfe2352460"},
		{"four chunks", 4 * ChunkSize, "f13513b1112a5cf6cfd4fe007a73351cc808c4837321b9860843b2ef40c06163", "41d1028f4f36dca68308b5549f5990e840b6d2a594db74e455cc57b6330ac748"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pt := make([]byte, tt.ptSize)
			for j := range pt {
				pt[j] = byte(j)
			}
			ct, tag := EncryptAndMAC(nil, key, pt)

			prefix := min(32, len(ct))
			if ctHex := hex.EncodeToString(ct[:prefix]); ctHex != tt.wantCT {
				t.Errorf("ct prefix = %s, want %s", ctHex, tt.wantCT)
			}
			if tagHex := hex.EncodeToString(tag[:]); tagHex != tt.wantTag {
				t.Errorf("tag = %s, want %s", tagHex, tt.wantTag)
			}
		})
	}
}

func TestEncryptorDecryptorRoundTrip(t *testing.T) {
	key := testKey()

	sizes := []struct {
		name string
		size int
	}{
		{"empty", 0},
		{"1 byte", 1},
		{"167 bytes", blockRate},
		{"168 bytes", blockRate + 1},
		{"one chunk", ChunkSize},
		{"one chunk plus one", ChunkSize + 1},
		{"two chunks", 2 * ChunkSize},
		{"three chunks", 3 * ChunkSize},
		{"four chunks", 4 * ChunkSize},
		{"five chunks", 5 * ChunkSize},
		{"four chunks plus one", 4*ChunkSize + 1},
		{"six chunks plus 100", 6*ChunkSize + 100},
	}

	for _, tt := range sizes {
		t.Run(tt.name, func(t *testing.T) {
			pt := make([]byte, tt.size)
			for i := range pt {
				pt[i] = byte(i)
			}

			// Encrypt incrementally.
			ct := make([]byte, len(pt))
			e := NewEncryptor(key)
			e.XORKeyStream(ct, pt)
			encTag := e.Finalize()

			// Decrypt incrementally.
			got := make([]byte, len(ct))
			d := NewDecryptor(key)
			d.XORKeyStream(got, ct)
			decTag := d.Finalize()

			if subtle.ConstantTimeCompare(encTag[:], decTag[:]) != 1 {
				t.Fatal("Decryptor tag does not match Encryptor tag")
			}
			if !bytes.Equal(got, pt) {
				t.Error("decrypted plaintext does not match original")
			}
		})
	}
}

func TestEncryptorEquivalence(t *testing.T) {
	key := testKey()

	sizes := []struct {
		name string
		size int
	}{
		{"empty", 0},
		{"1 byte", 1},
		{"167 bytes", blockRate},
		{"one chunk", ChunkSize},
		{"one chunk plus one", ChunkSize + 1},
		{"two chunks", 2 * ChunkSize},
		{"four chunks", 4 * ChunkSize},
		{"five chunks", 5 * ChunkSize},
		{"six chunks plus 100", 6*ChunkSize + 100},
	}

	for _, tt := range sizes {
		t.Run(tt.name, func(t *testing.T) {
			pt := make([]byte, tt.size)
			for i := range pt {
				pt[i] = byte(i)
			}

			// Single-call API.
			wantCT, wantTag := EncryptAndMAC(nil, key, pt)

			// Incremental API (single write).
			gotCT := make([]byte, len(pt))
			e := NewEncryptor(key)
			e.XORKeyStream(gotCT, pt)
			gotTag := e.Finalize()

			if !bytes.Equal(gotCT, wantCT) {
				t.Error("Encryptor ciphertext does not match EncryptAndMAC")
			}
			if gotTag != wantTag {
				t.Error("Encryptor tag does not match EncryptAndMAC")
			}
		})
	}
}

func TestDecryptorEquivalence(t *testing.T) {
	key := testKey()

	sizes := []struct {
		name string
		size int
	}{
		{"empty", 0},
		{"1 byte", 1},
		{"167 bytes", blockRate},
		{"one chunk", ChunkSize},
		{"one chunk plus one", ChunkSize + 1},
		{"two chunks", 2 * ChunkSize},
		{"four chunks", 4 * ChunkSize},
		{"five chunks", 5 * ChunkSize},
		{"six chunks plus 100", 6*ChunkSize + 100},
	}

	for _, tt := range sizes {
		t.Run(tt.name, func(t *testing.T) {
			pt := make([]byte, tt.size)
			for i := range pt {
				pt[i] = byte(i)
			}

			ct, _ := EncryptAndMAC(nil, key, pt)

			// Single-call API.
			wantPT, wantTag := DecryptAndMAC(nil, key, ct)

			// Incremental API (single write).
			gotPT := make([]byte, len(ct))
			d := NewDecryptor(key)
			d.XORKeyStream(gotPT, ct)
			gotTag := d.Finalize()

			if !bytes.Equal(gotPT, wantPT) {
				t.Error("Decryptor plaintext does not match DecryptAndMAC")
			}
			if gotTag != wantTag {
				t.Error("Decryptor tag does not match DecryptAndMAC")
			}
		})
	}
}

func TestEncryptorMultiWrite(t *testing.T) {
	key := testKey()

	sizes := []int{
		1, blockRate, blockRate + 1, ChunkSize, ChunkSize + 1,
		2 * ChunkSize, 4 * ChunkSize, 5*ChunkSize + 100,
	}

	writePatterns := []struct {
		name      string
		chunkSize int
	}{
		{"single-byte", 1},
		{"small", 100},
		{"block-rate", blockRate},
		{"chunk-aligned", ChunkSize},
		{"chunk-plus-one", ChunkSize + 1},
	}

	for _, size := range sizes {
		for _, wp := range writePatterns {
			name := fmt.Sprintf("%dB", size) + "/" + wp.name
			t.Run(name, func(t *testing.T) {
				pt := make([]byte, size)
				for i := range pt {
					pt[i] = byte(i)
				}

				// Reference: single-call API.
				wantCT, wantTag := EncryptAndMAC(nil, key, pt)

				// Incremental: write in chunks of wp.chunkSize.
				gotCT := make([]byte, size)
				e := NewEncryptor(key)
				for i := 0; i < size; i += wp.chunkSize {
					end := min(i+wp.chunkSize, size)
					e.XORKeyStream(gotCT[i:end], pt[i:end])
				}
				gotTag := e.Finalize()

				if !bytes.Equal(gotCT, wantCT) {
					t.Errorf("ciphertext mismatch (size=%d, write=%d)", size, wp.chunkSize)
				}
				if gotTag != wantTag {
					t.Errorf("tag mismatch (size=%d, write=%d)", size, wp.chunkSize)
				}
			})
		}
	}
}

func TestDecryptorMultiWrite(t *testing.T) {
	key := testKey()

	sizes := []int{
		1, blockRate, blockRate + 1, ChunkSize, ChunkSize + 1,
		2 * ChunkSize, 4 * ChunkSize, 5*ChunkSize + 100,
	}

	writePatterns := []struct {
		name      string
		chunkSize int
	}{
		{"single-byte", 1},
		{"small", 100},
		{"block-rate", blockRate},
		{"chunk-aligned", ChunkSize},
		{"chunk-plus-one", ChunkSize + 1},
	}

	for _, size := range sizes {
		for _, wp := range writePatterns {
			name := fmt.Sprintf("%dB", size) + "/" + wp.name
			t.Run(name, func(t *testing.T) {
				pt := make([]byte, size)
				for i := range pt {
					pt[i] = byte(i)
				}

				ct, _ := EncryptAndMAC(nil, key, pt)

				// Reference: single-call API.
				wantPT, wantTag := DecryptAndMAC(nil, key, ct)

				// Incremental: write in chunks of wp.chunkSize.
				gotPT := make([]byte, size)
				d := NewDecryptor(key)
				for i := 0; i < size; i += wp.chunkSize {
					end := min(i+wp.chunkSize, size)
					d.XORKeyStream(gotPT[i:end], ct[i:end])
				}
				gotTag := d.Finalize()

				if !bytes.Equal(gotPT, wantPT) {
					t.Errorf("plaintext mismatch (size=%d, write=%d)", size, wp.chunkSize)
				}
				if gotTag != wantTag {
					t.Errorf("tag mismatch (size=%d, write=%d)", size, wp.chunkSize)
				}
			})
		}
	}
}

func BenchmarkEncryptAndMAC(b *testing.B) {
	key := testKey()
	for _, size := range testdata.Sizes {
		pt := make([]byte, size.N)
		output := make([]byte, size.N)
		b.Run(size.Name, func(b *testing.B) {
			b.SetBytes(int64(size.N))
			b.ReportAllocs()
			for b.Loop() {
				EncryptAndMAC(output[:0], key, pt)
			}
		})
	}
}

func BenchmarkDecryptAndMAC(b *testing.B) {
	key := testKey()
	for _, size := range testdata.Sizes {
		pt := make([]byte, size.N)
		ct, _ := EncryptAndMAC(nil, key, pt)
		output := make([]byte, size.N)
		b.Run(size.Name, func(b *testing.B) {
			b.SetBytes(int64(size.N))
			b.ReportAllocs()
			for b.Loop() {
				DecryptAndMAC(output[:0], key, ct)
			}
		})
	}
}

func BenchmarkEncryptor(b *testing.B) {
	key := testKey()
	for _, size := range testdata.Sizes {
		pt := make([]byte, size.N)
		output := make([]byte, size.N)
		b.Run(size.Name, func(b *testing.B) {
			b.SetBytes(int64(size.N))
			b.ReportAllocs()
			for b.Loop() {
				e := NewEncryptor(key)
				e.XORKeyStream(output, pt)
				e.Finalize()
			}
		})
	}
}

func BenchmarkDecryptor(b *testing.B) {
	key := testKey()
	for _, size := range testdata.Sizes {
		pt := make([]byte, size.N)
		ct, _ := EncryptAndMAC(nil, key, pt)
		output := make([]byte, size.N)
		b.Run(size.Name, func(b *testing.B) {
			b.SetBytes(int64(size.N))
			b.ReportAllocs()
			for b.Loop() {
				d := NewDecryptor(key)
				d.XORKeyStream(output, ct)
				d.Finalize()
			}
		})
	}
}
