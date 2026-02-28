package treewrap

import (
	"bytes"
	"crypto/subtle"
	"encoding/hex"
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
		{"empty", 0, "", "4d74e724544a5498eb490e22778f990b91f4881abadf52aab863144ca037ee2d"},
		{"1 byte", 1, "f1", "11c7e612c89abd32f4f3421557b2e29614eda613b2bcb316a15d02099a867769"},
		{"one chunk", ChunkSize, "f13513b1112a5cf6cfd4fe007a73351cc808c4837321b9860843b2ef40c06163", "2550a32191dfa145cadc8364812821be06fd566472804df57be019629b911385"},
		{"one chunk plus one", ChunkSize + 1, "f13513b1112a5cf6cfd4fe007a73351cc808c4837321b9860843b2ef40c06163", "9ed701f2d71ab47bc8e2819e256cb922a46f05497c292c383663fdcf2d6c9877"},
		{"four chunks", 4 * ChunkSize, "f13513b1112a5cf6cfd4fe007a73351cc808c4837321b9860843b2ef40c06163", "ae07f24e71e77ee3bc3247bfb87b897cede60b35186a95f00ba089391cf668c0"},
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
