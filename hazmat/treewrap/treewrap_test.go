package treewrap

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"testing"

	"github.com/codahale/thyrse/internal/keccak"
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
		{"168 bytes", keccak.Rate},
		{"169 bytes", keccak.Rate + 1},
		{"one chunk", ChunkSize},
		{"one chunk plus one", ChunkSize + 1},
		{"two chunks", 2 * ChunkSize},
		{"three chunks", 3 * ChunkSize},
		{"four chunks", 4 * ChunkSize},
		{"five chunks", 5 * ChunkSize},
		{"four chunks plus one", 4*ChunkSize + 1},
		{"six chunks plus 100", 6*ChunkSize + 100},
		{"eight chunks", 8 * ChunkSize},
		{"nine chunks", 9 * ChunkSize},
		{"eight chunks plus one", 8*ChunkSize + 1},
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
		{"168 bytes", keccak.Rate},
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

func loadTestVectors(t *testing.T) testVectorFile {
	t.Helper()
	data, err := os.ReadFile("../../docs/treewrap-test-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var f testVectorFile
	if err := json.Unmarshal(data, &f); err != nil {
		t.Fatal(err)
	}
	return f
}

type testVectorFile struct {
	Bare struct {
		KeyHex  string       `json:"key_hex"`
		Vectors []bareVector `json:"vectors"`
	} `json:"bare"`
}

type bareVector struct {
	ID      string `json:"id"`
	Title   string `json:"title"`
	Message struct {
		Mode string `json:"mode"`
		Len  int    `json:"len"`
	} `json:"message"`
	Expected struct {
		TagHex        string `json:"tag_hex"`
		CtHex         string `json:"ct_hex"`
		CtPrefix32Hex string `json:"ct_prefix32_hex"`
		FlipTagHex    string `json:"flip_tag_hex"`
		SwapTagHex    string `json:"swap_tag_hex"`
	} `json:"expected"`
}

func TestEncryptAndMAC(t *testing.T) {
	vf := loadTestVectors(t)
	keyBytes, err := hex.DecodeString(vf.Bare.KeyHex)
	if err != nil {
		t.Fatal(err)
	}
	key := (*[KeySize]byte)(keyBytes)

	for _, vec := range vf.Bare.Vectors {
		t.Run(vec.ID+"_"+vec.Title, func(t *testing.T) {
			pt := make([]byte, vec.Message.Len)
			for j := range pt {
				pt[j] = byte(j % 256)
			}
			ct, tag := EncryptAndMAC(nil, key, pt)

			// Check tag.
			if tagHex := hex.EncodeToString(tag[:]); tagHex != vec.Expected.TagHex {
				t.Errorf("tag = %s, want %s", tagHex, vec.Expected.TagHex)
			}

			// Check ciphertext (full or prefix depending on what the vector provides).
			if vec.Expected.CtHex != "" || vec.Message.Len == 0 {
				if ctHex := hex.EncodeToString(ct); ctHex != vec.Expected.CtHex {
					t.Errorf("ct = %s, want %s", ctHex, vec.Expected.CtHex)
				}
			}
			if vec.Expected.CtPrefix32Hex != "" {
				prefix := min(32, len(ct))
				if ctHex := hex.EncodeToString(ct[:prefix]); ctHex != vec.Expected.CtPrefix32Hex {
					t.Errorf("ct prefix = %s, want %s", ctHex, vec.Expected.CtPrefix32Hex)
				}
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
		{"168 bytes", keccak.Rate},
		{"169 bytes", keccak.Rate + 1},
		{"one chunk", ChunkSize},
		{"one chunk plus one", ChunkSize + 1},
		{"two chunks", 2 * ChunkSize},
		{"three chunks", 3 * ChunkSize},
		{"four chunks", 4 * ChunkSize},
		{"five chunks", 5 * ChunkSize},
		{"four chunks plus one", 4*ChunkSize + 1},
		{"six chunks plus 100", 6*ChunkSize + 100},
		{"eight chunks", 8 * ChunkSize},
		{"nine chunks", 9 * ChunkSize},
		{"eight chunks plus one", 8*ChunkSize + 1},
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
		{"168 bytes", keccak.Rate},
		{"one chunk", ChunkSize},
		{"one chunk plus one", ChunkSize + 1},
		{"two chunks", 2 * ChunkSize},
		{"four chunks", 4 * ChunkSize},
		{"five chunks", 5 * ChunkSize},
		{"six chunks plus 100", 6*ChunkSize + 100},
		{"eight chunks", 8 * ChunkSize},
		{"nine chunks", 9 * ChunkSize},
		{"eight chunks plus one", 8*ChunkSize + 1},
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
		{"168 bytes", keccak.Rate},
		{"one chunk", ChunkSize},
		{"one chunk plus one", ChunkSize + 1},
		{"two chunks", 2 * ChunkSize},
		{"four chunks", 4 * ChunkSize},
		{"five chunks", 5 * ChunkSize},
		{"six chunks plus 100", 6*ChunkSize + 100},
		{"eight chunks", 8 * ChunkSize},
		{"nine chunks", 9 * ChunkSize},
		{"eight chunks plus one", 8*ChunkSize + 1},
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
		1, keccak.Rate, keccak.Rate + 1, ChunkSize, ChunkSize + 1,
		2 * ChunkSize, 4 * ChunkSize, 5*ChunkSize + 100,
	}

	writePatterns := []struct {
		name      string
		chunkSize int
	}{
		{"single-byte", 1},
		{"small", 100},
		{"block-rate", keccak.Rate},
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
		1, keccak.Rate, keccak.Rate + 1, ChunkSize, ChunkSize + 1,
		2 * ChunkSize, 4 * ChunkSize, 5*ChunkSize + 100,
	}

	writePatterns := []struct {
		name      string
		chunkSize int
	}{
		{"single-byte", 1},
		{"small", 100},
		{"block-rate", keccak.Rate},
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

func BenchmarkAESGCM(b *testing.B) {
	key := testKey()
	for _, size := range testdata.Sizes {
		nonce := make([]byte, 12)
		pt := make([]byte, size.N)
		output := make([]byte, size.N)
		b.Run(size.Name, func(b *testing.B) {
			b.SetBytes(int64(size.N))
			b.ReportAllocs()
			for b.Loop() {
				block, _ := aes.NewCipher(key[:])
				gcm, _ := cipher.NewGCM(block)
				gcm.Seal(output[:0], nonce, pt, nil)
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
