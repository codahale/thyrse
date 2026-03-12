package tw128

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

func testKey() []byte {
	key := make([]byte, KeySize)
	for i := range key {
		key[i] = byte(i)
	}
	return key
}

// encrypt is a convenience helper for tests: single-call encrypt via streaming API.
func encrypt(key, nonce, ad, pt []byte) ([]byte, [TagSize]byte) {
	ct := make([]byte, len(pt))
	e := NewEncryptor(key, nonce, ad)
	e.XORKeyStream(ct, pt)
	return ct, e.Finalize()
}

// decrypt is a convenience helper for tests: single-call decrypt via streaming API.
func decrypt(key, nonce, ad, ct []byte) ([]byte, [TagSize]byte) {
	pt := make([]byte, len(ct))
	d := NewDecryptor(key, nonce, ad)
	d.XORKeyStream(pt, ct)
	return pt, d.Finalize()
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

			ct, encryptTag := encrypt(key, nil, nil, pt)

			if len(ct) != len(pt) {
				t.Fatalf("ciphertext length %d, want %d", len(ct), len(pt))
			}

			if tt.size > 0 && bytes.Equal(ct, pt) {
				t.Error("ciphertext equals plaintext")
			}

			got, decryptTag := decrypt(key, nil, nil, ct)

			if subtle.ConstantTimeCompare(encryptTag[:], decryptTag[:]) != 1 {
				t.Fatal("decrypt tag does not match encrypt tag")
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
			orig := make([]byte, len(pt))
			copy(orig, pt)

			// In-place encrypt.
			e := NewEncryptor(key, nil, nil)
			e.XORKeyStream(pt, pt)
			encryptTag := e.Finalize()

			// In-place decrypt.
			d := NewDecryptor(key, nil, nil)
			d.XORKeyStream(pt, pt)
			decryptTag := d.Finalize()

			if subtle.ConstantTimeCompare(encryptTag[:], decryptTag[:]) != 1 {
				t.Fatal("decrypt tag does not match encrypt tag")
			}

			if !bytes.Equal(pt, orig) {
				t.Error("in-place round-trip failed")
			}
		})
	}
}

func TestDecrypt(t *testing.T) {
	t.Run("wrong key", func(t *testing.T) {
		key := testKey()
		pt := []byte("hello world")

		_, encryptTag := encrypt(key, nil, nil, pt)

		wrongKey := make([]byte, KeySize)
		for i := range wrongKey {
			wrongKey[i] = byte(i + 1)
		}

		ct2, _ := encrypt(wrongKey, nil, nil, pt)
		_, decryptTag := decrypt(key, nil, nil, ct2)

		if got, want := subtle.ConstantTimeCompare(encryptTag[:], decryptTag[:]), 0; got != want {
			t.Errorf("ConstantTimeCompare() = %d, want %d", got, want)
		}
	})

	t.Run("modified ciphertext", func(t *testing.T) {
		key := testKey()
		pt := make([]byte, ChunkSize)
		for i := range pt {
			pt[i] = byte(i)
		}

		ct, encryptTag := encrypt(key, nil, nil, pt)
		ct[0] ^= 1

		_, decryptTag := decrypt(key, nil, nil, ct)

		if got, want := subtle.ConstantTimeCompare(encryptTag[:], decryptTag[:]), 0; got != want {
			t.Errorf("ConstantTimeCompare() = %d, want %d", got, want)
		}
	})

	t.Run("chunk swapped", func(t *testing.T) {
		key := testKey()
		pt := make([]byte, 2*ChunkSize)
		for i := range pt {
			pt[i] = byte(i)
		}

		ct, encryptTag := encrypt(key, nil, nil, pt)

		swapped := make([]byte, len(ct))
		copy(swapped[:ChunkSize], ct[ChunkSize:])
		copy(swapped[ChunkSize:], ct[:ChunkSize])

		_, decryptTag := decrypt(key, nil, nil, swapped)

		if got, want := subtle.ConstantTimeCompare(encryptTag[:], decryptTag[:]), 0; got != want {
			t.Errorf("ConstantTimeCompare() = %d, want %d", got, want)
		}
	})

	t.Run("empty", func(t *testing.T) {
		key := testKey()

		ct, encryptTag := encrypt(key, nil, nil, nil)
		got, decryptTag := decrypt(key, nil, nil, ct)

		if subtle.ConstantTimeCompare(encryptTag[:], decryptTag[:]) != 1 {
			t.Fatal("decrypt tag does not match encrypt tag")
		}
		if len(got) != 0 {
			t.Errorf("got %d bytes, want 0", len(got))
		}
	})
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

			ct := make([]byte, len(pt))
			e := NewEncryptor(key, nil, nil)
			e.XORKeyStream(ct, pt)
			encTag := e.Finalize()

			got := make([]byte, len(ct))
			d := NewDecryptor(key, nil, nil)
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

				// Reference: single-call.
				wantCT, wantTag := encrypt(key, nil, nil, pt)

				// Incremental: write in chunks of wp.chunkSize.
				gotCT := make([]byte, size)
				e := NewEncryptor(key, nil, nil)
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

				ct, _ := encrypt(key, nil, nil, pt)

				// Reference: single-call.
				wantPT, wantTag := decrypt(key, nil, nil, ct)

				// Incremental: write in chunks of wp.chunkSize.
				gotPT := make([]byte, size)
				d := NewDecryptor(key, nil, nil)
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

// AEAD test vectors from docs/tw128-test-vectors.json.

type aeadVectorFile struct {
	AEAD struct {
		Vectors []aeadVector `json:"vectors"`
	} `json:"aead"`
}

type aeadVector struct {
	ID       string `json:"id"`
	Title    string `json:"title"`
	KeyHex   string `json:"key_hex"`
	NonceHex string `json:"nonce_hex"`
	ADHex    string `json:"ad_hex"`
	Message  struct {
		Mode string `json:"mode"`
		Len  int    `json:"len"`
		Hex  string `json:"hex"`
	} `json:"message"`
	AltMessage *struct {
		Mode string `json:"mode"`
		Hex  string `json:"hex"`
	} `json:"alt_message"`
	AltADHex string `json:"alt_ad_hex"`
	Checks   struct {
		BadNonce          bool `json:"bad_nonce"`
		BadAD             bool `json:"bad_ad"`
		BadTag            bool `json:"bad_tag"`
		NonceReuseXORLeak bool `json:"nonce_reuse_xor_leak"`
		SwapNonceAD       bool `json:"swap_nonce_ad"`
		ADEmptyVsZeroByte bool `json:"ad_empty_vs_zero_byte"`
	} `json:"checks"`
	Expected struct {
		CtTagHex            string `json:"ct_tag_hex"`
		CtPrefix32Hex       string `json:"ct_prefix32_hex"`
		TagHex              string `json:"tag_hex"`
		ReuseCtTagHex       string `json:"reuse_ct_tag_hex"`
		SwapNonceADCtTagHex string `json:"swap_nonce_ad_ct_tag_hex"`
		AltADCtTagHex       string `json:"alt_ad_ct_tag_hex"`
	} `json:"expected"`
}

func loadAEADVectors(t *testing.T) []aeadVector {
	t.Helper()
	data, err := os.ReadFile("../../docs/tw128-test-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var f aeadVectorFile
	if err := json.Unmarshal(data, &f); err != nil {
		t.Fatal(err)
	}
	return f.AEAD.Vectors
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func makeAEADPlaintext(msg struct {
	Mode string `json:"mode"`
	Len  int    `json:"len"`
	Hex  string `json:"hex"`
}) []byte {
	if msg.Mode == "hex" {
		b, _ := hex.DecodeString(msg.Hex)
		return b
	}
	pt := make([]byte, msg.Len)
	for i := range pt {
		pt[i] = byte(i % 256)
	}
	return pt
}

// seal encrypts and appends tag via streaming API.
func seal(key, nonce, ad, pt []byte) []byte {
	ct, tag := encrypt(key, nonce, ad, pt)
	return append(ct, tag[:]...)
}

// open decrypts and verifies tag via streaming API.
func open(key, nonce, ad, ctTag []byte) ([]byte, bool) {
	if len(ctTag) < TagSize {
		return nil, false
	}
	ct := ctTag[:len(ctTag)-TagSize]
	tag := ctTag[len(ctTag)-TagSize:]
	pt, gotTag := decrypt(key, nonce, ad, ct)
	if subtle.ConstantTimeCompare(gotTag[:], tag) != 1 {
		return nil, false
	}
	return pt, true
}

func TestAEADSeal(t *testing.T) {
	for _, vec := range loadAEADVectors(t) {
		t.Run(vec.ID+"_"+vec.Title, func(t *testing.T) {
			key := mustHex(t, vec.KeyHex)
			nonce := mustHex(t, vec.NonceHex)
			ad := mustHex(t, vec.ADHex)
			pt := makeAEADPlaintext(vec.Message)

			ctTag := seal(key, nonce, ad, pt)

			if vec.Expected.CtTagHex != "" {
				if got, want := hex.EncodeToString(ctTag), vec.Expected.CtTagHex; got != want {
					t.Errorf("ct_tag = %s, want %s", got, want)
				}
			}
			if vec.Expected.CtPrefix32Hex != "" {
				prefix := min(32, len(ctTag)-TagSize)
				if got, want := hex.EncodeToString(ctTag[:prefix]), vec.Expected.CtPrefix32Hex; got != want {
					t.Errorf("ct prefix = %s, want %s", got, want)
				}
			}
			if vec.Expected.TagHex != "" {
				tag := ctTag[len(ctTag)-TagSize:]
				if got, want := hex.EncodeToString(tag), vec.Expected.TagHex; got != want {
					t.Errorf("tag = %s, want %s", got, want)
				}
			}
		})
	}
}

func TestAEADRoundTrip(t *testing.T) {
	for _, vec := range loadAEADVectors(t) {
		t.Run(vec.ID+"_"+vec.Title, func(t *testing.T) {
			key := mustHex(t, vec.KeyHex)
			nonce := mustHex(t, vec.NonceHex)
			ad := mustHex(t, vec.ADHex)
			pt := makeAEADPlaintext(vec.Message)

			ctTag := seal(key, nonce, ad, pt)

			got, ok := open(key, nonce, ad, ctTag)
			if !ok {
				t.Fatal("Open failed")
			}
			if !bytes.Equal(got, pt) {
				t.Error("round-trip plaintext mismatch")
			}
		})
	}
}

func TestAEADOpenBadNonce(t *testing.T) {
	for _, vec := range loadAEADVectors(t) {
		if !vec.Checks.BadNonce {
			continue
		}
		t.Run(vec.ID+"_"+vec.Title, func(t *testing.T) {
			key := mustHex(t, vec.KeyHex)
			nonce := mustHex(t, vec.NonceHex)
			ad := mustHex(t, vec.ADHex)
			pt := makeAEADPlaintext(vec.Message)

			ctTag := seal(key, nonce, ad, pt)

			badNonce := make([]byte, len(nonce))
			copy(badNonce, nonce)
			badNonce[0] ^= 1

			if _, ok := open(key, badNonce, ad, ctTag); ok {
				t.Error("Open with bad nonce should fail")
			}
		})
	}
}

func TestAEADOpenBadAD(t *testing.T) {
	for _, vec := range loadAEADVectors(t) {
		if !vec.Checks.BadAD {
			continue
		}
		t.Run(vec.ID+"_"+vec.Title, func(t *testing.T) {
			key := mustHex(t, vec.KeyHex)
			nonce := mustHex(t, vec.NonceHex)
			ad := mustHex(t, vec.ADHex)
			pt := makeAEADPlaintext(vec.Message)

			ctTag := seal(key, nonce, ad, pt)
			badAD := append(ad[:len(ad):len(ad)], 0xFF)

			if _, ok := open(key, nonce, badAD, ctTag); ok {
				t.Error("Open with bad AD should fail")
			}
		})
	}
}

func TestAEADOpenBadTag(t *testing.T) {
	for _, vec := range loadAEADVectors(t) {
		if !vec.Checks.BadTag {
			continue
		}
		t.Run(vec.ID+"_"+vec.Title, func(t *testing.T) {
			key := mustHex(t, vec.KeyHex)
			nonce := mustHex(t, vec.NonceHex)
			ad := mustHex(t, vec.ADHex)
			pt := makeAEADPlaintext(vec.Message)

			ctTag := seal(key, nonce, ad, pt)
			ctTag[len(ctTag)-1] ^= 1

			if _, ok := open(key, nonce, ad, ctTag); ok {
				t.Error("Open with bad tag should fail")
			}
		})
	}
}

func TestAEADNonceReuse(t *testing.T) {
	for _, vec := range loadAEADVectors(t) {
		if !vec.Checks.NonceReuseXORLeak {
			continue
		}
		t.Run(vec.ID+"_"+vec.Title, func(t *testing.T) {
			key := mustHex(t, vec.KeyHex)
			nonce := mustHex(t, vec.NonceHex)
			ad := mustHex(t, vec.ADHex)
			pt1 := makeAEADPlaintext(vec.Message)

			ctTag1 := seal(key, nonce, ad, pt1)
			if got, want := hex.EncodeToString(ctTag1), vec.Expected.CtTagHex; got != want {
				t.Errorf("ct_tag1 = %s, want %s", got, want)
			}

			pt2, _ := hex.DecodeString(vec.AltMessage.Hex)
			ctTag2 := seal(key, nonce, ad, pt2)
			if got, want := hex.EncodeToString(ctTag2), vec.Expected.ReuseCtTagHex; got != want {
				t.Errorf("ct_tag2 = %s, want %s", got, want)
			}

			ct1 := ctTag1[:len(ctTag1)-TagSize]
			ct2 := ctTag2[:len(ctTag2)-TagSize]
			xorCT := make([]byte, len(ct1))
			xorPT := make([]byte, len(pt1))
			subtle.XORBytes(xorCT, ct1, ct2)
			subtle.XORBytes(xorPT, pt1, pt2)
			if !bytes.Equal(xorCT, xorPT) {
				t.Error("XOR of ciphertexts does not equal XOR of plaintexts")
			}
		})
	}
}

func TestAEADSwapNonceAD(t *testing.T) {
	for _, vec := range loadAEADVectors(t) {
		if !vec.Checks.SwapNonceAD {
			continue
		}
		t.Run(vec.ID+"_"+vec.Title, func(t *testing.T) {
			key := mustHex(t, vec.KeyHex)
			nonce := mustHex(t, vec.NonceHex)
			ad := mustHex(t, vec.ADHex)
			pt := makeAEADPlaintext(vec.Message)

			ctTag := seal(key, nonce, ad, pt)
			swapCtTag := seal(key, ad, nonce, pt)

			if got, want := hex.EncodeToString(swapCtTag), vec.Expected.SwapNonceADCtTagHex; got != want {
				t.Errorf("swap ct_tag = %s, want %s", got, want)
			}
			if bytes.Equal(ctTag, swapCtTag) {
				t.Error("swapped nonce/AD produced same ciphertext")
			}
		})
	}
}

func TestAEADEmptyVsZeroByteAD(t *testing.T) {
	for _, vec := range loadAEADVectors(t) {
		if !vec.Checks.ADEmptyVsZeroByte {
			continue
		}
		t.Run(vec.ID+"_"+vec.Title, func(t *testing.T) {
			key := mustHex(t, vec.KeyHex)
			nonce := mustHex(t, vec.NonceHex)
			pt := makeAEADPlaintext(vec.Message)

			ctTag := seal(key, nonce, nil, pt)
			if got, want := hex.EncodeToString(ctTag), vec.Expected.CtTagHex; got != want {
				t.Errorf("empty AD ct_tag = %s, want %s", got, want)
			}

			altAD := mustHex(t, vec.AltADHex)
			altCtTag := seal(key, nonce, altAD, pt)
			if got, want := hex.EncodeToString(altCtTag), vec.Expected.AltADCtTagHex; got != want {
				t.Errorf("alt AD ct_tag = %s, want %s", got, want)
			}

			if bytes.Equal(ctTag, altCtTag) {
				t.Error("empty AD and zero-byte AD produced same ciphertext")
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
				e := NewEncryptor(key, nil, nil)
				e.XORKeyStream(output, pt)
				e.Finalize()
			}
		})
	}
}

func BenchmarkAESGCM(b *testing.B) {
	key := testKey()
	for _, size := range testdata.Sizes {
		nonce := make([]byte, 12)
		pt := make([]byte, size.N)
		output := make([]byte, size.N+16)
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

func BenchmarkDecryptor(b *testing.B) {
	key := testKey()
	for _, size := range testdata.Sizes {
		pt := make([]byte, size.N)
		ct, _ := encrypt(key, nil, nil, pt)
		output := make([]byte, size.N)
		b.Run(size.Name, func(b *testing.B) {
			b.SetBytes(int64(size.N))
			b.ReportAllocs()
			for b.Loop() {
				d := NewDecryptor(key, nil, nil)
				d.XORKeyStream(output, ct)
				d.Finalize()
			}
		})
	}
}
