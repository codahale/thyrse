package tw128

import (
	"bytes"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

type testVectorFile struct {
	Bare struct {
		KeyHex  string       `json:"key_hex"`
		Vectors []bareVector `json:"vectors"`
	} `json:"bare"`
	AEAD struct {
		Vectors []aeadVector `json:"vectors"`
	} `json:"aead"`
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
	} `json:"expected"`
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

func loadTestVectors(t *testing.T) testVectorFile {
	t.Helper()
	data, err := os.ReadFile("../../docs/tw128-test-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var f testVectorFile
	if err := json.Unmarshal(data, &f); err != nil {
		t.Fatal(err)
	}
	return f
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func makePlaintext(vec bareVector) []byte {
	pt := make([]byte, vec.Message.Len)
	for i := range pt {
		pt[i] = byte(i % 256)
	}
	return pt
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

func TestBareEncryptAndMAC(t *testing.T) {
	vf := loadTestVectors(t)
	key := (*[KeySize]byte)(mustHex(t, vf.Bare.KeyHex))

	for _, vec := range vf.Bare.Vectors {
		t.Run(vec.ID+"_"+vec.Title, func(t *testing.T) {
			pt := makePlaintext(vec)
			ct, tag := EncryptAndMAC(nil, key, pt)

			if got, want := hex.EncodeToString(tag[:]), vec.Expected.TagHex; got != want {
				t.Errorf("tag = %s, want %s", got, want)
			}
			if vec.Expected.CtHex != "" || vec.Message.Len == 0 {
				if got, want := hex.EncodeToString(ct), vec.Expected.CtHex; got != want {
					t.Errorf("ct = %s, want %s", got, want)
				}
			}
			if vec.Expected.CtPrefix32Hex != "" {
				prefix := min(32, len(ct))
				if got, want := hex.EncodeToString(ct[:prefix]), vec.Expected.CtPrefix32Hex; got != want {
					t.Errorf("ct prefix = %s, want %s", got, want)
				}
			}
		})
	}
}

func TestAEADSeal(t *testing.T) {
	vf := loadTestVectors(t)

	for _, vec := range vf.AEAD.Vectors {
		t.Run(vec.ID+"_"+vec.Title, func(t *testing.T) {
			key := mustHex(t, vec.KeyHex)
			nonce := mustHex(t, vec.NonceHex)
			ad := mustHex(t, vec.ADHex)
			pt := makeAEADPlaintext(vec.Message)

			a := New(key, len(nonce))
			ctTag := a.Seal(nil, nonce, pt, ad)

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
	vf := loadTestVectors(t)

	for _, vec := range vf.AEAD.Vectors {
		t.Run(vec.ID+"_"+vec.Title, func(t *testing.T) {
			key := mustHex(t, vec.KeyHex)
			nonce := mustHex(t, vec.NonceHex)
			ad := mustHex(t, vec.ADHex)
			pt := makeAEADPlaintext(vec.Message)

			a := New(key, len(nonce))
			ctTag := a.Seal(nil, nonce, pt, ad)

			got, err := a.Open(nil, nonce, ctTag, ad)
			if err != nil {
				t.Fatalf("Open failed: %v", err)
			}
			if !bytes.Equal(got, pt) {
				t.Error("round-trip plaintext mismatch")
			}
		})
	}
}

func TestAEADOpenBadNonce(t *testing.T) {
	vf := loadTestVectors(t)

	for _, vec := range vf.AEAD.Vectors {
		if !vec.Checks.BadNonce {
			continue
		}
		t.Run(vec.ID+"_"+vec.Title, func(t *testing.T) {
			key := mustHex(t, vec.KeyHex)
			nonce := mustHex(t, vec.NonceHex)
			ad := mustHex(t, vec.ADHex)
			pt := makeAEADPlaintext(vec.Message)

			a := New(key, len(nonce))
			ctTag := a.Seal(nil, nonce, pt, ad)

			badNonce := make([]byte, len(nonce))
			copy(badNonce, nonce)
			badNonce[0] ^= 1

			_, err := a.Open(nil, badNonce, ctTag, ad)
			if err != ErrOpen {
				t.Errorf("Open with bad nonce: got %v, want ErrOpen", err)
			}
		})
	}
}

func TestAEADOpenBadAD(t *testing.T) {
	vf := loadTestVectors(t)

	for _, vec := range vf.AEAD.Vectors {
		if !vec.Checks.BadAD {
			continue
		}
		t.Run(vec.ID+"_"+vec.Title, func(t *testing.T) {
			key := mustHex(t, vec.KeyHex)
			nonce := mustHex(t, vec.NonceHex)
			ad := mustHex(t, vec.ADHex)
			pt := makeAEADPlaintext(vec.Message)

			a := New(key, len(nonce))
			ctTag := a.Seal(nil, nonce, pt, ad)

			badAD := append(ad[:len(ad):len(ad)], 0xFF)

			_, err := a.Open(nil, nonce, ctTag, badAD)
			if err != ErrOpen {
				t.Errorf("Open with bad AD: got %v, want ErrOpen", err)
			}
		})
	}
}

func TestAEADOpenBadTag(t *testing.T) {
	vf := loadTestVectors(t)

	for _, vec := range vf.AEAD.Vectors {
		if !vec.Checks.BadTag {
			continue
		}
		t.Run(vec.ID+"_"+vec.Title, func(t *testing.T) {
			key := mustHex(t, vec.KeyHex)
			nonce := mustHex(t, vec.NonceHex)
			ad := mustHex(t, vec.ADHex)
			pt := makeAEADPlaintext(vec.Message)

			a := New(key, len(nonce))
			ctTag := a.Seal(nil, nonce, pt, ad)

			// Flip last bit of tag.
			ctTag[len(ctTag)-1] ^= 1

			_, err := a.Open(nil, nonce, ctTag, ad)
			if err != ErrOpen {
				t.Errorf("Open with bad tag: got %v, want ErrOpen", err)
			}
		})
	}
}

func TestAEADNonceReuse(t *testing.T) {
	vf := loadTestVectors(t)

	for _, vec := range vf.AEAD.Vectors {
		if !vec.Checks.NonceReuseXORLeak {
			continue
		}
		t.Run(vec.ID+"_"+vec.Title, func(t *testing.T) {
			key := mustHex(t, vec.KeyHex)
			nonce := mustHex(t, vec.NonceHex)
			ad := mustHex(t, vec.ADHex)
			pt1 := makeAEADPlaintext(vec.Message)

			a := New(key, len(nonce))
			ctTag1 := a.Seal(nil, nonce, pt1, ad)

			// Verify ct_tag matches expected.
			if got, want := hex.EncodeToString(ctTag1), vec.Expected.CtTagHex; got != want {
				t.Errorf("ct_tag1 = %s, want %s", got, want)
			}

			// Encrypt alt message with same nonce.
			pt2, _ := hex.DecodeString(vec.AltMessage.Hex)
			ctTag2 := a.Seal(nil, nonce, pt2, ad)

			if got, want := hex.EncodeToString(ctTag2), vec.Expected.ReuseCtTagHex; got != want {
				t.Errorf("ct_tag2 = %s, want %s", got, want)
			}

			// XOR of ciphertexts should equal XOR of plaintexts.
			ct1 := ctTag1[:len(ctTag1)-TagSize]
			ct2 := ctTag2[:len(ctTag2)-TagSize]
			if len(ct1) != len(ct2) {
				t.Fatal("ciphertext lengths differ")
			}

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
	vf := loadTestVectors(t)

	for _, vec := range vf.AEAD.Vectors {
		if !vec.Checks.SwapNonceAD {
			continue
		}
		t.Run(vec.ID+"_"+vec.Title, func(t *testing.T) {
			key := mustHex(t, vec.KeyHex)
			nonce := mustHex(t, vec.NonceHex)
			ad := mustHex(t, vec.ADHex)
			pt := makeAEADPlaintext(vec.Message)

			// Normal seal.
			a := New(key, len(nonce))
			ctTag := a.Seal(nil, nonce, pt, ad)
			if got, want := hex.EncodeToString(ctTag), vec.Expected.CtTagHex; got != want {
				t.Errorf("normal ct_tag = %s, want %s", got, want)
			}

			// Swapped: use AD as nonce and nonce as AD (same lengths in this vector).
			aSwap := New(key, len(ad))
			swapCtTag := aSwap.Seal(nil, ad, pt, nonce)
			if got, want := hex.EncodeToString(swapCtTag), vec.Expected.SwapNonceADCtTagHex; got != want {
				t.Errorf("swap ct_tag = %s, want %s", got, want)
			}

			// Must differ.
			if bytes.Equal(ctTag, swapCtTag) {
				t.Error("swapped nonce/AD produced same ciphertext")
			}
		})
	}
}

func TestAEADEmptyVsZeroByteAD(t *testing.T) {
	vf := loadTestVectors(t)

	for _, vec := range vf.AEAD.Vectors {
		if !vec.Checks.ADEmptyVsZeroByte {
			continue
		}
		t.Run(vec.ID+"_"+vec.Title, func(t *testing.T) {
			key := mustHex(t, vec.KeyHex)
			nonce := mustHex(t, vec.NonceHex)
			pt := makeAEADPlaintext(vec.Message)

			a := New(key, len(nonce))

			// Empty AD.
			ctTag := a.Seal(nil, nonce, pt, nil)
			if got, want := hex.EncodeToString(ctTag), vec.Expected.CtTagHex; got != want {
				t.Errorf("empty AD ct_tag = %s, want %s", got, want)
			}

			// Alt AD (0x00).
			altAD := mustHex(t, vec.AltADHex)
			altCtTag := a.Seal(nil, nonce, pt, altAD)
			if got, want := hex.EncodeToString(altCtTag), vec.Expected.AltADCtTagHex; got != want {
				t.Errorf("alt AD ct_tag = %s, want %s", got, want)
			}

			// Must differ.
			if bytes.Equal(ctTag, altCtTag) {
				t.Error("empty AD and zero-byte AD produced same ciphertext")
			}
		})
	}
}
