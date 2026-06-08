package aesgcm

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"math/rand"
	"testing"
)

// sealStdlib returns ciphertext||tag from the standard library's AES-GCM, the
// oracle this package is validated against. A nil nonce is treated as NonceSize
// zero bytes, matching this package.
func sealStdlib(t *testing.T, key, nonce, pt []byte) []byte {
	t.Helper()
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatalf("aes.NewCipher: %v", err)
	}
	if nonce == nil {
		nonce = make([]byte, NonceSize)
	}
	var aead cipher.AEAD
	if len(nonce) == NonceSize {
		aead, err = cipher.NewGCM(block)
	} else {
		aead, err = cipher.NewGCMWithNonceSize(block, len(nonce))
	}
	if err != nil {
		t.Fatalf("cipher.NewGCM: %v", err)
	}
	return aead.Seal(nil, nonce, pt, nil)
}

// checkOneShot validates a single (key, nonce, pt) against the stdlib oracle for
// both Encrypt and Decrypt.
func checkOneShot(t *testing.T, key, nonce, pt []byte) {
	t.Helper()
	want := sealStdlib(t, key, nonce, pt)
	wantCT, wantTag := want[:len(pt)], want[len(pt):]

	ct := make([]byte, len(pt))
	tag := Encrypt(ct, key, nonce, pt)
	if !bytes.Equal(ct, wantCT) {
		t.Fatalf("ciphertext mismatch\n got %x\nwant %x", ct, wantCT)
	}
	if !bytes.Equal(tag, wantTag) {
		t.Fatalf("tag mismatch\n got %x\nwant %x", tag, wantTag)
	}

	// Decrypt: expected tag must equal the real tag, plaintext must round-trip.
	gotPT := make([]byte, len(wantCT))
	expTag := Decrypt(gotPT, key, nonce, wantCT)
	if !bytes.Equal(gotPT, pt) {
		t.Fatalf("plaintext mismatch\n got %x\nwant %x", gotPT, pt)
	}
	if !bytes.Equal(expTag, wantTag) {
		t.Fatalf("expected-tag mismatch\n got %x\nwant %x", expTag, wantTag)
	}
}

var testSizes = []int{
	0, 1, 7, 15, 16, 17, 31, 32, 33, 48, 63, 64, 65,
	127, 128, 129, 191, 255, 256, 257, 1000, 4095, 4096, 4097, 16384,
}

func fill(n int, seed int64) []byte {
	b := make([]byte, n)
	rand.New(rand.NewSource(seed)).Read(b)
	return b
}

func TestVsStdlib(t *testing.T) {
	key := fill(KeySize, 1)
	nonce := fill(NonceSize, 2)
	for _, n := range testSizes {
		t.Run("", func(t *testing.T) { checkOneShot(t, key, nonce, fill(n, int64(n))) })
	}
}

func TestNilNonce(t *testing.T) {
	key := fill(KeySize, 3)
	for _, n := range testSizes {
		checkOneShot(t, key, nil, fill(n, int64(n)))
	}
}

func TestNonceSizes(t *testing.T) {
	key := fill(KeySize, 4)
	pt := fill(200, 6)
	for _, nlen := range []int{1, 4, 8, 12, 13, 15, 16, 17, 32, 64} {
		nonce := fill(nlen, int64(100+nlen))
		t.Run("", func(t *testing.T) { checkOneShot(t, key, nonce, pt) })
	}
}

// TestUnverifiedPlaintext documents that Decrypt returns unverified plaintext
// and an expected tag without performing verification: a tampered ciphertext
// still decrypts (to garbage) and the expected tag simply differs from the
// tampered tag.
func TestUnverifiedPlaintext(t *testing.T) {
	key := fill(KeySize, 11)
	nonce := fill(NonceSize, 12)
	pt := fill(64, 13)
	sealed := sealStdlib(t, key, nonce, pt)
	ct, realTag := sealed[:len(pt)], sealed[len(pt):]

	tampered := append([]byte(nil), ct...)
	tampered[0] ^= 0xff

	out := make([]byte, len(tampered))
	expTag := Decrypt(out, key, nonce, tampered)
	if bytes.Equal(expTag, realTag) {
		t.Fatal("expected tag unexpectedly matched the untampered tag")
	}
	if len(out) != len(pt) {
		t.Fatal("plaintext was not returned for tampered input")
	}
}

func TestBadKeySizePanics(t *testing.T) {
	for _, n := range []int{0, 15, 17, 24, 32} {
		func() {
			defer func() {
				if recover() == nil {
					t.Fatalf("key size %d did not panic", n)
				}
			}()
			Encrypt(nil, make([]byte, n), nil, nil)
		}()
	}
}

// TestKAT checks known-answer vectors (no additional data) from the GCM
// specification (McGrew & Viega) to anchor correctness independently of the
// stdlib oracle.
func TestKAT(t *testing.T) {
	dec := func(s string) []byte { b, _ := hex.DecodeString(s); return b }
	cases := []struct {
		key, nonce, pt, ct, tag string
	}{
		{ // Test Case 1: empty plaintext.
			key: "00000000000000000000000000000000", nonce: "000000000000000000000000",
			pt: "", ct: "", tag: "58e2fccefa7e3061367f1d57a4e7455a",
		},
		{ // Test Case 2: one zero block.
			key: "00000000000000000000000000000000", nonce: "000000000000000000000000",
			pt: "00000000000000000000000000000000", ct: "0388dace60b6a392f328c2b971b2fe78",
			tag: "ab6e47d42cec13bdf53a67b21257bddf",
		},
	}
	for i, c := range cases {
		pt := dec(c.pt)
		ct := make([]byte, len(pt))
		tag := Encrypt(ct, dec(c.key), dec(c.nonce), pt)
		if !bytes.Equal(ct, dec(c.ct)) {
			t.Errorf("case %d ciphertext\n got %x\nwant %s", i, ct, c.ct)
		}
		if !bytes.Equal(tag, dec(c.tag)) {
			t.Errorf("case %d tag\n got %x\nwant %s", i, tag, c.tag)
		}
	}
}
