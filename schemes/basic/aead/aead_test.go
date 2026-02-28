package aead_test

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/codahale/thyrse"
	"github.com/codahale/thyrse/internal/testdata"
	"github.com/codahale/thyrse/schemes/basic/aead"
)

func TestAEAD_New(t *testing.T) {
	t.Run("panic on small nonce", func(t *testing.T) {
		defer func() {
			if recover() == nil {
				t.Error("should have panicked")
			}
		}()
		aead.New("test", make([]byte, 32), 12)
	})

	t.Run("allows larger nonces", func(t *testing.T) {
		c := aead.New("test", make([]byte, 32), 24)
		if ns := c.NonceSize(); ns != 24 {
			t.Errorf("NonceSize() = %d, want 24", ns)
		}
	})
}

func TestAEAD_NonceSize(t *testing.T) {
	c := aead.New("com.example.test", make([]byte, 32), 16)

	if got, want := c.NonceSize(), 16; got != want {
		t.Errorf("NonceSize() = %d, want %d", got, want)
	}
}

func TestAEAD_Overhead(t *testing.T) {
	c := aead.New("com.example.test", make([]byte, 32), 16)

	if got, want := c.Overhead(), thyrse.TagSize; got != want {
		t.Errorf("Overhead() = %d, want %d", got, want)
	}
}

func TestAEAD_Seal(t *testing.T) {
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	c := aead.New("com.example.test", key, 16)

	t.Run("invalid nonce size", func(t *testing.T) {
		defer func() {
			if recover() == nil {
				t.Error("should have panicked")
			}
		}()

		c.Seal(nil, make([]byte, 12), []byte("msg"), nil)
	})

	t.Run("happy path", func(t *testing.T) {
		nonce := make([]byte, c.NonceSize())
		_, _ = rand.Read(nonce)
		plaintext := []byte("Hello, world!")
		ad := []byte("header data")

		ciphertext := c.Seal(nil, nonce, plaintext, ad)

		if got, want := len(ciphertext), len(plaintext)+c.Overhead(); got != want {
			t.Errorf("len(ciphertext) = %d, want %d", got, want)
		}
	})
}

func TestAEAD_Open(t *testing.T) {
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	c := aead.New("com.example.test", key, 16)
	nonce := make([]byte, c.NonceSize())
	_, _ = rand.Read(nonce)
	plaintext := []byte("Hello, world!")
	ad := []byte("header data")
	ciphertext := c.Seal(nil, nonce, plaintext, ad)

	t.Run("happy path", func(t *testing.T) {
		decrypted, err := c.Open(nil, nonce, ciphertext, ad)
		if err != nil {
			t.Fatalf("Open failed: %v", err)
		}

		if got, want := decrypted, plaintext; !bytes.Equal(got, want) {
			t.Errorf("Open() = %q, want %q", got, want)
		}
	})

	t.Run("invalid nonce size", func(t *testing.T) {
		defer func() {
			if recover() == nil {
				t.Error("should have panicked")
			}
		}()

		_, _ = c.Open(nil, make([]byte, 12), ciphertext, ad)
	})

	t.Run("wrong key", func(t *testing.T) {
		c2 := aead.New("com.example.test", []byte("wrong key"), 16)
		if _, err := c2.Open(nil, nonce, ciphertext, ad); err == nil {
			t.Error("should have failed")
		}
	})

	t.Run("wrong domain", func(t *testing.T) {
		c2 := aead.New("wrong domain", key, 16)
		if _, err := c2.Open(nil, nonce, ciphertext, ad); err == nil {
			t.Error("should have failed")
		}
	})

	t.Run("wrong nonce", func(t *testing.T) {
		wrongNonce := make([]byte, len(nonce))
		copy(wrongNonce, nonce)
		wrongNonce[0] ^= 1
		if _, err := c.Open(nil, wrongNonce, ciphertext, ad); err == nil {
			t.Error("should have failed")
		}
	})

	t.Run("wrong AD", func(t *testing.T) {
		if _, err := c.Open(nil, nonce, ciphertext, []byte("wrong ad")); err == nil {
			t.Error("should have failed")
		}
	})

	t.Run("modified ciphertext", func(t *testing.T) {
		wrongCiphertext := make([]byte, len(ciphertext))
		copy(wrongCiphertext, ciphertext)
		wrongCiphertext[0] ^= 1
		if _, err := c.Open(nil, nonce, wrongCiphertext, ad); err == nil {
			t.Error("should have failed")
		}
	})

	t.Run("truncated ciphertext", func(t *testing.T) {
		if _, err := c.Open(nil, nonce, ciphertext[:len(ciphertext)-1], ad); err == nil {
			t.Error("should have failed")
		}
	})
}

func FuzzAEAD(f *testing.F) {
	drbg := testdata.New("thyrse aead fuzz")
	for range 10 {
		f.Add(drbg.Data(32), drbg.Data(16), drbg.Data(48), drbg.Data(16))
	}

	f.Fuzz(func(t *testing.T, key, nonce, ciphertext, ad []byte) {
		if len(nonce) < 16 {
			t.Skip()
		}

		c := aead.New("fuzz", key, len(nonce))
		v, err := c.Open(nil, nonce, ciphertext, ad)
		if err == nil {
			t.Errorf("Open(key=%x, nonce=%x, ciphertext=%x, ad=%x) = plaintext=%x, want = err", key, nonce, ciphertext, ad, v)
		}
	})
}
