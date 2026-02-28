package mhf_test

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/codahale/thyrse/schemes/basic/mhf"
)

func ExampleHash() {
	domain := "example passwords"
	cost := uint8(10)
	password := []byte("C'est moi, le Mario")
	salt := []byte("a yellow submarine")
	n := 32
	hash := mhf.Hash(domain, cost, salt, password, nil, n)
	fmt.Printf("hash = %x\n", hash)
	// Output:
	// hash = ecfe75d90dcb797de46b64ed380cec2a01d7ab86b96157f8268f9d67fcc1e2fa
}

func TestHash(t *testing.T) {
	domain := "example passwords"
	cost := uint8(10)
	password := []byte("C'est moi, le Mario")
	salt := []byte("a yellow submarine")
	n := 32
	hash := mhf.Hash(domain, cost, salt, password, nil, n)

	t.Run("happy path", func(t *testing.T) {
		if got, want := mhf.Hash(domain, cost, salt, password, nil, n), hash; !bytes.Equal(got, want) {
			t.Errorf("Hash = %x, want = %x", got, want)
		}
	})

	t.Run("wrong domain", func(t *testing.T) {
		wrongDomain := "example crosswords"
		if got, want := mhf.Hash(wrongDomain, cost, salt, password, nil, n), hash; bytes.Equal(got, want) {
			t.Errorf("Hash = %x, want != %x", got, want)
		}
	})

	t.Run("wrong cost", func(t *testing.T) {
		wrongCost := uint8(8)
		if got, want := mhf.Hash(domain, wrongCost, salt, password, nil, n), hash; bytes.Equal(got, want) {
			t.Errorf("Hash = %x, want != %x", got, want)
		}
	})

	t.Run("wrong salt", func(t *testing.T) {
		wrongSalt := []byte("okay")
		if got, want := mhf.Hash(domain, cost, wrongSalt, password, nil, n), hash; bytes.Equal(got, want) {
			t.Errorf("Hash = %x, want != %x", got, want)
		}
	})

	t.Run("wrong password", func(t *testing.T) {
		wrongPassword := []byte("It is I, Mario")
		if got, want := mhf.Hash(domain, cost, salt, wrongPassword, nil, n), hash; bytes.Equal(got, want) {
			t.Errorf("Hash = %x, want != %x", got, want)
		}
	})

	t.Run("wrong output length", func(t *testing.T) {
		wrongN := 22
		if got, want := mhf.Hash(domain, cost, salt, password, nil, wrongN), hash; bytes.Equal(got, want) {
			t.Errorf("Hash = %x, want != %x", got, want)
		}
	})
}

// FuzzHash tests the Hash function with various inputs
func FuzzHash(f *testing.F) {
	// Add seed corpus
	f.Add("test.domain", uint8(4), []byte("salt"), []byte("password"))
	f.Add("", uint8(2), []byte(""), []byte(""))
	f.Add("app.auth", uint8(6), []byte("random-salt-123"), []byte("complex-P@ssw0rd!"))
	f.Add("long.domain.name", uint8(3), []byte("s"), []byte("very long password with spaces"))

	f.Fuzz(func(t *testing.T, domain string, cost uint8, salt, password []byte) {
		// Skip invalid parameters - cost too high will use too much memory
		if cost > 10 {
			t.Skip()
		}

		// Test that Hash doesn't panic
		hash := mhf.Hash(domain, cost, salt, password, nil, 32)

		// Verify output length
		if len(hash) != 32 {
			t.Fatalf("hash length = %d, want 32", len(hash))
		}

		// Verify determinism - same inputs should produce the same output
		hash2 := mhf.Hash(domain, cost, salt, password, nil, 32)
		if !bytes.Equal(hash, hash2) {
			t.Fatal("Hash is not deterministic")
		}

		// Different passwords should produce different hashes
		if len(password) > 0 {
			modifiedPassword := make([]byte, len(password))
			copy(modifiedPassword, password)
			modifiedPassword[0] ^= 0xFF
			hash3 := mhf.Hash(domain, cost, salt, modifiedPassword, nil, 32)
			if bytes.Equal(hash, hash3) {
				t.Fatal("Different passwords produced same hash")
			}
		}
	})
}

// FuzzHashVariableLength tests Hash with different output lengths
func FuzzHashVariableLength(f *testing.F) {
	f.Add("test", uint8(2), []byte("salt"), []byte("pass"), 16)
	f.Add("test", uint8(2), []byte("salt"), []byte("pass"), 32)
	f.Add("test", uint8(2), []byte("salt"), []byte("pass"), 64)

	f.Fuzz(func(t *testing.T, domain string, cost uint8, salt, password []byte, outputLen int) {
		// Skip invalid parameters
		if cost > 8 || outputLen < 1 || outputLen > 256 {
			t.Skip()
		}

		// Test that Hash doesn't panic with various output lengths
		hash := mhf.Hash(domain, cost, salt, password, nil, outputLen)

		// Verify output length
		if len(hash) != outputLen {
			t.Fatalf("hash length = %d, want %d", len(hash), outputLen)
		}
	})
}

// FuzzHashSaltSensitivity tests that different salts produce different outputs
func FuzzHashSaltSensitivity(f *testing.F) {
	f.Add("auth", []byte("password"), []byte("salt1"), []byte("salt2"))
	f.Add("", []byte(""), []byte{0x00}, []byte{0x01})

	f.Fuzz(func(t *testing.T, domain string, password, salt1, salt2 []byte) {
		// Skip if salts are identical
		if bytes.Equal(salt1, salt2) {
			t.Skip()
		}

		cost := uint8(2) // Small cost for fuzzing performance

		hash1 := mhf.Hash(domain, cost, salt1, password, nil, 32)
		hash2 := mhf.Hash(domain, cost, salt2, password, nil, 32)

		// Different salts should produce different hashes
		if bytes.Equal(hash1, hash2) {
			t.Fatal("Different salts produced identical hashes")
		}
	})
}

// FuzzHashCostSensitivity tests that different costs affect the output
func FuzzHashCostSensitivity(f *testing.F) {
	f.Add("test", []byte("pass"), []byte("salt"), uint8(2), uint8(3))
	f.Add("test", []byte("pass"), []byte("salt"), uint8(4), uint8(5))

	f.Fuzz(func(t *testing.T, domain string, password, salt []byte, cost1, cost2 uint8) {
		// Skip invalid or identical parameters
		if cost1 > 8 || cost2 > 8 || cost1 == cost2 {
			t.Skip()
		}

		hash1 := mhf.Hash(domain, cost1, salt, password, nil, 32)
		hash2 := mhf.Hash(domain, cost2, salt, password, nil, 32)

		// Different costs should produce different hashes
		if bytes.Equal(hash1, hash2) {
			t.Fatal("Different costs produced identical hashes")
		}
	})
}

// FuzzHashEmptyInputs tests Hash with empty or nil inputs
func FuzzHashEmptyInputs(f *testing.F) {
	f.Add(true, true, true)
	f.Add(false, true, true)
	f.Add(true, false, true)
	f.Add(true, true, false)

	f.Fuzz(func(t *testing.T, useEmptyDomain, useEmptyPassword, useEmptySalt bool) {
		domain := "test"
		if useEmptyDomain {
			domain = ""
		}

		password := []byte("password")
		if useEmptyPassword {
			password = []byte{}
		}

		salt := []byte("salt")
		if useEmptySalt {
			salt = []byte{}
		}

		cost := uint8(2)

		// Test that Hash handles empty inputs without panicking
		hash := mhf.Hash(domain, cost, salt, password, nil, 32)

		if len(hash) != 32 {
			t.Fatalf("hash length = %d, want 32", len(hash))
		}

		// Verify determinism even with empty inputs
		hash2 := mhf.Hash(domain, cost, salt, password, nil, 32)
		if !bytes.Equal(hash, hash2) {
			t.Fatal("Hash is not deterministic with empty inputs")
		}
	})
}
