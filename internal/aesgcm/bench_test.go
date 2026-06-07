package aesgcm

import (
	"crypto/aes"
	"crypto/cipher"
	"strconv"
	"testing"
)

var benchSizes = []int{16, 64, 1024, 8192, 65536}

func BenchmarkEncrypt(b *testing.B) {
	key := fill(KeySize, 1)
	nonce := fill(NonceSize, 2)
	for _, n := range benchSizes {
		pt := fill(n, int64(n))
		dst := make([]byte, 0, n)
		b.Run(strconv.Itoa(n), func(b *testing.B) {
			b.SetBytes(int64(n))
			for range b.N {
				Encrypt(dst[:0], key, nonce, pt)
			}
		})
	}
}

func BenchmarkDecrypt(b *testing.B) {
	key := fill(KeySize, 1)
	nonce := fill(NonceSize, 2)
	for _, n := range benchSizes {
		ct := fill(n, int64(n))
		dst := make([]byte, 0, n)
		b.Run(strconv.Itoa(n), func(b *testing.B) {
			b.SetBytes(int64(n))
			for range b.N {
				Decrypt(dst[:0], key, nonce, ct)
			}
		})
	}
}

// BenchmarkStdlibSealFresh rebuilds the cipher and AEAD on every operation,
// matching this package's per-operation setup cost (a fresh key per message).
func BenchmarkStdlibSealFresh(b *testing.B) {
	key := fill(KeySize, 1)
	nonce := fill(NonceSize, 2)
	for _, n := range benchSizes {
		pt := fill(n, int64(n))
		dst := make([]byte, 0, n+TagSize)
		b.Run(strconv.Itoa(n), func(b *testing.B) {
			b.SetBytes(int64(n))
			for range b.N {
				block, _ := aes.NewCipher(key)
				aead, _ := cipher.NewGCM(block)
				aead.Seal(dst[:0], nonce, pt, nil)
			}
		})
	}
}
