// Package tw128 implements TreeWrap128, a tree-parallel authenticated encryption algorithm built on TurboSHAKE128.
//
// It provides both bare EncryptAndMAC/DecryptAndMAC functions (delegating to the internal treewrap implementation)
// and a [crypto/cipher.AEAD] interface that adds nonce/AD-based key derivation per the spec Section 5.2.
package tw128

import (
	"crypto/cipher"
	"crypto/subtle"
	"errors"

	"github.com/codahale/thyrse/internal/enc"
	"github.com/codahale/thyrse/internal/keccak"
	"github.com/codahale/thyrse/internal/mem"
	"github.com/codahale/thyrse/internal/treewrap"
)

const (
	// KeySize is the key size in bytes.
	KeySize = treewrap.KeySize

	// TagSize is the authentication tag size in bytes.
	TagSize = treewrap.TagSize
)

// ErrOpen is returned by [AEAD.Open] when authentication fails.
var ErrOpen = errors.New("tw128: authentication failed")

// EncryptAndMAC encrypts plaintext, appends the ciphertext to dst, and returns the resulting slice along with a
// TagSize-byte authentication tag. The key MUST be unique per invocation.
func EncryptAndMAC(dst []byte, key *[KeySize]byte, plaintext []byte) ([]byte, [TagSize]byte) {
	return treewrap.EncryptAndMAC(dst, key, plaintext)
}

// DecryptAndMAC decrypts ciphertext, appends the plaintext to dst, and returns the resulting slice along with the
// expected TagSize-byte authentication tag. The caller MUST verify the tag using constant-time comparison before using
// the plaintext.
func DecryptAndMAC(dst []byte, key *[KeySize]byte, ciphertext []byte) ([]byte, [TagSize]byte) {
	return treewrap.DecryptAndMAC(dst, key, ciphertext)
}

// New returns a new [cipher.AEAD] using TreeWrap128 with the given key and nonce size.
// It panics if len(key) != KeySize or nonceSize < 1.
func New(key []byte, nonceSize int) cipher.AEAD {
	if len(key) != KeySize {
		panic("tw128: invalid key size")
	}
	if nonceSize < 1 {
		panic("tw128: nonce size must be >= 1")
	}
	a := &aead{nonceSize: nonceSize}
	copy(a.key[:], key)
	return a
}

type aead struct {
	key       [KeySize]byte
	nonceSize int
}

func (a *aead) NonceSize() int { return a.nonceSize }
func (a *aead) Overhead() int  { return TagSize }

func (a *aead) deriveKey(nonce, ad []byte) [KeySize]byte {
	var d keccak.Duplex
	d.Reset()

	// Absorb: encode_string(K) || encode_string(N) || encode_string(AD)
	// K and N are small, so batch them.
	var buf [128]byte
	b := buf[:0]
	b = enc.EncodeString(b, a.key[:])
	b = enc.EncodeString(b, nonce)
	d.Absorb(b)

	// AD may be large — encode header separately, then stream AD data.
	b = buf[:0]
	b = enc.LeftEncode(b, uint64(len(ad))*8)
	d.Absorb(b)
	d.Absorb(ad)

	d.PadPermute(0x09)

	var twKey [KeySize]byte
	d.Squeeze(twKey[:])
	return twKey
}

// Seal encrypts and authenticates plaintext with the given nonce and additional data.
func (a *aead) Seal(dst, nonce, plaintext, additionalData []byte) []byte {
	if len(nonce) != a.nonceSize {
		panic("tw128: incorrect nonce length")
	}

	twKey := a.deriveKey(nonce, additionalData)
	ret, out := mem.SliceForAppend(dst, len(plaintext)+TagSize)
	ct, tag := treewrap.EncryptAndMAC(out[:0], &twKey, plaintext)
	copy(out[:len(plaintext)], ct)
	copy(out[len(plaintext):], tag[:])

	// Clear derived key.
	for i := range twKey {
		twKey[i] = 0
	}

	return ret
}

// Open decrypts and authenticates ciphertext with the given nonce and additional data.
// Returns the decrypted plaintext, or nil and [ErrOpen] if authentication fails.
func (a *aead) Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	if len(nonce) != a.nonceSize {
		panic("tw128: incorrect nonce length")
	}
	if len(ciphertext) < TagSize {
		return nil, ErrOpen
	}

	ctLen := len(ciphertext) - TagSize
	ct := ciphertext[:ctLen]
	tag := ciphertext[ctLen:]

	twKey := a.deriveKey(nonce, additionalData)
	ret, out := mem.SliceForAppend(dst, ctLen)
	pt, gotTag := treewrap.DecryptAndMAC(out[:0], &twKey, ct)
	copy(out, pt)

	// Clear derived key.
	for i := range twKey {
		twKey[i] = 0
	}

	if subtle.ConstantTimeCompare(gotTag[:], tag) != 1 {
		// Clear plaintext on failure.
		for i := range out {
			out[i] = 0
		}
		return nil, ErrOpen
	}

	return ret, nil
}
