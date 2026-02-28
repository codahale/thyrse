// Package testdata provides a deterministic random bit generator for testing.
package testdata

import (
	"crypto/sha3"
	"io"

	"github.com/gtank/ristretto255"
)

// DRBG is a deterministic random bit generator based on SHAKE128.
type DRBG struct {
	h *sha3.SHAKE
}

// New returns a new DRBG instance initialized with the given customization string.
func New(customization string) *DRBG {
	h := sha3.NewSHAKE128()
	_, _ = h.Write([]byte(customization))
	return &DRBG{h}
}

// KeyPair returns a deterministic Ristretto255 key pair from the DRBG.
func (d *DRBG) KeyPair() (*ristretto255.Scalar, *ristretto255.Element) {
	x, _ := ristretto255.NewScalar().SetUniformBytes(d.Data(64))
	y := ristretto255.NewIdentityElement().ScalarBaseMult(x)
	return x, y
}

// Data returns n bytes of deterministic data from the DRBG.
func (d *DRBG) Data(n int) []byte {
	b := make([]byte, n)
	_, _ = d.h.Read(b)
	return b
}

// Reader returns pseudorandom reader seeded with a value from this DRBG.
func (d *DRBG) Reader() io.Reader {
	h := sha3.NewSHAKE128()
	_, _ = h.Write(d.Data(32))
	return h
}
