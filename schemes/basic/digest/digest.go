// Package digest provides an implementation of a message digest (hash) using the Thyrse protocol.
package digest

import (
	"hash"

	"github.com/codahale/thyrse"
)

const (
	// UnkeyedSize is the size, in bytes, of the unkeyed hash's digest.
	UnkeyedSize = 32

	// KeyedSize is the size, in bytes, of the keyed hash's digest.
	KeyedSize = 16

	// BlockSize is the internal block size used by the digest.
	BlockSize = 8192
)

// New returns a new hash.Hash instance which uses the given domain string.
func New(domain string) hash.Hash {
	base := thyrse.New(domain)
	d := &digest{
		base: base,
		size: UnkeyedSize,
	}
	d.Reset()
	return d
}

// NewKeyed returns a new hash.Hash instance which uses the given domain string and the given key.
func NewKeyed(domain string, key []byte) hash.Hash {
	base := thyrse.New(domain)
	base.Mix("key", key)
	d := &digest{
		base: base,
		size: KeyedSize,
	}
	d.Reset()
	return d
}

type digest struct {
	base *thyrse.Protocol
	w    *thyrse.MixWriter
	size int
}

func (d *digest) Write(p []byte) (n int, err error) {
	return d.w.Write(p)
}

func (d *digest) Sum(b []byte) []byte {
	p, w := d.w.Clone()
	_ = w.Close()
	var label string
	if d.size == KeyedSize {
		label = "tag"
	} else {
		label = "digest"
	}
	return p.Derive(label, b, d.size)
}

func (d *digest) Reset() {
	p := d.base.Clone()
	d.w = p.MixWriter("message")
}

func (d *digest) Size() int {
	return d.size
}

func (d *digest) BlockSize() int {
	return BlockSize
}

var _ hash.Hash = (*digest)(nil)
