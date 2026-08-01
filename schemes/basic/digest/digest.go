// Package digest provides an implementation of a message digest (hash) using the Thyrse protocol.
package digest

import (
	"bufio"
	"hash"

	"github.com/codahale/kt128"
	"github.com/codahale/thyrse"
)

const (
	// UnkeyedSize is the size, in bytes, of the unkeyed hash's digest.
	UnkeyedSize = 32

	// KeyedSize is the size, in bytes, of the keyed hash's digest.
	KeyedSize = 16

	// BlockSize is the internal block size used by the digest.
	BlockSize = kt128.ChunkSize

	writerBufferSize = 8 * kt128.ChunkSize
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
	p    *thyrse.Protocol
	w    *thyrse.MixWriter
	buf  *bufio.Writer
	size int
}

func (d *digest) Write(p []byte) (n int, err error) {
	return d.buf.Write(p)
}

func (d *digest) Sum(b []byte) []byte {
	if err := d.buf.Flush(); err != nil {
		panic("digest: " + err.Error())
	}
	p, w := d.w.Clone()
	_ = w.Close()
	defer p.Clear()
	var label string
	if d.size == KeyedSize {
		label = "tag"
	} else {
		label = "digest"
	}
	return p.Derive(label, b, d.size)
}

func (d *digest) Reset() {
	if d.buf != nil {
		kt128.ClearWriter(d.buf)
	}
	if d.p != nil {
		d.p.Clear()
	}
	d.p = d.base.Clone()
	d.w = d.p.MixWriter("message")
	if d.buf == nil {
		d.buf = bufio.NewWriterSize(d.w, writerBufferSize)
	} else {
		d.buf.Reset(d.w)
	}
}

func (d *digest) Size() int {
	return d.size
}

func (d *digest) BlockSize() int {
	return BlockSize
}

var _ hash.Hash = (*digest)(nil)
