// Package aestream provides a streaming authenticated encryption scheme on top of a thyrse.Protocol.
//
// A stream of data is broken up into a sequence of blocks.
//
// The writer encodes each block's length as a 2-byte big endian integer, seals that header, seals the block, and
// writes both to the wrapped writer. An empty block is used to mark the end of the stream when the writer is closed. A
// block may be at most 2^16-1 bytes long (65,535 bytes).
//
// The reader reads the sealed header, opens it, decodes it into a block length, reads an encrypted block of that
// length and its authentication tag, then opens the sealed block. When it encounters the empty block, it returns EOF.
// If the stream terminates before that, an invalid ciphertext error is returned.
package aestream

import (
	"encoding/binary"
	"errors"
	"io"
	"slices"

	"github.com/codahale/thyrse"
)

// MaxBlockSize is the maximum size of an aestream block, in bytes. Writes larger than this broken up into blocks of
// this size.
const MaxBlockSize = 1<<16 - 1

// Writer encrypts written data in blocks, ensuring both confidentiality and authenticity.
type Writer struct {
	p      *thyrse.Protocol
	w      io.Writer
	buf    []byte
	closed bool
}

// NewWriter wraps the given thyrse.Protocol and io.Writer with a streaming authenticated encryption writer.
//
// The returned io.WriteCloser MUST be closed for the encrypted stream to be valid. The provided thyrse.Protocol MUST
// NOT be used while the writer is open.
//
// For maximum throughput and transmission efficiency, the use of a bufio.Writer wrapper is strongly recommended.
// Unbuffered writes will result in blocks the length of each write, rather than blocks of the maximum size.
func NewWriter(p *thyrse.Protocol, w io.Writer) *Writer {
	return &Writer{
		p:      p,
		w:      w,
		buf:    make([]byte, 0, 1024),
		closed: false,
	}
}

func (s *Writer) Write(p []byte) (n int, err error) {
	if len(p) == 0 {
		return 0, nil
	}

	total := len(p)
	for len(p) > 0 {
		blockLen := min(len(p), MaxBlockSize)
		err = s.sealAndWrite(p[:blockLen])
		if err != nil {
			return total - len(p), err
		}
		p = p[blockLen:]
	}

	return total, nil
}

// Close ends the stream with a terminal block, ensuring no further writes can be made to the stream.
func (s *Writer) Close() error {
	if s.closed {
		return nil
	}
	s.closed = true

	// Encode and seal a header for a zero-length block.
	if err := s.sealAndWrite(nil); err != nil {
		return err
	}
	return nil
}

func (s *Writer) sealAndWrite(p []byte) error {
	// Encode a header with a 2-byte big endian block length and mask it.
	s.buf = slices.Grow(s.buf[:0], headerSize+len(p)+thyrse.TagSize)
	header := binary.BigEndian.AppendUint16(s.buf[:0], uint16(len(p)))
	block := s.p.Mask("header", header[:0], header)

	// Seal the block, append it to the header block, and send it.
	block = s.p.Seal("block", block, p)
	if _, err := s.w.Write(block); err != nil {
		return err
	}

	// Ratchet for forward secrecy.
	s.p.Ratchet("block")

	return nil
}

// Reader decrypts written data in blocks, ensuring both confidentiality and authenticity.
type Reader struct {
	p             *thyrse.Protocol
	r             io.Reader
	buf, blockBuf []byte
	eos           bool
}

// NewReader wraps the given thyrse.Protocol and io.Reader with a streaming authenticated encryption reader. See
// the NewWriter documentation for details.
//
// If the stream has been modified or truncated, a thyrse.ErrInvalidCiphertext is returned.
//
// The provided thyrse.Protocol MUST NOT be used while the reader is open.
func NewReader(p *thyrse.Protocol, r io.Reader) *Reader {
	return &Reader{
		p:        p,
		r:        r,
		buf:      make([]byte, 0, 1024),
		blockBuf: nil,
		eos:      false,
	}
}

func (o *Reader) Read(p []byte) (n int, err error) {
	if len(p) == 0 {
		return 0, nil
	}

	for {
		// If a block is buffer, satisfy the read with that.
		if len(o.blockBuf) > 0 {
			n = min(len(o.blockBuf), len(p))
			copy(p, o.blockBuf[:n])
			o.blockBuf = o.blockBuf[n:]
			return n, nil
		}

		// If the stream is closed, return EOF.
		if o.eos {
			return 0, io.EOF
		}

		// Read and unmask the header and decode the block length.
		header, err := o.read(headerSize)
		if err != nil {
			return 0, err
		}
		header = o.p.Unmask("header", header[:0], header)
		blockLen := int(binary.BigEndian.Uint16(header))

		// Read and open the block.
		block, err := o.read(blockLen + thyrse.TagSize)
		if err != nil {
			return 0, err
		}
		block, err = o.p.Open("block", block[:0], block)
		if err != nil {
			return 0, err
		}
		o.eos = len(block) == 0
		o.blockBuf = block

		// Ratchet for forward secrecy.
		o.p.Ratchet("block")
	}
}

func (o *Reader) read(n int) ([]byte, error) {
	o.buf = slices.Grow(o.buf[:0], n)
	data := o.buf[:n]
	_, err := io.ReadFull(o.r, data)
	if err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return nil, thyrse.ErrInvalidCiphertext
		}
		return nil, err
	}
	return data, nil
}

const headerSize = 2

var (
	_ io.WriteCloser = (*Writer)(nil)
	_ io.Reader      = (*Reader)(nil)
)
