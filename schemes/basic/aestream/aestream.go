// Package aestream provides a streaming authenticated encryption scheme on top of a thyrse.Protocol.
//
// A stream of data is broken up into a sequence of blocks.
//
// The writer encodes each block's length as a 4-byte big endian integer, seals that header, seals the block, and
// writes both to the wrapped writer. An empty block is used to mark the end of the stream when the writer is closed. A
// block may be at most 2^32-1 bytes long.
//
// The reader reads the sealed header, opens it, decodes it into a block length, reads an encrypted block of that
// length and its authentication tag, then opens the sealed block. When it encounters the empty block, it returns EOF.
// If the stream terminates before that, an invalid ciphertext error is returned.
//
// The stream is self-delimiting: the reader stops at the terminal block and neither reads nor authenticates any data
// following it in the underlying reader. Callers embedding a stream in a larger framing must authenticate any trailing
// data themselves.
package aestream

import (
	"encoding/binary"
	"errors"
	"io"
	"math"
	"slices"

	"github.com/codahale/thyrse"
)

// MaxBlockSize is the maximum size of an aestream block, in bytes.
const MaxBlockSize = 1<<32 - 1

// Writer encrypts written data in blocks, ensuring both confidentiality and authenticity.
type Writer struct {
	p            *thyrse.Protocol
	w            io.Writer
	maxBlockSize uint32
	buf          []byte
	closed       bool
	err          error
}

// NewWriter wraps the given thyrse.Protocol and io.Writer with a streaming authenticated encryption writer.
//
// The returned io.WriteCloser MUST be closed for the encrypted stream to be valid. The provided thyrse.Protocol MUST
// NOT be used while the writer is open.
//
// For maximum throughput and transmission efficiency, the use of a bufio.Writer wrapper is strongly recommended.
// Unbuffered writes will result in blocks the length of each write, rather than blocks of the configured maximum size.
// After an underlying write error, all subsequent writes and closes return the same error.
//
// If maxBlockSize is zero, the format maximum of [MaxBlockSize] is used.
func NewWriter(p *thyrse.Protocol, w io.Writer, maxBlockSize uint32) *Writer {
	return &Writer{
		p:            p,
		w:            w,
		maxBlockSize: normalizeMaxBlockSize(maxBlockSize),
		buf:          make([]byte, 0, 1024),
		closed:       false,
	}
}

func (s *Writer) Write(p []byte) (n int, err error) {
	if s.err != nil {
		return 0, s.err
	}
	if s.closed {
		return 0, io.ErrClosedPipe
	}
	if len(p) == 0 {
		return 0, nil
	}

	total := len(p)
	for len(p) > 0 {
		blockLen := len(p)
		if uint64(blockLen) > uint64(s.maxBlockSize) {
			blockLen = int(s.maxBlockSize)
		}
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
	if s.err != nil {
		return s.err
	}
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
	// Encode and seal a header with a 4-byte big endian block length.
	s.buf = slices.Grow(s.buf[:0], sealedHeaderSize+len(p)+thyrse.TagSize)
	header := binary.BigEndian.AppendUint32(s.buf[:0], uint32(len(p)))
	block := s.p.Seal("header", header[:0], header)

	// Seal the block, append it to the header block, and send it.
	block = s.p.Seal("block", block, p)
	n, err := s.w.Write(block)
	if err != nil {
		s.err = err
		return err
	}
	if n != len(block) {
		s.err = io.ErrShortWrite
		return s.err
	}

	return nil
}

// Reader decrypts written data in blocks, ensuring both confidentiality and authenticity.
type Reader struct {
	p             *thyrse.Protocol
	r             io.Reader
	maxBlockSize  uint32
	buf, blockBuf []byte
	eos           bool
	err           error
}

// NewReader wraps the given thyrse.Protocol and io.Reader with a streaming authenticated encryption reader. See
// the NewWriter documentation for details.
//
// If the stream has been modified or truncated, a thyrse.ErrInvalidCiphertext is returned.
//
// The provided thyrse.Protocol MUST NOT be used while the reader is open.
// After a read or authentication error, all subsequent non-empty reads return the same error.
//
// If maxBlockSize is zero, the format maximum of [MaxBlockSize] is used. An authenticated block length larger than
// the configured maximum is rejected with thyrse.ErrInvalidCiphertext before the block is read or allocated.
func NewReader(p *thyrse.Protocol, r io.Reader, maxBlockSize uint32) *Reader {
	return &Reader{
		p:            p,
		r:            r,
		maxBlockSize: normalizeMaxBlockSize(maxBlockSize),
		buf:          make([]byte, 0, 1024),
		blockBuf:     nil,
		eos:          false,
	}
}

func (o *Reader) Read(p []byte) (n int, err error) {
	if len(p) == 0 {
		return 0, nil
	}
	if o.err != nil {
		return 0, o.err
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

		// Read and open the header before trusting the encoded block length.
		header, err := o.read(sealedHeaderSize)
		if err != nil {
			o.err = err
			return 0, err
		}
		header, err = o.p.Open("header", header[:0], header)
		if err != nil {
			o.err = err
			return 0, err
		}
		blockLen := binary.BigEndian.Uint32(header)
		if blockLen > o.maxBlockSize || uint64(blockLen)+thyrse.TagSize > uint64(math.MaxInt) {
			o.err = thyrse.ErrInvalidCiphertext
			return 0, o.err
		}

		// Read and open the block.
		block, err := o.read(int(blockLen) + thyrse.TagSize)
		if err != nil {
			o.err = err
			return 0, err
		}
		block, err = o.p.Open("block", block[:0], block)
		if err != nil {
			o.err = err
			return 0, err
		}
		o.eos = len(block) == 0
		o.blockBuf = block

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

func normalizeMaxBlockSize(maxBlockSize uint32) uint32 {
	if maxBlockSize == 0 {
		return MaxBlockSize
	}
	return maxBlockSize
}

const (
	headerSize       = 4
	sealedHeaderSize = headerSize + thyrse.TagSize
)

var (
	_ io.WriteCloser = (*Writer)(nil)
	_ io.Reader      = (*Reader)(nil)
)
