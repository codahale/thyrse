// Package oae2 provides an Online Authenticated Encryption (OAE2) stream implementation.
//
// OAE2 allows for secure streaming of data with a fixed block size, providing confidentiality, integrity, and
// authenticity. It protects against truncation, tampering, and block-reordering attacks by using a stateful
// cryptographic protocol to authenticate each block in sequence.
package oae2

import (
	"errors"
	"io"

	"github.com/codahale/thyrse"
)

// A Writer buffers and encrypts data into discrete blocks, writing them to an underlying io.Writer.
//
// It provides OAE2-secure streaming by using a thyrse.Protocol to seal each block of data. The stream is finalized
// when Close is called.
type Writer struct {
	p         *thyrse.Protocol
	w         io.Writer
	blockSize int
	buf       []byte // plaintext accumulator, flushed when it reaches blockSize
	closed    bool   // true after Close returns, makes Close idempotent
	err       error  // sticky write error; once set, all further operations fail
}

// NewWriter returns an io.WriteCloser that buffers written data into blocks of the given size.
//
// Each block is encrypted and authenticated using the provided protocol. The protocol's prior state must be
// probabilistic to ensure OAE2 security.
//
// The returned io.WriteCloser MUST be closed for the encrypted stream to be valid. The provided thyrse.Protocol MUST
// NOT be used while the writer is open.
func NewWriter(p *thyrse.Protocol, w io.Writer, blockSize int) *Writer {
	if blockSize < 1 {
		panic("oae2: block size must be at least 1")
	}
	return &Writer{
		p:         p,
		w:         w,
		blockSize: blockSize,
		buf:       make([]byte, 0, blockSize),
	}
}

// Write writes data to the underlying io.Writer in buffered blocks.
//
// It encrypts and authenticates full blocks of size blockSize. Partial blocks are buffered until enough data is written
// or Close is called.
func (w *Writer) Write(data []byte) (n int, err error) {
	if w.closed {
		return 0, errors.New("oae2: Writer closed")
	}
	if w.err != nil {
		return 0, w.err
	}
	written := 0
	for len(data) > 0 {
		// Fill the buffer up to blockSize.
		space := w.blockSize - len(w.buf)
		toCopy := data
		if len(toCopy) > space {
			toCopy = toCopy[:space]
		}
		w.buf = append(w.buf, toCopy...)
		data = data[len(toCopy):]
		written += len(toCopy)

		// Seal and emit each full block as an intermediate "block".
		if len(w.buf) == w.blockSize {
			if err := w.flushBlock("block"); err != nil {
				return written, err
			}
		}
	}
	return written, nil
}

// Close flushes any remaining buffered data and finalizes the stream.
//
// It pads the final block with 0x80 bit padding and encrypts it with the "final" label. This must be called to properly
// finish the OAE2 stream.
func (w *Writer) Close() error {
	if w.closed {
		return nil
	}
	w.closed = true

	if w.err != nil {
		return w.err
	}
	// Apply 0x80 bit padding to encode the plaintext length.
	w.buf = pad(w.buf, w.blockSize)

	// Seal the padded final block with a distinct label to prevent truncation.
	return w.flushBlock("final")
}

// flushBlock seals the buffer with the given label and writes the ciphertext.
func (w *Writer) flushBlock(label string) error {
	ciphertext := w.p.Seal(label, nil, w.buf)
	_, err := w.w.Write(ciphertext)
	if err != nil {
		w.err = err
		return err
	}
	w.buf = w.buf[:0]
	return nil
}

// A Reader transparently reads and authenticates an OAE2-secure stream from an underlying io.Reader.
//
// It buffers the decrypted plaintext and returns it as requested, ensuring that any tampering, reordering, or
// truncation of the underlying ciphertext results in an error.
type Reader struct {
	p         *thyrse.Protocol
	r         io.Reader
	blockSize int
	buf       []byte // decrypted plaintext not yet returned to the caller
	err       error
	next      []byte // current ciphertext block buffer (reused across fills)
	ahead     []byte // one-block-ahead lookahead buffer (swapped with next)
	nextN     int    // valid bytes in next; 0 means next is empty
	final     bool   // true after the "final"-labeled block has been opened
}

// NewReader returns an io.Reader that reads and opens the data sealed by a Writer.
//
// The protocol state provided must be exactly synchronized with the protocol state used to initialize the Writer.
//
// If the stream has been modified or truncated, a thyrse.ErrInvalidCiphertext is returned. The provided
// thyrse.Protocol MUST NOT be used while the reader is open.
func NewReader(p *thyrse.Protocol, r io.Reader, blockSize int) *Reader {
	if blockSize < 1 {
		panic("oae2: block size must be at least 1")
	}
	cipherLen := blockSize + thyrse.TagSize
	return &Reader{
		p:         p,
		r:         r,
		blockSize: blockSize,
		next:      make([]byte, cipherLen),
		ahead:     make([]byte, cipherLen),
	}
}

// Read reads and decrypts data from the underlying OAE2 stream.
//
// It returns io.EOF when the stream is fully read and authenticated. If the stream is tampered with, truncated, or
// incorrectly formatted, it returns thyrse.ErrInvalidCiphertext.
func (r *Reader) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}

	// Drain any buffered plaintext before reading more ciphertext.
	if len(r.buf) > 0 {
		n := copy(p, r.buf)
		r.buf = r.buf[n:]
		return n, nil
	}
	if r.err != nil {
		return 0, r.err
	}

	// Decrypt the next block. An error is deferred if plaintext is available.
	err := r.fill()
	if err != nil {
		r.err = err
		if len(r.buf) == 0 {
			return 0, err
		}
	}

	if len(r.buf) > 0 {
		n := copy(p, r.buf)
		r.buf = r.buf[n:]
		return n, nil
	}

	return 0, r.err
}

// fill decrypts one block from the underlying reader into r.buf.
func (r *Reader) fill() error {
	if r.final {
		return io.EOF
	}

	cipherLen := r.blockSize + thyrse.TagSize

	// Bootstrap: read the first ciphertext block on the initial call.
	if r.nextN == 0 {
		if _, err := io.ReadFull(r.r, r.next[:cipherLen]); err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				return thyrse.ErrInvalidCiphertext
			}
			return err
		}
		r.nextN = cipherLen
	}

	// Peek one byte ahead to determine if this is the last block. EOF here means no more blocks follow, so the current
	// block is final.
	var peek [1]byte
	_, err := io.ReadFull(r.r, peek[:])
	isFinal := false
	if errors.Is(err, io.EOF) {
		isFinal = true
	} else if err != nil {
		return err
	}

	// Not final: read the rest of the lookahead block. A short read here means the stream was truncated mid-block.
	if !isFinal {
		r.ahead[0] = peek[0]
		if _, err := io.ReadFull(r.r, r.ahead[1:cipherLen]); err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				return thyrse.ErrInvalidCiphertext
			}
			return err
		}
	}

	// Open the current block. The label must match what the writer used; a mismatch (e.g., truncated stream) causes
	// Open to fail.
	label := "block"
	if isFinal {
		label = "final"
	}

	plaintext, err := r.p.Open(label, nil, r.next[:r.nextN])
	if err != nil {
		return err
	}

	if isFinal {
		// Strip 0x80 bit padding: scan backwards past zero bytes to find the 0x80 marker. Any other non-zero byte means
		// invalid padding.
		plaintext, err = unpad(plaintext)
		if err != nil {
			return thyrse.ErrInvalidCiphertext
		}
	}

	r.buf = plaintext
	if isFinal {
		r.nextN = 0
		r.final = true
	} else {
		// Promote the lookahead block to current for the next call.
		r.next, r.ahead = r.ahead, r.next
		r.nextN = cipherLen
	}
	return nil

}

// pad appends 0x80 followed by zero bytes to buf until it reaches blockSize.
func pad(buf []byte, blockSize int) []byte {
	buf = append(buf, 0x80)
	if len(buf) < blockSize {
		buf = append(buf, make([]byte, blockSize-len(buf))...)
	}
	return buf
}

// unpad strips trailing zero bytes and the 0x80 marker, returning the original plaintext.
func unpad(plaintext []byte) ([]byte, error) {
	for i := len(plaintext) - 1; i >= 0; i-- {
		if plaintext[i] == 0x80 {
			return plaintext[:i], nil
		} else if plaintext[i] != 0x00 {
			return nil, errInvalidPadding
		}
	}
	return nil, errInvalidPadding
}

var errInvalidPadding = errors.New("invalid padding")

var (
	_ io.WriteCloser = (*Writer)(nil)
	_ io.Reader      = (*Reader)(nil)
)
