// Package thyrse implements a transcript-based cryptographic protocol framework.
//
// At each finalizing operation, KT128 is evaluated over the transcript to derive keys, chain values, and pseudorandom
// output. The transcript uses TKDF encoding, which is recoverable, providing random-oracle-indifferentiable key
// derivation via the RO-KDF construction.
//
// See docs/thyrse-spec.md for the full specification.
package thyrse

import (
	"crypto/subtle"
	"errors"
	"fmt"

	"github.com/codahale/thyrse/internal/enc"
	"github.com/codahale/thyrse/internal/kt128"
	"github.com/codahale/thyrse/internal/mem"
	"github.com/codahale/thyrse/internal/tw128"
)

// TagSize is the tag size appended by Seal.
const TagSize = tw128.TagSize

// ErrInvalidCiphertext is returned by [Protocol.Open] when tag verification fails. After a failed Open, the
// protocol's transcript has diverged from the sender's because the CHAIN frame absorbed a different tag.
var ErrInvalidCiphertext = errors.New("thyrse: authentication failed")

// Protocol is a transcript-based cryptographic protocol instance.
//
// Operations append TKDF frames to an internal transcript. Finalizing operations (Derive, Ratchet, Mask, Seal)
// evaluate KT128 over the transcript, derive outputs, and reset the transcript with a chain value.
type Protocol struct {
	h          *kt128.KT128
	frameStart uint64
}

// New creates a new protocol instance with the given label for domain separation. The label establishes the protocol
// identity: two protocols using different labels produce cryptographically independent transcripts.
func New(label string) *Protocol {
	p := &Protocol{h: kt128.New()}
	p.beginFrame(opInit, label)
	p.endFrame()
	return p
}

// Equal compares the two Protocol instances in constant time, returning 1 if they are equal, 0 if not.
func (p *Protocol) Equal(other *Protocol) int {
	return p.h.Equal(other.h)
}

func (p *Protocol) String() string {
	return fmt.Sprintf("Protocol(%x)", p.Clone().Derive("test", nil, 8))
}

// Mix absorbs data into the protocol transcript. Use for key material, nonces, associated data, and any protocol input
// that fits in memory.
func (p *Protocol) Mix(label string, data []byte) {
	p.beginFrame(opMix, label)
	_, _ = p.h.Write(data)
	p.endFrame()
}

// Fork calls ForkN with the given label and values and returns the two branches.
func (p *Protocol) Fork(label string, left, right []byte) (*Protocol, *Protocol) {
	branches := p.ForkN(label, left, right)
	return branches[0], branches[1]
}

// ForkN clones the protocol state into N independent branches and modifies the base. The base receives ordinal 0 with an
// empty value. Each clone receives ordinals 1 through N with the corresponding value. Callers must ensure clone values
// are distinct from each other.
func (p *Protocol) ForkN(label string, values ...[]byte) []*Protocol {
	n := len(values)

	// Create clones BEFORE writing fork frame to base.
	clones := make([]*Protocol, n)
	for i := range n {
		clone := p.Clone()
		clone.beginFrame(opFork, label)
		_, _ = clone.h.Write(enc.LeftEncode(nil, uint64(n)))
		_, _ = clone.h.Write(enc.LeftEncode(nil, uint64(i+1)))
		_, _ = clone.h.Write(enc.EncodeString(nil, values[i]))
		clone.endFrame()
		clones[i] = clone
	}

	// Now write base fork frame (ordinal 0, empty value).
	p.beginFrame(opFork, label)
	_, _ = p.h.Write(enc.LeftEncode(nil, uint64(n)))
	_, _ = p.h.Write(enc.LeftEncode(nil, 0))
	_, _ = p.h.Write(enc.EncodeString(nil, nil))
	p.endFrame()

	return clones
}

// Derive produces pseudorandom output that is a deterministic function of the full transcript. The outputLen must be
// greater than zero; use [Protocol.Ratchet] for zero-output-length state advancement.
func (p *Protocol) Derive(label string, dst []byte, outputLen int) []byte {
	if outputLen <= 0 {
		panic("thyrse: Derive output_len must be greater than zero")
	}
	ret, out := mem.SliceForAppend(dst, outputLen)

	var buf [enc.MaxIntSize]byte
	p.beginFrame(opDerive, label)
	_, _ = p.h.Write(enc.LeftEncode(buf[:0], uint64(outputLen)))
	p.endFrame()

	cv := p.finalize(dsDerive, out)
	p.resetChain(opDerive, cv[:], nil)

	return ret
}

// Ratchet irreversibly advances the protocol state for forward secrecy. No user-visible output is produced.
func (p *Protocol) Ratchet(label string) {
	p.beginFrame(opRatchet, label)
	p.endFrame()

	cv := p.finalize(dsRatchet, nil)
	p.resetChain(opRatchet, cv[:], nil)
}

// Mask encrypts plaintext without authentication. The caller is responsible for authenticating the ciphertext through
// external mechanisms.
//
// Confidentiality requires that the transcript contains at least one unpredictable input (see [Protocol.Mix]).
func (p *Protocol) Mask(label string, dst, plaintext []byte) []byte {
	p.beginFrame(opMask, label)
	p.endFrame()

	var twKey [tw128.KeySize]byte
	cv := p.finalize(dsMask, twKey[:])

	ret, ciphertext := mem.SliceForAppend(dst, len(plaintext))
	e := tw128.NewEncryptor(twKey[:], nil, nil)
	e.XORKeyStream(ciphertext, plaintext)
	tag := e.Finalize()
	clear(twKey[:])

	p.resetChain(opMask, cv[:], tag[:])
	return ret
}

// Unmask decrypts ciphertext encrypted with [Protocol.Mask]. Both sides must have identical transcript state at the
// point of the Mask or Unmask call.
func (p *Protocol) Unmask(label string, dst, ciphertext []byte) []byte {
	p.beginFrame(opMask, label)
	p.endFrame()

	var twKey [tw128.KeySize]byte
	cv := p.finalize(dsMask, twKey[:])

	ret, plaintext := mem.SliceForAppend(dst, len(ciphertext))
	d := tw128.NewDecryptor(twKey[:], nil, nil)
	d.XORKeyStream(plaintext, ciphertext)
	tag := d.Finalize()
	clear(twKey[:])

	p.resetChain(opMask, cv[:], tag[:])
	return ret
}

// MaskStream returns a [MaskStream] for incrementally encrypting data without authentication. Write ciphertext by
// calling [MaskStream.XORKeyStream], then call [MaskStream.Close] to finalize the operation and advance the protocol
// transcript.
//
// MaskStream implements [cipher.Stream] and [io.Closer].
func (p *Protocol) MaskStream(label string) *MaskStream {
	p.beginFrame(opMask, label)
	p.endFrame()

	var twKey [tw128.KeySize]byte
	cv := p.finalize(dsMask, twKey[:])

	ms := &MaskStream{
		p:  p,
		cv: cv,
		e:  tw128.NewEncryptor(twKey[:], nil, nil),
	}
	clear(twKey[:])

	return ms
}

// MaskStream incrementally encrypts data for a Mask operation. Call [MaskStream.Close] to finalize the operation on the
// associated [Protocol].
type MaskStream struct {
	p  *Protocol
	cv [chainValueSize]byte
	e  tw128.Encryptor
}

// XORKeyStream encrypts src into dst. Dst and src must overlap entirely or not at all. Len(dst) must be >= len(src).
func (ms *MaskStream) XORKeyStream(dst, src []byte) {
	ms.e.XORKeyStream(dst, src)
}

// Close finalizes the Mask operation, advancing the protocol transcript. Close must be called exactly once.
func (ms *MaskStream) Close() error {
	tag := ms.e.Finalize()
	ms.p.resetChain(opMask, ms.cv[:], tag[:])
	return nil
}

// UnmaskStream returns an [UnmaskStream] for incrementally decrypting data. Write plaintext by calling
// [UnmaskStream.XORKeyStream], then call [UnmaskStream.Close] to finalize the operation and advance the protocol
// transcript.
//
// UnmaskStream implements [cipher.Stream] and [io.Closer].
func (p *Protocol) UnmaskStream(label string) *UnmaskStream {
	p.beginFrame(opMask, label)
	p.endFrame()

	var twKey [tw128.KeySize]byte
	cv := p.finalize(dsMask, twKey[:])

	us := &UnmaskStream{
		p:  p,
		cv: cv,
		d:  tw128.NewDecryptor(twKey[:], nil, nil),
	}
	clear(twKey[:])

	return us
}

// UnmaskStream incrementally decrypts data for an Unmask operation. Call [UnmaskStream.Close] to finalize the operation
// on the associated [Protocol].
type UnmaskStream struct {
	p  *Protocol
	cv [chainValueSize]byte
	d  tw128.Decryptor
}

// XORKeyStream decrypts src into dst. Dst and src must overlap entirely or not at all. Len(dst) must be >= len(src).
func (us *UnmaskStream) XORKeyStream(dst, src []byte) {
	us.d.XORKeyStream(dst, src)
}

// Close finalizes the Unmask operation, advancing the protocol transcript. Close must be called exactly once.
func (us *UnmaskStream) Close() error {
	tag := us.d.Finalize()
	us.p.resetChain(opMask, us.cv[:], tag[:])
	return nil
}

// Seal encrypts plaintext with authentication. Returns ciphertext with a [TagSize]-byte tag appended. Confidentiality
// requires that the transcript contains at least one unpredictable input (see [Protocol.Mix]).
func (p *Protocol) Seal(label string, dst, plaintext []byte) []byte {
	ret, out := mem.SliceForAppend(dst, len(plaintext)+TagSize)
	ciphertext, tagDst := out[:len(plaintext)], out[len(plaintext):]

	p.beginFrame(opSeal, label)
	p.endFrame()

	var twKey [tw128.KeySize]byte
	cv := p.finalize(dsSeal, twKey[:])

	e := tw128.NewEncryptor(twKey[:], nil, nil)
	e.XORKeyStream(ciphertext, plaintext)
	fullTag := e.Finalize()
	clear(twKey[:])

	p.resetChain(opSeal, cv[:], fullTag[:])

	copy(tagDst, fullTag[:])
	return ret
}

// Open decrypts and authenticates sealed data produced by Seal. The sealed input must be ciphertext with the tag
// appended (as returned by Seal).
//
// On success, returns the plaintext. On failure, returns ErrInvalidCiphertext. The protocol's transcript diverges
// from the sender's because the CHAIN frame absorbs a different computed tag.
func (p *Protocol) Open(label string, dst, sealed []byte) ([]byte, error) {
	if len(sealed) < TagSize {
		return nil, ErrInvalidCiphertext
	}

	ct := sealed[:len(sealed)-TagSize]
	tt := sealed[len(sealed)-TagSize:]

	p.beginFrame(opSeal, label)
	p.endFrame()

	var twKey [tw128.KeySize]byte
	cv := p.finalize(dsSeal, twKey[:])

	ret, plaintext := mem.SliceForAppend(dst, len(ct))
	d := tw128.NewDecryptor(twKey[:], nil, nil)
	d.XORKeyStream(plaintext, ct)
	fullTag := d.Finalize()
	clear(twKey[:])

	p.resetChain(opSeal, cv[:], fullTag[:])

	if subtle.ConstantTimeCompare(fullTag[:], tt) != 1 {
		clear(plaintext)
		return nil, ErrInvalidCiphertext
	}

	return ret, nil
}

// Clone returns an independent copy of the protocol state. The original and clone evolve independently.
func (p *Protocol) Clone() *Protocol {
	return &Protocol{h: p.h.Clone(), frameStart: p.frameStart}
}

// Clear overwrites the protocol state with zeros and invalidates the instance. After Clear, the instance must not be
// used.
func (p *Protocol) Clear() {
	p.h.Reset()
	p.h = nil
}

// finalize performs KT128 finalization.
//
// For Derive, Mask, and Seal: two KT128 evaluations via [kt128.KT128.Chain]
// produce the chain value (dsChain) and the output (outputDS) in parallel.
//
// For Ratchet: a single KT128 evaluation produces the chain value (dsRatchet).
func (p *Protocol) finalize(outputDS byte, dst []byte) [chainValueSize]byte {
	var cv [chainValueSize]byte
	if outputDS == dsRatchet {
		_, _ = p.h.ReadCustom([]byte{dsRatchet}, cv[:])
	} else {
		p.h.Chain(dsChain, cv[:], outputDS, dst)
	}
	return cv
}

// writeOpLabel writes op || encode_string(label) in a single call to h.Write.
// All protocol operations start with this preamble.
func (p *Protocol) writeOpLabel(op byte, label string) {
	buf := make([]byte, 1, 1+enc.MaxIntSize+len(label))
	buf[0] = op
	buf = enc.EncodeString(buf, []byte(label))
	_, _ = p.h.Write(buf)
}

// beginFrame records the current position and writes the operation preamble.
func (p *Protocol) beginFrame(op byte, label string) {
	p.frameStart = p.h.Pos()
	p.writeOpLabel(op, label)
}

// endFrame writes the position marker that closes the current frame.
func (p *Protocol) endFrame() {
	var buf [enc.MaxIntSize]byte
	_, _ = p.h.Write(enc.RightEncode(buf[:0], p.frameStart))
}

// resetChain resets the transcript with a CHAIN frame. The chain value is always chainValueSize bytes and the tag, when
// present, is always tw128.TagSize bytes.
//
// The frame layout is assembled into a stack buffer and written in a single h.Write call. After h.Reset, the frame
// starts at position 0, so right_encode(frameStart) is always [0x00, 0x01].
//
// No-tag layout (75 bytes, used by Derive and Ratchet):
//
//	opChain 0x01 0x00  originOp  0x01 0x01  0x02 0x02 0x00 [chainValue: 64B]  0x00 0x01
//	╰─ writeOpLabel ─╯           ╰─LE(1)─╯ ╰─LE(512)──╯                      ╰─RE(0)─╯
//
// With-tag layout (110 bytes, used by Mask and Seal):
//
//	opChain 0x01 0x00  originOp  0x01 0x02  0x02 0x02 0x00 [chainValue: 64B]  0x02 0x01 0x00 [tag: 32B]  0x00 0x01
//	╰─ writeOpLabel ─╯           ╰─LE(2)─╯ ╰─LE(512)──╯                      ╰─LE(256)──╯              ╰─RE(0)─╯
func (p *Protocol) resetChain(originOp byte, chainValue, tag []byte) {
	p.h.Reset()

	if len(tag) == 0 {
		var buf [75]byte
		buf[0] = opChain
		buf[1] = 1
		// buf[2] = 0 — left_encode(0) low byte
		buf[3] = originOp
		buf[4] = 1
		buf[5] = 1 // left_encode(1)
		buf[6] = 2
		buf[7] = 2 // left_encode(512) = [2, 2, 0]
		// buf[8] = 0
		copy(buf[9:73], chainValue)
		// buf[73] = 0 — right_encode(0) value
		buf[74] = 1 // right_encode(0) byte count
		_, _ = p.h.Write(buf[:])
	} else {
		var buf [110]byte
		buf[0] = opChain
		buf[1] = 1
		// buf[2] = 0
		buf[3] = originOp
		buf[4] = 1
		buf[5] = 2 // left_encode(2)
		buf[6] = 2
		buf[7] = 2 // left_encode(512)
		// buf[8] = 0
		copy(buf[9:73], chainValue)
		buf[73] = 2
		buf[74] = 1 // left_encode(256) = [2, 1, 0]
		// buf[75] = 0
		copy(buf[76:108], tag)
		// buf[108] = 0
		buf[109] = 1 // right_encode(0)
		_, _ = p.h.Write(buf[:])
	}
}

const (
	// chainValueSize is the chain value size in bytes (H).
	chainValueSize = 64

	// KT128 customization strings.
	dsChain   = 0x20
	dsDerive  = 0x21
	dsMask    = 0x22
	dsSeal    = 0x23
	dsRatchet = 0x24

	// Operation codes.
	opInit    = 0x01
	opMix     = 0x02
	opFork    = 0x03
	opDerive  = 0x04
	opRatchet = 0x05
	opMask    = 0x06
	opSeal    = 0x07
	opChain   = 0x08
)
