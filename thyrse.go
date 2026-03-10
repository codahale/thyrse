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

	"github.com/codahale/thyrse/hazmat/treewrap"
	"github.com/codahale/thyrse/internal/kt128"
	"github.com/codahale/thyrse/internal/mem"
)

// TagSize is the tag size appended by Seal.
const TagSize = treewrap.TagSize

// ErrInvalidCiphertext is returned by [Protocol.Open] when tag verification fails. After a failed Open, the
// protocol's transcript has diverged from the sender's because the CHAIN frame absorbed a different tag.
var ErrInvalidCiphertext = errors.New("thyrse: authentication failed")

// Protocol is a transcript-based cryptographic protocol instance.
//
// Operations append TKDF frames to an internal transcript. Finalizing operations (Derive, Ratchet, Mask, Seal)
// evaluate KT128 over the transcript, derive outputs, and reset the transcript with a chain value.
type Protocol struct {
	h          *kt128.Hasher
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
		clone.writeLeftEncode(uint64(n))
		clone.writeLeftEncode(uint64(i + 1))
		clone.writeEncodeString(values[i])
		clone.endFrame()
		clones[i] = clone
	}

	// Now write base fork frame (ordinal 0, empty value).
	p.beginFrame(opFork, label)
	p.writeLeftEncode(uint64(n))
	p.writeLeftEncode(0)
	p.writeEncodeString(nil)
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

	p.beginFrame(opDerive, label)
	p.writeLeftEncode(uint64(outputLen))
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

	var twKey [treewrap.KeySize]byte
	cv := p.finalize(dsMask, twKey[:])

	ciphertext, tag := treewrap.EncryptAndMAC(dst, &twKey, plaintext)
	clear(twKey[:])

	p.resetChain(opMask, cv[:], tag[:])
	return ciphertext
}

// Unmask decrypts ciphertext encrypted with [Protocol.Mask]. Both sides must have identical transcript state at the
// point of the Mask or Unmask call.
func (p *Protocol) Unmask(label string, dst, ciphertext []byte) []byte {
	p.beginFrame(opMask, label)
	p.endFrame()

	var twKey [treewrap.KeySize]byte
	cv := p.finalize(dsMask, twKey[:])

	plaintext, tag := treewrap.DecryptAndMAC(dst, &twKey, ciphertext)
	clear(twKey[:])

	p.resetChain(opMask, cv[:], tag[:])
	return plaintext
}

// MaskStream returns a [MaskStream] for incrementally encrypting data without authentication. Write ciphertext by
// calling [MaskStream.XORKeyStream], then call [MaskStream.Close] to finalize the operation and advance the protocol
// transcript.
//
// MaskStream implements [cipher.Stream] and [io.Closer].
func (p *Protocol) MaskStream(label string) *MaskStream {
	p.beginFrame(opMask, label)
	p.endFrame()

	var twKey [treewrap.KeySize]byte
	cv := p.finalize(dsMask, twKey[:])

	ms := &MaskStream{
		p:  p,
		cv: cv,
		e:  treewrap.NewEncryptor(&twKey),
	}
	clear(twKey[:])

	return ms
}

// MaskStream incrementally encrypts data for a Mask operation. Call [MaskStream.Close] to finalize the operation on the
// associated [Protocol].
type MaskStream struct {
	p  *Protocol
	cv [chainValueSize]byte
	e  treewrap.Encryptor
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

	var twKey [treewrap.KeySize]byte
	cv := p.finalize(dsMask, twKey[:])

	us := &UnmaskStream{
		p:  p,
		cv: cv,
		d:  treewrap.NewDecryptor(&twKey),
	}
	clear(twKey[:])

	return us
}

// UnmaskStream incrementally decrypts data for an Unmask operation. Call [UnmaskStream.Close] to finalize the operation
// on the associated [Protocol].
type UnmaskStream struct {
	p  *Protocol
	cv [chainValueSize]byte
	d  treewrap.Decryptor
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
	ciphertext, tag := out[:len(plaintext)], out[len(plaintext):]

	p.beginFrame(opSeal, label)
	p.endFrame()

	var twKey [treewrap.KeySize]byte
	cv := p.finalize(dsSeal, twKey[:])

	_, fullTag := treewrap.EncryptAndMAC(ciphertext[:0], &twKey, plaintext)
	clear(twKey[:])

	p.resetChain(opSeal, cv[:], fullTag[:])

	copy(tag, fullTag[:])
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

	var twKey [treewrap.KeySize]byte
	cv := p.finalize(dsSeal, twKey[:])

	plaintext, fullTag := treewrap.DecryptAndMAC(dst, &twKey, ct)
	clear(twKey[:])

	p.resetChain(opSeal, cv[:], fullTag[:])

	if subtle.ConstantTimeCompare(fullTag[:], tt) != 1 {
		clear(plaintext)
		return nil, ErrInvalidCiphertext
	}

	return plaintext, nil
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
// For Derive, Mask, and Seal: two KT128 evaluations via [kt128.Hasher.Chain]
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
	n := len(label)
	bits := n * 8
	if bits < 256 {
		// Fast path: left_encode(bits) = [1, bits], frame is op || 1 || bits || label.
		var buf [3 + 31]byte // max n=31 when bits<256
		buf[0] = op
		buf[1] = 1
		buf[2] = byte(bits)
		copy(buf[3:], label)
		_, _ = p.h.Write(buf[:3+n])
	} else {
		_, _ = p.h.Write([]byte{op})
		p.writeEncodeString([]byte(label))
	}
}

// beginFrame records the current position and writes the operation preamble.
func (p *Protocol) beginFrame(op byte, label string) {
	p.frameStart = p.h.Pos()
	p.writeOpLabel(op, label)
}

// endFrame writes the position marker that closes the current frame.
func (p *Protocol) endFrame() {
	p.writeRightEncode(p.frameStart)
}

// resetChain resets the transcript with a CHAIN frame. The chain value is always chainValueSize bytes and the tag, when
// present, is always treewrap.TagSize bytes.
func (p *Protocol) resetChain(originOp byte, chainValue, tag []byte) {
	p.h.Reset()
	p.beginFrame(opChain, "")
	_, _ = p.h.Write([]byte{originOp})
	if len(tag) == 0 {
		p.writeLeftEncode(1)
		p.writeEncodeString(chainValue)
	} else {
		p.writeLeftEncode(2)
		p.writeEncodeString(chainValue)
		p.writeEncodeString(tag)
	}
	p.endFrame()
}

// writeLeftEncode writes left_encode(x) as defined in NIST SP 800-185.
func (p *Protocol) writeLeftEncode(x uint64) {
	var buf [9]byte

	if x == 0 {
		buf[0] = 1
		_, _ = p.h.Write(buf[:2])
		return
	}

	i := 8
	v := x
	for v > 0 {
		buf[i] = byte(v)
		v >>= 8
		i--
	}
	buf[i] = byte(8 - i)
	_, _ = p.h.Write(buf[i:9])
}

// writeRightEncode writes right_encode(x): big-endian encoding of x followed by byte count.
func (p *Protocol) writeRightEncode(x uint64) {
	var buf [9]byte

	if x == 0 {
		buf[0] = 0
		buf[1] = 1
		_, _ = p.h.Write(buf[:2])
		return
	}

	i := 7
	v := x
	for v > 0 {
		buf[i] = byte(v)
		v >>= 8
		i--
	}
	n := byte(7 - i)
	buf[8] = n
	_, _ = p.h.Write(buf[i+1 : 9])
}

// writeEncodeString writes encode_string(x) = left_encode(len(x)*8) || x (NIST SP 800-185).
func (p *Protocol) writeEncodeString(data []byte) {
	n := len(data)
	bits := uint64(n) * 8
	if n > 0 && bits < 256 {
		// Fast path: left_encode(bits) = [1, bits], batch into single write.
		var buf [2 + 31]byte // max n=31 when bits<256
		buf[0] = 1
		buf[1] = byte(bits)
		copy(buf[2:], data)
		_, _ = p.h.Write(buf[:2+n])
		return
	}
	p.writeLeftEncode(bits)
	if n > 0 {
		_, _ = p.h.Write(data)
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
