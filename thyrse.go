// Package thyrse implements a transcript-based cryptographic protocol framework.
//
// At each finalizing operation, TurboSHAKE128 is evaluated over the transcript to derive keys, chain values, and
// pseudorandom output. The transcript encoding is recoverable, providing random-oracle-indifferentiable key derivation
// via the RO-KDF construction.
//
// See docs/protocol-spec.md for the full specification.
package thyrse

import (
	"crypto/subtle"
	"errors"
	"fmt"
	"io"

	"github.com/codahale/thyrse/hazmat/kt128"
	"github.com/codahale/thyrse/hazmat/treewrap"
	"github.com/codahale/thyrse/hazmat/turboshake"
	"github.com/codahale/thyrse/internal/mem"
)

// TagSize is the tag size appended by Seal.
const TagSize = treewrap.TagSize

// ErrInvalidCiphertext is returned by [Protocol.Open] when tag verification fails. The protocol instance is permanently
// desynchronized and must be discarded.
var ErrInvalidCiphertext = errors.New("thyrse: authentication failed")

// Protocol is a transcript-based cryptographic protocol instance.
//
// Operations append frames to an internal transcript. Finalizing operations (Derive, Ratchet, Mask, Seal) evaluate
// TurboSHAKE128 over the transcript, derive outputs, and reset the transcript with a chain value.
type Protocol struct {
	h         turboshake.Hasher
	initLabel string
}

// New creates a new protocol instance with the given label for domain separation. The label establishes the protocol
// identity: two protocols using different labels produce cryptographically independent transcripts.
func New(label string) *Protocol {
	var p Protocol
	p.h = turboshake.New(dsChain)
	p.initLabel = label
	p.writeOpLabel(opInit, label)
	return &p
}

// Equal compares the two Protocol instances in constant time, returning 1 if they are equal, 0 if not.
func (p *Protocol) Equal(other *Protocol) int {
	return subtle.ConstantTimeCompare([]byte(p.initLabel), []byte(other.initLabel)) &
		p.h.Equal(&other.h)
}

func (p *Protocol) String() string {
	return fmt.Sprintf("Protocol(%s)", p.initLabel)
}

// Mix absorbs data into the protocol transcript. Use for key material, nonces, associated data, and any protocol input
// that fits in memory.
func (p *Protocol) Mix(label string, data []byte) {
	p.writeOpLabel(opMix, label)
	p.writeLengthEncode(data)
}

// MixStream absorbs streaming data by pre-hashing through KT128. The Init label is used as the KT128 customization
// string, binding the digest to the protocol identity.
func (p *Protocol) MixStream(label string, r io.Reader) error {
	kh := kt128.NewCustom([]byte(p.initLabel))
	if _, err := io.Copy(kh, r); err != nil {
		return err
	}

	var digest [chainValueSize]byte
	_, _ = kh.Read(digest[:])

	p.writeOpLabel(opMixStream, label)
	p.writeLengthEncode(digest[:])
	return nil
}

// MixWriter returns a [MixWriter] for incrementally supplying the input of a MixStream operation. Write data to it in
// any number of calls, then Close it to complete the operation.
//
// To simultaneously route written data to another destination, wrap the MixWriter and the other destination in an
// [io.MultiWriter]. To mix data from an [io.Reader] while also routing it to another destination, wrap the reader with
// [io.TeeReader].
func (p *Protocol) MixWriter(label string) *MixWriter {
	return &MixWriter{
		p:     p,
		label: label,
		kh:    kt128.NewCustom([]byte(p.initLabel)),
	}
}

// MixWriter incrementally accumulates the input of a MixStream operation. Call [MixWriter.Close] to complete the
// operation on the associated [Protocol].
type MixWriter struct {
	p     *Protocol
	label string
	kh    *kt128.Hasher
}

// Write adds p to the MixStream input.
func (mw *MixWriter) Write(p []byte) (int, error) {
	return mw.kh.Write(p)
}

// Branch returns a clone of the associated [Protocol] with the MixStream operation completed using the input
// accumulated so far. The original Protocol and MixWriter remain unchanged and can continue to accumulate input.
func (mw *MixWriter) Branch() *Protocol {
	kh := mw.kh.Clone()

	var digest [chainValueSize]byte
	_, _ = kh.Read(digest[:])

	p := mw.p.Clone()
	p.writeOpLabel(opMixStream, mw.label)
	p.writeLengthEncode(digest[:])
	return p
}

// Close completes the MixStream operation, mixing the accumulated input into the protocol transcript. Close must be
// called exactly once.
func (mw *MixWriter) Close() error {
	var digest [chainValueSize]byte
	_, _ = mw.kh.Read(digest[:])

	mw.p.writeOpLabel(opMixStream, mw.label)
	mw.p.writeLengthEncode(digest[:])
	return nil
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

	// Write the common prefix.
	p.writeOpLabel(opFork, label)
	p.writeLeftEncode(uint64(n))

	// Create clones before writing base ordinal.
	clones := make([]*Protocol, n)
	for i := range n {
		clone := p.Clone()
		clone.writeLeftEncode(uint64(i + 1))
		clone.writeLengthEncode(values[i])
		clones[i] = clone
	}

	// Finalize base (ordinal 0, empty value).
	p.writeLeftEncode(0)
	p.writeLengthEncode(nil)

	return clones
}

// Derive produces pseudorandom output that is a deterministic function of the full transcript. The outputLen must be
// greater than zero; use [Protocol.Ratchet] for zero-output-length state advancement.
func (p *Protocol) Derive(label string, dst []byte, outputLen int) []byte {
	ret, out := mem.SliceForAppend(dst, outputLen)
	if outputLen <= 0 {
		panic("thyrse: Derive output_len must be greater than zero")
	}

	p.writeOpLabel(opDerive, label)
	p.writeLeftEncode(uint64(outputLen))

	cv := p.finalize(dsDerive, out)
	p.resetChain(opDerive, cv[:], nil)

	return ret
}

// Ratchet irreversibly advances the protocol state for forward secrecy. No user-visible output is produced.
func (p *Protocol) Ratchet(label string) {
	p.writeOpLabel(opRatchet, label)

	cv := p.finalize(dsRatchet, nil)
	p.resetChain(opRatchet, cv[:], nil)
}

// Mask encrypts plaintext without authentication. The caller is responsible for authenticating the ciphertext through
// external mechanisms.
//
// Confidentiality requires that the transcript contains at least one unpredictable input (see [Protocol.Mix]).
func (p *Protocol) Mask(label string, dst, plaintext []byte) []byte {
	p.writeOpLabel(opMask, label)

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
	p.writeOpLabel(opMask, label)

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
	p.writeOpLabel(opMask, label)

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
	p.writeOpLabel(opMask, label)

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

	p.writeOpLabel(opSeal, label)

	var twKey [treewrap.KeySize]byte
	cv := p.finalize(dsSeal, twKey[:])

	ciphertext, fullTag := treewrap.EncryptAndMAC(ciphertext[:0], &twKey, plaintext)
	clear(twKey[:])

	p.resetChain(opSeal, cv[:], fullTag[:])

	copy(tag, fullTag[:])
	return ret
}

// Open decrypts and authenticates sealed data produced by Seal. The sealed input must be ciphertext with the truncated
// tag appended (as returned by Seal).
//
// On success, returns the plaintext. On failure, returns ErrInvalidCiphertext, and the protocol instance is permanently
// desynchronized and must be discarded.
func (p *Protocol) Open(label string, dst, sealed []byte) ([]byte, error) {
	if len(sealed) < TagSize {
		return nil, ErrInvalidCiphertext
	}

	ct := sealed[:len(sealed)-TagSize]
	tt := sealed[len(sealed)-TagSize:]

	p.writeOpLabel(opSeal, label)

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
	return &Protocol{h: p.h, initLabel: p.initLabel}
}

// Clear overwrites the protocol state with zeros and invalidates the instance. After Clear, the instance must not be
// used.
func (p *Protocol) Clear() {
	p.h.Reset(0)
	p.initLabel = ""
}

// finalize performs the dual TurboSHAKE128 finalization in parallel using [turboshake.Chain].
//
// For Derive, Mask, and Seal: p.h (constructed with dsChain=0x20) produces the
// chain value, and the clone (finalized with outputDS) produces the output read
// into dst.
//
// For Ratchet: the clone (finalized with dsRatchet=0x24) produces the chain value;
// p.h's output is discarded.
func (p *Protocol) finalize(outputDS byte, dst []byte) [chainValueSize]byte {
	var cv [chainValueSize]byte

	oh := p.h
	if outputDS == dsRatchet {
		turboshake.Chain(&p.h, &oh, dsRatchet)
		_, _ = oh.Read(cv[:])
	} else {
		turboshake.Chain(&p.h, &oh, outputDS)
		_, _ = p.h.Read(cv[:])
		if dst != nil {
			_, _ = oh.Read(dst)
		}
	}

	return cv
}

// writeOpLabel writes op || length_encode(label) in a single call to h.Write.
// All protocol operations start with this preamble.
func (p *Protocol) writeOpLabel(op byte, label string) {
	n := len(label)
	if n < 256 {
		// Common case: left_encode(n) = [1, n], so frame is op || 1 || n || label.
		var buf [259]byte // 3 + 256
		buf[0] = op
		buf[1] = 1
		buf[2] = byte(n)
		copy(buf[3:], label)
		_, _ = p.h.Write(buf[:3+n])
	} else {
		_, _ = p.h.Write([]byte{op})
		p.writeLengthEncode([]byte(label))
	}
}

// resetChain resets the transcript with a CHAIN frame. The chain value is always chainValueSize bytes and the tag, when
// present, is always treewrap.TagSize bytes.
func (p *Protocol) resetChain(originOp byte, chainValue, tag []byte) {
	p.h.Reset(dsChain)

	// Build the entire CHAIN frame in a single stack buffer:
	//   opChain || originOp || left_encode(count) || left_encode(len(cv)) || cv
	//   [|| left_encode(len(tag)) || tag]
	const prefixLen = 6 // opChain(1) + originOp(1) + left_encode(count)(2) + left_encode(cvLen)(2)
	var buf [prefixLen + chainValueSize + 2 + 32]byte
	buf[0] = opChain
	buf[1] = originOp
	buf[2] = 1 // left_encode length prefix
	buf[4] = 1 // left_encode length prefix
	buf[5] = chainValueSize

	n := prefixLen + chainValueSize
	copy(buf[prefixLen:], chainValue)

	if len(tag) == 0 {
		buf[3] = 1 // count = 1
		_, _ = p.h.Write(buf[:n])
	} else {
		buf[3] = 2 // count = 2
		buf[n] = 1 // left_encode length prefix
		buf[n+1] = byte(len(tag))
		copy(buf[n+2:], tag)
		_, _ = p.h.Write(buf[:n+2+len(tag)])
	}
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

// writeLengthEncode writes length_encode(x) = left_encode(len(x)) || x.
func (p *Protocol) writeLengthEncode(data []byte) {
	n := len(data)
	if n > 0 && n < 128 {
		// Common case: batch left_encode(len) and data into a single write.
		var buf [130]byte // 2 + 128
		buf[0] = 1
		buf[1] = byte(n)
		copy(buf[2:], data)
		_, _ = p.h.Write(buf[:2+n])
		return
	}
	p.writeLeftEncode(uint64(n))
	if n > 0 {
		_, _ = p.h.Write(data)
	}
}

const (
	// chainValueSize is the chain value and pre-hash digest size in bytes (H).
	chainValueSize = 64

	// TurboSHAKE128 domain separation bytes.
	dsChain   = 0x20
	dsDerive  = 0x21
	dsMask    = 0x22
	dsSeal    = 0x23
	dsRatchet = 0x24

	// Operation codes.
	opInit      = 0x10
	opMix       = 0x11
	opMixStream = 0x12
	opFork      = 0x13
	opDerive    = 0x14
	opRatchet   = 0x15
	opMask      = 0x16
	opSeal      = 0x17
	opChain     = 0x18
)
