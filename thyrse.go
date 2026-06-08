// Package thyrse implements a transcript-based cryptographic protocol framework.
package thyrse

import (
	"crypto/subtle"
	"errors"
	"fmt"

	"github.com/codahale/kt128"
	"github.com/codahale/thyrse/internal/aesgcm"
	"github.com/codahale/thyrse/internal/enc"
	"github.com/codahale/thyrse/internal/mem"
)

// TagSize is the size in bytes of the authentication tag appended by Seal. The tag is KT128 output committing to the
// transcript after the AES-GCM tag is bound, not the AES-GCM tag itself.
const TagSize = 32

// ErrInvalidCiphertext is returned by [Protocol.Open] when tag verification fails. After a failed Open, the
// protocol's transcript has diverged from the sender's because the chain frame absorbed a different tag.
var ErrInvalidCiphertext = errors.New("thyrse: authentication failed")

// Protocol is a transcript-based cryptographic protocol instance.
//
// Operations append TKDF frames to an internal transcript. Finalizing
// operations evaluate KT128 over the transcript, parse the resulting bundle, and
// reset the transcript with a chain value.
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

	cv := p.finalize(csDerive, out)
	p.resetChain(opDerive, cv[:], nil)

	return ret
}

// Ratchet irreversibly advances the protocol state for forward secrecy. No user-visible output is produced.
func (p *Protocol) Ratchet(label string) {
	p.beginFrame(opRatchet, label)
	p.endFrame()

	cv := p.finalize(csRatchet, nil)
	p.resetChain(opRatchet, cv[:], nil)
}

// Mask encrypts plaintext without authentication. The caller is responsible for authenticating the ciphertext through
// external mechanisms. The plaintext length is bound into the protocol transcript.
//
// Confidentiality requires that the transcript contains at least one unpredictable input (see [Protocol.Mix]).
func (p *Protocol) Mask(label string, dst, plaintext []byte) []byte {
	var buf [enc.MaxIntSize]byte
	p.beginFrame(opMask, label)
	_, _ = p.h.Write(enc.LeftEncode(buf[:0], uint64(len(plaintext))))
	p.endFrame()

	var keyNonce [aesgcm.KeySize + aesgcm.NonceSize]byte
	cv := p.finalize(csMask, keyNonce[:])
	key, nonce := keyNonce[:aesgcm.KeySize], keyNonce[aesgcm.KeySize:]

	ret, ciphertext := mem.SliceForAppend(dst, len(plaintext))
	tag := aesgcm.Encrypt(ciphertext, key, nonce, plaintext)
	clear(keyNonce[:])

	p.resetChain(opMask, cv[:], tag)
	return ret
}

// Unmask decrypts ciphertext encrypted with [Protocol.Mask]. Both sides must have identical transcript state at the
// point of the Mask or Unmask call.
func (p *Protocol) Unmask(label string, dst, ciphertext []byte) []byte {
	var buf [enc.MaxIntSize]byte
	p.beginFrame(opMask, label)
	_, _ = p.h.Write(enc.LeftEncode(buf[:0], uint64(len(ciphertext))))
	p.endFrame()

	var keyNonce [aesgcm.KeySize + aesgcm.NonceSize]byte
	cv := p.finalize(csMask, keyNonce[:])
	key, nonce := keyNonce[:aesgcm.KeySize], keyNonce[aesgcm.KeySize:]

	ret, plaintext := mem.SliceForAppend(dst, len(ciphertext))
	tag := aesgcm.Decrypt(plaintext, key, nonce, ciphertext)
	clear(keyNonce[:])

	p.resetChain(opMask, cv[:], tag)
	return ret
}

// Seal encrypts plaintext with authentication. Returns ciphertext with a [TagSize]-byte tag appended. The plaintext
// length is bound into the protocol transcript. Confidentiality requires that the transcript contains at least one
// unpredictable input (see [Protocol.Mix]).
func (p *Protocol) Seal(label string, dst, plaintext []byte) []byte {
	ret, out := mem.SliceForAppend(dst, len(plaintext)+TagSize)
	ciphertext, tagDst := out[:len(plaintext)], out[len(plaintext):]

	var buf [enc.MaxIntSize]byte
	p.beginFrame(opSeal, label)
	_, _ = p.h.Write(enc.LeftEncode(buf[:0], uint64(len(plaintext))))
	p.endFrame()

	var keyNonce [aesgcm.KeySize + aesgcm.NonceSize]byte
	cv := p.finalize(csSeal, keyNonce[:])
	key, nonce := keyNonce[:aesgcm.KeySize], keyNonce[aesgcm.KeySize:]

	gcmTag := aesgcm.Encrypt(ciphertext, key, nonce, plaintext)
	clear(keyNonce[:])

	// Bind the AES-GCM tag into the transcript under opSealTag, then derive the
	// wire tag (KT128 output) from that state instead of returning the AES-GCM
	// tag itself. The completed seal then chains under opSeal, keeping the
	// tag-derivation state distinct from the state subsequent operations follow.
	p.resetChain(opSealTag, cv[:], gcmTag)
	cv = p.finalize(csSeal, tagDst)
	p.resetChain(opSeal, cv[:], nil)

	return ret
}

// Open decrypts and authenticates sealed data produced by Seal. The sealed input must be ciphertext with the tag
// appended (as returned by Seal).
//
// On success, returns the plaintext. On failure, returns ErrInvalidCiphertext. The protocol's transcript diverges
// from the sender's because the chain frame absorbs the computed AES-GCM tag before verification returns.
func (p *Protocol) Open(label string, dst, sealed []byte) ([]byte, error) {
	var ct, tt []byte
	if len(sealed) < TagSize {
		tt = sealed
	} else {
		ct = sealed[:len(sealed)-TagSize]
		tt = sealed[len(sealed)-TagSize:]
	}

	var buf [enc.MaxIntSize]byte
	p.beginFrame(opSeal, label)
	_, _ = p.h.Write(enc.LeftEncode(buf[:0], uint64(len(ct))))
	p.endFrame()

	var keyNonce [aesgcm.KeySize + aesgcm.NonceSize]byte
	cv := p.finalize(csSeal, keyNonce[:])
	key, nonce := keyNonce[:aesgcm.KeySize], keyNonce[aesgcm.KeySize:]

	ret, plaintext := mem.SliceForAppend(dst, len(ct))
	gcmTag := aesgcm.Decrypt(plaintext, key, nonce, ct)
	clear(keyNonce[:])

	// Bind the expected AES-GCM tag into the transcript under opSealTag, then
	// recompute the wire tag (KT128 output) from that state and compare it
	// against the received tag. The completed open chains under opSeal.
	p.resetChain(opSealTag, cv[:], gcmTag)
	var tag [TagSize]byte
	cv = p.finalize(csSeal, tag[:])
	p.resetChain(opSeal, cv[:], nil)

	if subtle.ConstantTimeCompare(tag[:], tt) != 1 {
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

// finalize derives one KT128 output bundle for the current transcript. The
// bundle is parsed as cv || dst, where cv is always chainValueSize bytes and dst
// may be empty.
func (p *Protocol) finalize(customization []byte, dst []byte) [chainValueSize]byte {
	var cv [chainValueSize]byte
	p.h.SetCustomizationString(customization)
	_, _ = p.h.Read(cv[:])
	if len(dst) > 0 {
		_, _ = p.h.Read(dst)
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

// resetChain resets the transcript with a chain frame. The chain value is always chainValueSize bytes and the tag, when
// present, is always aesgcm.TagSize (16) bytes.
//
// The frame layout is assembled into a stack buffer and written in a single h.Write call. After h.Reset, the frame
// starts at position 0, so right_encode(frameStart) is always [0x00, 0x01].
//
// No-tag layout (75 bytes, used by Derive, Ratchet, and the completed Seal/Open under opSeal):
//
//	opChain 0x01 0x00  originOp  0x01 0x01  0x02 0x02 0x00 [chainValue: 64B]  0x00 0x01
//	╰─ writeOpLabel ─╯           ╰─LE(1)─╯ ╰─LE(512)──╯                      ╰─RE(0)─╯
//
// With-tag layout (93 bytes, used by Mask/Unmask under opMask and the Seal/Open tag binding under opSealTag):
//
//	opChain 0x01 0x00  originOp  0x01 0x02  0x02 0x02 0x00 [chainValue: 64B]  0x01 0x80 [tag: 16B]  0x00 0x01
//	╰─ writeOpLabel ─╯           ╰─LE(2)─╯ ╰─LE(512)──╯                      ╰LE(128)╯            ╰─RE(0)─╯
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
		var buf [93]byte
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
		buf[73] = 1
		buf[74] = 0x80 // left_encode(128) = [1, 0x80]
		copy(buf[75:91], tag)
		// buf[91] = 0
		buf[92] = 1 // right_encode(0)
		_, _ = p.h.Write(buf[:])
	}
}

const (
	// chainValueSize is the chain value size in bytes (H).
	chainValueSize = 64

	// Operation codes.
	opInit    = 0x01
	opMix     = 0x02
	opFork    = 0x03
	opDerive  = 0x04
	opRatchet = 0x05
	opMask    = 0x06
	opSeal    = 0x07
	opChain   = 0x08

	// opSealTag is the origin code for the chain frame Seal and Open derive the
	// wire tag from (the AES-GCM tag binding). The completed seal chains under
	// opSeal, so this intermediate, tag-derivation state stays distinct from the
	// state that subsequent operations follow.
	opSealTag = 0x09
)

var (
	csDerive  = []byte("thyrse/derive")
	csRatchet = []byte("thyrse/ratchet")
	csMask    = []byte("thyrse/mask")
	csSeal    = []byte("thyrse/seal")
)
