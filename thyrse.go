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
// transcript after the GMAC tag is bound, not the GMAC tag itself.
const TagSize = 32

// ErrInvalidCiphertext is returned by [Protocol.Open] when tag verification fails. After a failed Open, the
// protocol's transcript has diverged from the sender's because the chain frame absorbed a different tag.
var ErrInvalidCiphertext = errors.New("thyrse: authentication failed")

// Protocol is a transcript-based cryptographic protocol instance.
//
// Operations append frames to an internal transcript. Finalizing operations evaluate KT128 over the
// transcript, parse the resulting bundle, and reset the transcript with a chain value.
//
// Frames are parseable right to left: each frame ends with its op code byte, byte-string fields are suffixed with
// right_encode of their byte length, integers are written as right_encode directly, and counts sit to the right of
// the lists they delimit. Reading right to left from an op code, every variable-length element is therefore
// delimited by information already read, making the transcript a recoverable encoding of the operation sequence.
type Protocol struct {
	h *kt128.Hasher
}

// New creates a new protocol instance with the given label for domain separation. The label establishes the protocol
// identity: two protocols using different labels produce cryptographically independent transcripts.
func New(label string) *Protocol {
	p := &Protocol{h: kt128.New()}
	p.writeLabelOp(label, opInit)
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
	p.writeLabel(label)
	p.writeStringOp(data, opMix)
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
		clone.writeLabel(label)
		clone.writeInt(uint64(n))
		clone.writeInt(uint64(i + 1))
		clone.writeStringOp(values[i], opFork)
		clones[i] = clone
	}

	// Now write base fork frame (ordinal 0, empty value).
	p.writeLabel(label)
	p.writeInt(uint64(n))
	p.writeInt(0)
	p.writeStringOp(nil, opFork)

	return clones
}

// Derive produces pseudorandom output that is a deterministic function of the full transcript. The outputLen must be
// greater than zero; use [Protocol.Ratchet] for zero-output-length state advancement.
func (p *Protocol) Derive(label string, dst []byte, outputLen int) []byte {
	if outputLen <= 0 {
		panic("thyrse: Derive output_len must be greater than zero")
	}
	ret, out := mem.SliceForAppend(dst, outputLen)

	p.writeLabel(label)
	p.writeIntOp(uint64(outputLen), opDerive)

	cv := p.finalize(csDerive, out)
	p.resetChain(opDerive, cv[:], nil)

	return ret
}

// Ratchet irreversibly advances the protocol state for forward secrecy. No user-visible output is produced.
func (p *Protocol) Ratchet(label string) {
	p.writeLabelOp(label, opRatchet)

	cv := p.finalize(csRatchet, nil)
	p.resetChain(opRatchet, cv[:], nil)
}

// Mask encrypts plaintext without authentication. The caller is responsible for authenticating the ciphertext through
// external mechanisms. The plaintext length is bound into the protocol transcript.
//
// Confidentiality requires that the transcript contains at least one unpredictable input (see [Protocol.Mix]).
func (p *Protocol) Mask(label string, dst, plaintext []byte) []byte {
	p.writeLabel(label)
	p.writeIntOp(uint64(len(plaintext)), opMask)

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
	p.writeLabel(label)
	p.writeIntOp(uint64(len(ciphertext)), opMask)

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

	p.writeLabel(label)
	p.writeIntOp(uint64(len(plaintext)), opSeal)

	var keyNonce [aesgcm.KeySize + aesgcm.NonceSize]byte
	cv := p.finalize(csSeal, keyNonce[:])
	key, nonce := keyNonce[:aesgcm.KeySize], keyNonce[aesgcm.KeySize:]

	gcmTag := aesgcm.Encrypt(ciphertext, key, nonce, plaintext)
	clear(keyNonce[:])

	// Bind the GMAC tag into the transcript under opSealTag, then derive the
	// wire tag (KT128 output) from that state instead of returning the GMAC
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
// from the sender's because the chain frame absorbs the computed GMAC tag before verification returns.
func (p *Protocol) Open(label string, dst, sealed []byte) ([]byte, error) {
	var ct, tt []byte
	if len(sealed) < TagSize {
		tt = sealed
	} else {
		ct = sealed[:len(sealed)-TagSize]
		tt = sealed[len(sealed)-TagSize:]
	}

	p.writeLabel(label)
	p.writeIntOp(uint64(len(ct)), opSeal)

	var keyNonce [aesgcm.KeySize + aesgcm.NonceSize]byte
	cv := p.finalize(csSeal, keyNonce[:])
	key, nonce := keyNonce[:aesgcm.KeySize], keyNonce[aesgcm.KeySize:]

	ret, plaintext := mem.SliceForAppend(dst, len(ct))
	gcmTag := aesgcm.Decrypt(plaintext, key, nonce, ct)
	clear(keyNonce[:])

	// Bind the expected GMAC tag into the transcript under opSealTag, then
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
	return &Protocol{h: p.h.Clone()}
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

// writeLabel writes label || right_encode(len(label)), the leftmost field of every operation frame, in a single call
// to h.Write.
func (p *Protocol) writeLabel(label string) {
	buf := make([]byte, 0, len(label)+enc.MaxIntSize)
	buf = append(buf, label...)
	buf = enc.RightEncode(buf, uint64(len(label)))
	_, _ = p.h.Write(buf)
}

// writeLabelOp writes label || right_encode(len(label)) || op, a complete label-only frame, in a single call to
// h.Write.
func (p *Protocol) writeLabelOp(label string, op byte) {
	buf := make([]byte, 0, len(label)+enc.MaxIntSize+1)
	buf = append(buf, label...)
	buf = enc.RightEncode(buf, uint64(len(label)))
	buf = append(buf, op)
	_, _ = p.h.Write(buf)
}

// writeStringOp writes data || right_encode(len(data)) || op, a length-suffixed byte-string field closing the current
// frame. The data is written directly without copying.
func (p *Protocol) writeStringOp(data []byte, op byte) {
	var buf [enc.MaxIntSize + 1]byte
	_, _ = p.h.Write(data)
	b := enc.RightEncode(buf[:0], uint64(len(data)))
	b = append(b, op)
	_, _ = p.h.Write(b)
}

// writeInt writes right_encode(v).
func (p *Protocol) writeInt(v uint64) {
	var buf [enc.MaxIntSize]byte
	_, _ = p.h.Write(enc.RightEncode(buf[:0], v))
}

// writeIntOp writes right_encode(v) || op, an integer field closing the current frame, in a single call to h.Write.
func (p *Protocol) writeIntOp(v uint64, op byte) {
	var buf [enc.MaxIntSize + 1]byte
	b := enc.RightEncode(buf[:0], v)
	b = append(b, op)
	_, _ = p.h.Write(b)
}

// resetChain resets the transcript with a chain frame. The chain value is always chainValueSize bytes and the tag, when
// present, is always aesgcm.TagSize (16) bytes.
//
// The frame layout is assembled into a stack buffer and written in a single h.Write call. Like all frames, it reads
// right to left: the op code is last, the count of encoded values sits immediately before it, and each value's
// right-encoded byte length sits to its right. The origin op code is a raw single byte at a position fixed once the
// values are stripped, so it carries no length suffix.
//
// No-tag layout (38 bytes, used by Derive, Ratchet, and the completed Seal/Open under opSeal):
//
//	originOp [chainValue: 32B]  0x20 0x01  0x01 0x01  opChain
//	                           ╰─RE(32)─╯ ╰─RE(1)──╯
//
// With-tag layout (56 bytes, used by Mask/Unmask under opMask and the Seal/Open tag binding under opSealTag):
//
//	originOp [chainValue: 32B]  0x20 0x01  [tag: 16B]  0x10 0x01  0x02 0x01  opChain
//	                           ╰─RE(32)─╯             ╰─RE(16)─╯ ╰─RE(2)──╯
func (p *Protocol) resetChain(originOp byte, chainValue, tag []byte) {
	p.h.Reset()

	if len(tag) == 0 {
		var buf [38]byte
		buf[0] = originOp
		copy(buf[1:33], chainValue)
		buf[33] = 32 // right_encode(32) = [0x20, 0x01]
		buf[34] = 1
		buf[35] = 1 // right_encode(1) — encoded value count
		buf[36] = 1
		buf[37] = opChain
		_, _ = p.h.Write(buf[:])
	} else {
		var buf [56]byte
		buf[0] = originOp
		copy(buf[1:33], chainValue)
		buf[33] = 32 // right_encode(32) = [0x20, 0x01]
		buf[34] = 1
		copy(buf[35:51], tag)
		buf[51] = 16 // right_encode(16) = [0x10, 0x01]
		buf[52] = 1
		buf[53] = 2 // right_encode(2) — encoded value count
		buf[54] = 1
		buf[55] = opChain
		_, _ = p.h.Write(buf[:])
	}
}

const (
	// chainValueSize is the chain value size in bytes (H).
	chainValueSize = 32

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
	// wire tag from (the GMAC tag binding). The completed seal chains under
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
