// Package thyrse implements a transcript-based cryptographic protocol framework.
package thyrse

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/subtle"
	"errors"
	"fmt"

	"github.com/codahale/kt128"
	"github.com/codahale/thyrse/internal/enc"
	"github.com/codahale/thyrse/internal/mem"
)

// TagSize is the size in bytes of the authentication tag appended by Seal. The tag is KT128 output committing to the
// transcript after the ciphertext is absorbed.
const TagSize = 32

// ErrInvalidCiphertext is returned by [Protocol.Open] when tag verification fails. After a failed Open, the
// protocol's transcript has diverged from the sender's because it absorbed a different ciphertext.
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
	p := &Protocol{h: kt128.New(nil)}
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

	cv := p.finalize(out)
	p.resetChain(opDerive, cv[:])

	return ret
}

// Ratchet irreversibly advances the protocol state for forward secrecy. No user-visible output is produced.
func (p *Protocol) Ratchet(label string) {
	p.writeLabelOp(label, opRatchet)

	cv := p.finalize(nil)
	p.resetChain(opRatchet, cv[:])
}

// Mask encrypts plaintext without authentication. The caller is responsible for authenticating the ciphertext through
// external mechanisms. The plaintext length is bound into the protocol transcript and the ciphertext is absorbed into
// it, so the transcript commits collision-resistantly to the ciphertext.
//
// Confidentiality requires that the transcript contains at least one unpredictable input (see [Protocol.Mix]).
func (p *Protocol) Mask(label string, dst, plaintext []byte) []byte {
	p.writeLabel(label)
	p.writeIntOp(uint64(len(plaintext)), opMask)

	var key [keySize]byte
	cv := p.finalize(key[:])

	ret, ciphertext := mem.SliceForAppend(dst, len(plaintext))
	p.resetChain(opMask, cv[:])
	p.writeMaskedStringOp(opMaskData, key[:], ciphertext, plaintext, false)
	clear(key[:])

	return ret
}

// Unmask decrypts ciphertext encrypted with [Protocol.Mask]. Both sides must have identical transcript state at the
// point of the Mask or Unmask call.
func (p *Protocol) Unmask(label string, dst, ciphertext []byte) []byte {
	p.writeLabel(label)
	p.writeIntOp(uint64(len(ciphertext)), opMask)

	var key [keySize]byte
	cv := p.finalize(key[:])

	ret, plaintext := mem.SliceForAppend(dst, len(ciphertext))
	p.resetChain(opMask, cv[:])
	p.writeMaskedStringOp(opMaskData, key[:], plaintext, ciphertext, true)
	clear(key[:])

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

	var key [keySize]byte
	cv := p.finalize(key[:])

	// Encrypt under opSealTag, absorbing the ciphertext into the transcript, then derive the wire tag (KT128 output)
	// from that state. The completed seal then chains under opSeal, keeping the tag-derivation state distinct from the
	// state subsequent operations follow.
	p.resetChain(opSealTag, cv[:])
	p.writeMaskedStringOp(opSealData, key[:], ciphertext, plaintext, false)
	clear(key[:])

	cv = p.finalize(tagDst)
	p.resetChain(opSeal, cv[:])

	return ret
}

// Open decrypts and authenticates sealed data produced by Seal. The sealed input must be ciphertext with the tag
// appended (as returned by Seal).
//
// On success, returns the plaintext. On failure, returns ErrInvalidCiphertext. The protocol's transcript diverges
// from the sender's because it absorbs the received ciphertext before verification returns.
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

	var key [keySize]byte
	cv := p.finalize(key[:])

	// Decrypt under opSealTag, absorbing the received ciphertext into the transcript, then recompute the wire tag
	// (KT128 output) from that state and compare it against the received tag. The completed open chains under opSeal.
	ret, plaintext := mem.SliceForAppend(dst, len(ct))
	p.resetChain(opSealTag, cv[:])
	p.writeMaskedStringOp(opSealData, key[:], plaintext, ct, true)
	clear(key[:])

	var tag [TagSize]byte
	cv = p.finalize(tag[:])
	p.resetChain(opSeal, cv[:])

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
func (p *Protocol) finalize(dst []byte) [chainValueSize]byte {
	var cv [chainValueSize]byte
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

// writeMaskedStringOp encrypts (or decrypts) src under AES-128-CTR with key, writing the result to dst, and absorbs the
// ciphertext into the transcript as ciphertext || right_encode(len) || op, a length-suffixed byte-string field closing
// the current frame.
//
// Encryption and absorption are fused over windows (see [ctrWindowSize]) so a large message's working set stays bounded
// between the AES-CTR pass and the KT128 pass. When decrypting, each window's ciphertext is absorbed before it is
// overwritten with plaintext, so dst may alias src. The window size does not affect the transcript: KT128 hashes the
// same byte sequence regardless of how it is chunked.
func (p *Protocol) writeMaskedStringOp(op byte, key, dst, src []byte, decrypt bool) {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic("thyrse: " + err.Error())
	}
	stream := cipher.NewCTR(block, zeroIV[:])

	window := ctrWindowSize(len(src))
	for off := 0; off < len(src); off += window {
		end := min(off+window, len(src))
		if decrypt {
			// Absorb the ciphertext before decrypting in place over it.
			_, _ = p.h.Write(src[off:end])
			stream.XORKeyStream(dst[off:end], src[off:end])
		} else {
			stream.XORKeyStream(dst[off:end], src[off:end])
			_, _ = p.h.Write(dst[off:end])
		}
	}

	var buf [enc.MaxIntSize + 1]byte
	b := enc.RightEncode(buf[:0], uint64(len(src)))
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

// resetChain resets the transcript with a chain frame seeded by a chainValueSize-byte chain value.
//
// The frame layout is assembled into a stack buffer and written in a single h.Write call. Like all frames, it reads
// right to left: the op code is last, the count of encoded values sits immediately before it, and each value's
// right-encoded byte length sits to its right. The origin op code is a raw single byte at a position fixed once the
// values are stripped, so it carries no length suffix.
//
// Layout (38 bytes):
//
//	originOp [chainValue: 32B]  0x20 0x01  0x01 0x01  opChain
//	                           ╰─RE(32)─╯ ╰─RE(1)──╯
func (p *Protocol) resetChain(originOp byte, chainValue []byte) {
	p.h.Reset()

	var buf [38]byte
	buf[0] = originOp
	copy(buf[1:33], chainValue)
	buf[33] = 32 // right_encode(32) = [0x20, 0x01]
	buf[34] = 1
	buf[35] = 1 // right_encode(1) — encoded value count
	buf[36] = 1
	buf[37] = opChain
	_, _ = p.h.Write(buf[:])
}

const (
	// chainValueSize is the chain value size in bytes (H).
	chainValueSize = 32

	// keySize is the AES-128 key size in bytes derived per Mask/Seal operation.
	keySize = 16

	// Operation codes.
	opInit     = 0x01
	opMix      = 0x02
	opFork     = 0x03
	opDerive   = 0x04
	opRatchet  = 0x05
	opMask     = 0x06
	opSeal     = 0x07
	opChain    = 0x08
	opMaskData = 0x0a
	opSealData = 0x0b

	// opSealTag is the origin code for the chain frame Seal and Open absorb the ciphertext into and derive the wire
	// tag from. The completed seal chains under opSeal, so this intermediate, tag-derivation state stays distinct from
	// the state that subsequent operations follow.
	opSealTag = 0x09
)

// zeroIV is the all-zero AES-CTR initial counter. A fresh key is derived per Mask/Seal operation, so a fixed counter
// start never repeats a (key, counter) pair across operations.
var zeroIV [aes.BlockSize]byte

// ctrWindowSize returns the window size in bytes over which AES-CTR encryption and KT128 absorption are interleaved for
// an n-byte message.
//
// Both AES-CTR and KT128 are compute-bound well below memory bandwidth, so keeping a window cache-resident buys little,
// while splitting a message into windows adds KT128 per-window buffering overhead. The window is therefore the whole
// message up to a cap: messages at or below the cap are encrypted and absorbed in a single pass each, and only larger
// messages are split, with the cap bounding the working set as cache-residency insurance on memory-bound platforms.
func ctrWindowSize(n int) int {
	return min(n, ctrWindowCap)
}

// ctrWindowCap is the maximum interleave window. It is a multiple of both the AES block size and the KT128 chunk size,
// and large enough to fit in the last-level cache of current hardware.
const ctrWindowCap = 1024 * 1024
