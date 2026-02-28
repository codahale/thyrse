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

// TagSize is the truncated tag size appended by Seal (T).
const TagSize = 16

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
	_, _ = p.h.Write([]byte{opInit})
	p.writeLengthEncode([]byte(label))
	return &p
}

func (p *Protocol) String() string {
	return fmt.Sprintf("Protocol(%s)", p.initLabel)
}

// Mix absorbs data into the protocol transcript. Use for key material, nonces, associated data, and any protocol input
// that fits in memory.
func (p *Protocol) Mix(label string, data []byte) {
	_, _ = p.h.Write([]byte{opMix})
	p.writeLengthEncode([]byte(label))
	p.writeLengthEncode(data)
}

// MixStream absorbs streaming data by pre-hashing through KT128. The Init label is used as the KT128 customization
// string, binding the digest to the protocol identity.
func (p *Protocol) MixStream(label string, r io.Reader) error {
	kh := kt128.NewCustom([]byte(p.initLabel))
	if _, err := kh.ReadFrom(r); err != nil {
		return err
	}

	var digest [chainValueSize]byte
	_, _ = kh.Read(digest[:])

	_, _ = p.h.Write([]byte{opMixStream})
	p.writeLengthEncode([]byte(label))
	_, _ = p.h.Write(digest[:]) // fixed H bytes, no length prefix
	return nil
}

// Fork clones the protocol state into N independent branches and modifies the base. The base receives ordinal 0 with an
// empty value. Each clone receives ordinals 1 through N with the corresponding value. Callers must ensure clone values
// are distinct from each other.
func (p *Protocol) Fork(label string, values ...[]byte) []*Protocol {
	n := len(values)

	// Write the common prefix.
	_, _ = p.h.Write([]byte{opFork})
	p.writeLengthEncode([]byte(label))
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

	_, _ = p.h.Write([]byte{opDerive})
	p.writeLengthEncode([]byte(label))
	p.writeLeftEncode(uint64(outputLen))

	cv := p.finalize(dsDerive, out)
	p.resetChain(opDerive, cv[:], nil)

	return ret
}

// Ratchet irreversibly advances the protocol state for forward secrecy. No user-visible output is produced.
func (p *Protocol) Ratchet(label string) {
	_, _ = p.h.Write([]byte{opRatchet})
	p.writeLengthEncode([]byte(label))

	cv := p.finalize(dsRatchet, nil)
	p.resetChain(opRatchet, cv[:], nil)
}

// Mask encrypts plaintext without authentication. The caller is responsible for authenticating the ciphertext through
// external mechanisms.
//
// Confidentiality requires that the transcript contains at least one unpredictable input (see [Protocol.Mix]).
func (p *Protocol) Mask(label string, dst, plaintext []byte) []byte {
	_, _ = p.h.Write([]byte{opMask})
	p.writeLengthEncode([]byte(label))

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
	_, _ = p.h.Write([]byte{opMask})
	p.writeLengthEncode([]byte(label))

	var twKey [treewrap.KeySize]byte
	cv := p.finalize(dsMask, twKey[:])

	plaintext, tag := treewrap.DecryptAndMAC(dst, &twKey, ciphertext)
	clear(twKey[:])

	p.resetChain(opMask, cv[:], tag[:])
	return plaintext
}

// Seal encrypts plaintext with authentication. Returns ciphertext with a [TagSize]-byte tag appended. Confidentiality
// requires that the transcript contains at least one unpredictable input (see [Protocol.Mix]).
func (p *Protocol) Seal(label string, dst, plaintext []byte) []byte {
	ret, out := mem.SliceForAppend(dst, len(plaintext)+TagSize)
	ciphertext, tag := out[:len(plaintext)], out[len(plaintext):]

	_, _ = p.h.Write([]byte{opSeal})
	p.writeLengthEncode([]byte(label))

	var twKey [treewrap.KeySize]byte
	cv := p.finalize(dsSeal, twKey[:])

	ciphertext, fullTag := treewrap.EncryptAndMAC(ciphertext[:0], &twKey, plaintext)
	clear(twKey[:])

	p.resetChain(opSeal, cv[:], fullTag[:])

	copy(tag, fullTag[:TagSize])
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

	_, _ = p.h.Write([]byte{opSeal})
	p.writeLengthEncode([]byte(label))

	var twKey [treewrap.KeySize]byte
	cv := p.finalize(dsSeal, twKey[:])

	plaintext, fullTag := treewrap.DecryptAndMAC(dst, &twKey, ct)
	clear(twKey[:])

	p.resetChain(opSeal, cv[:], fullTag[:])

	if subtle.ConstantTimeCompare(fullTag[:TagSize], tt) != 1 {
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

// resetChain resets the transcript with a CHAIN frame.
func (p *Protocol) resetChain(originOp byte, chainValue, tag []byte) {
	p.h.Reset(dsChain)
	_, _ = p.h.Write([]byte{opChain, originOp})

	if len(tag) == 0 {
		p.writeLeftEncode(1)
	} else {
		p.writeLeftEncode(2)
	}

	p.writeLengthEncode(chainValue)

	if len(tag) > 0 {
		p.writeLengthEncode(tag)
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
	p.writeLeftEncode(uint64(len(data)))
	if len(data) > 0 {
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
