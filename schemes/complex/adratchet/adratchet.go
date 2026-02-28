// Package adratchet implements an asynchronous double ratchet mechanism with Thyrse and Ristretto255.
//
// This package provides a State type that maintains send and receive states, allowing for encrypted communication with
// forward secrecy and break-in recovery. It uses ephemeral Ristretto255 keys for the asymmetric ratchet and Thyrse for
// the symmetric.
package adratchet

import (
	"crypto/rand"
	"encoding/binary"

	"github.com/codahale/thyrse"
	"github.com/gtank/ristretto255"
)

// State maintains the state of an asynchronous double ratchet.
type State struct {
	localPriv               *ristretto255.Scalar
	localPub                *ristretto255.Element
	remotePub               *ristretto255.Element
	send, recv              *thyrse.Protocol
	sendN, recvN, prevSendN uint32
	skipped                 map[skippedKey]*thyrse.Protocol
}

const (
	// MaxSkip is the maximum number of messages that can be skipped in a single chain.
	MaxSkip = 1000
	// Overhead is the number of bytes added to a message by State.SendMessage.
	Overhead = headerSize + thyrse.TagSize
)

// NewInitiator creates a new double ratchet state for the initiating party with the given base protocol, local private
// key, and peer public key. It automatically performs an initial DH ratchet step.
func NewInitiator(p *thyrse.Protocol, local *ristretto255.Scalar, remote *ristretto255.Element) *State {
	branches := p.Fork("role", []byte("initiator"), []byte("responder"))
	send, recv := branches[0], branches[1]
	s := &State{
		localPriv: local,
		localPub:  ristretto255.NewIdentityElement().ScalarBaseMult(local),
		remotePub: remote,
		send:      send,
		recv:      recv,
		sendN:     0,
		recvN:     0,
		prevSendN: 0,
		skipped:   make(map[skippedKey]*thyrse.Protocol),
	}
	s.Ratchet()
	return s
}

// NewResponder creates a new double ratchet state for the responding party with the given base protocol, local private
// key, and peer public key.
func NewResponder(p *thyrse.Protocol, local *ristretto255.Scalar, remote *ristretto255.Element) *State {
	branches := p.Fork("role", []byte("initiator"), []byte("responder"))
	recv, send := branches[0], branches[1]
	s := &State{
		localPriv: local,
		localPub:  ristretto255.NewIdentityElement().ScalarBaseMult(local),
		remotePub: remote,
		send:      send,
		recv:      recv,
		sendN:     0,
		recvN:     0,
		prevSendN: 0,
		skipped:   make(map[skippedKey]*thyrse.Protocol),
	}
	return s
}

// SendMessage encrypts the given plaintext and returns the ciphertext, which includes a header with the current ratchet
// state.
func (s *State) SendMessage(plaintext []byte) []byte {
	// Encode the header.
	header := make([]byte, headerSize)
	copy(header[:32], s.localPub.Bytes())
	binary.LittleEndian.PutUint32(header[32:36], s.sendN)
	binary.LittleEndian.PutUint32(header[36:40], s.prevSendN)

	// Step the sending chain and clone it for this message.
	s.send.Mix("n", binary.LittleEndian.AppendUint32(nil, s.sendN))
	p := s.send.Clone()

	// Perform a symmetric ratchet and increment the sent messages counter.
	s.send.Ratchet("step")
	s.sendN++

	// Mix in the header and seal the message.
	p.Mix("header", header)
	return p.Seal("message", header, plaintext)
}

// Ratchet performs a voluntary DH ratchet step, generating a new local key and mixing it with the
// remote public key into the sending protocol.
func (s *State) Ratchet() {
	var b [64]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	s.localPriv, _ = ristretto255.NewScalar().SetUniformBytes(b[:])
	s.localPub = ristretto255.NewIdentityElement().ScalarBaseMult(s.localPriv)

	dh := ristretto255.NewIdentityElement().ScalarMult(s.localPriv, s.remotePub)
	s.send.Mix("dh", dh.Bytes())
	s.prevSendN = s.sendN
	s.sendN = 0
}

// ReceiveMessage decrypts the given ciphertext and returns the plaintext. It handles out-of-order messages and performs
// ratchet steps as needed.
func (s *State) ReceiveMessage(ciphertext []byte) ([]byte, error) {
	if len(ciphertext) < Overhead {
		return nil, thyrse.ErrInvalidCiphertext
	}
	header := ciphertext[:headerSize]
	msg := ciphertext[headerSize:]

	pub, err := ristretto255.NewIdentityElement().SetCanonicalBytes(header[:32])
	if err != nil {
		return nil, thyrse.ErrInvalidCiphertext
	}
	n := binary.LittleEndian.Uint32(header[32:36])
	pn := binary.LittleEndian.Uint32(header[36:40])

	// Check for a skipped message key.
	sk := newSK(pub, n)
	if p, ok := s.skipped[sk]; ok {
		delete(s.skipped, sk)
		p.Mix("header", header)
		return p.Open("message", nil, msg)
	}

	// Check for a new DH key.
	if pub.Equal(s.remotePub) == 0 {
		// Catch up on the previous receiving chain.
		if err := s.advanceRecvChain(pn); err != nil {
			return nil, err
		}

		// Perform a DH step with the old local key and the new remote key.
		dh := ristretto255.NewIdentityElement().ScalarMult(s.localPriv, pub)
		s.recv.Mix("dh", dh.Bytes())

		// Update the remote public key and reset the receiving counter.
		s.remotePub = pub
		s.recvN = 0

		// Perform a voluntary DH ratchet step.
		s.Ratchet()
	}

	// Catch up on the current receiving chain.
	if err := s.advanceRecvChain(n); err != nil {
		return nil, err
	}

	// Step the receiving chain and clone it for this message.
	s.recv.Mix("n", binary.LittleEndian.AppendUint32(nil, s.recvN))
	p := s.recv.Clone()

	// Perform a symmetric ratchet and increment the received messages counter.
	s.recv.Ratchet("step")
	s.recvN++

	// Mix in the header and open the message.
	p.Mix("header", header)
	return p.Open("message", nil, msg)
}

func (s *State) advanceRecvChain(targetN uint32) error {
	if targetN < s.recvN {
		return nil
	}
	if targetN-s.recvN > MaxSkip {
		return thyrse.ErrInvalidCiphertext
	}
	for s.recvN < targetN {
		s.recv.Mix("n", binary.LittleEndian.AppendUint32(nil, s.recvN))
		p := s.recv.Clone()
		s.skipped[newSK(s.remotePub, s.recvN)] = p
		s.recv.Ratchet("step")
		s.recvN++
	}
	return nil
}

type skippedKey struct {
	pub [32]byte
	n   uint32
}

func newSK(q *ristretto255.Element, n uint32) skippedKey {
	return skippedKey{
		pub: [32]byte(q.Bytes()),
		n:   n,
	}
}

const headerSize = 32 + 4 + 4
