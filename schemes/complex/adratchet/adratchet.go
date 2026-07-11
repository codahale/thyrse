// Package adratchet implements an asynchronous double ratchet mechanism with Thyrse and Ristretto255.
//
// This package provides a State type that maintains send and receive states, allowing for encrypted communication with
// forward secrecy and break-in recovery. It uses ephemeral Ristretto255 keys for the asymmetric ratchet and Thyrse for
// the symmetric.
package adratchet

import (
	"crypto/rand"
	"encoding/binary"
	"maps"

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
	localRatchetDone        bool
}

const (
	// MaxSkip is the maximum number of skipped message states retained across all chains, as well as the maximum gap
	// accepted in a single chain.
	MaxSkip = 1000
	// Overhead is the number of bytes added to a message by State.SendMessage.
	Overhead = headerSize + thyrse.TagSize
)

// NewInitiator creates a new double ratchet state for the initiating party with the given base protocol, local private
// key, and peer public key. It automatically performs an initial DH ratchet step.
// Panics if either public key is the identity element.
func NewInitiator(p *thyrse.Protocol, local *ristretto255.Scalar, remote *ristretto255.Element) *State {
	localPub := ristretto255.NewIdentityElement().ScalarBaseMult(local)
	if localPub.Equal(ristretto255.NewIdentityElement()) == 1 || remote.Equal(ristretto255.NewIdentityElement()) == 1 {
		panic("adratchet: identity public key")
	}
	send, recv := p.Fork("role", []byte("initiator"), []byte("responder"))
	s := &State{
		localPriv: local,
		localPub:  localPub,
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
// Panics if either public key is the identity element.
func NewResponder(p *thyrse.Protocol, local *ristretto255.Scalar, remote *ristretto255.Element) *State {
	localPub := ristretto255.NewIdentityElement().ScalarBaseMult(local)
	if localPub.Equal(ristretto255.NewIdentityElement()) == 1 || remote.Equal(ristretto255.NewIdentityElement()) == 1 {
		panic("adratchet: identity public key")
	}
	recv, send := p.Fork("role", []byte("initiator"), []byte("responder"))
	s := &State{
		localPriv: local,
		localPub:  localPub,
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

// Ratchet performs a voluntary DH ratchet step, generating a new local key and mixing it with the remote public key into
// the sending protocol. At most one local ratchet is performed for each remote public key; additional calls are
// idempotent until a new remote key is received.
func (s *State) Ratchet() {
	if s.localRatchetDone {
		return
	}

	for {
		var b [64]byte
		if _, err := rand.Read(b[:]); err != nil {
			panic(err)
		}
		s.localPriv, _ = ristretto255.NewScalar().SetUniformBytes(b[:])
		s.localPub = ristretto255.NewIdentityElement().ScalarBaseMult(s.localPriv)
		if s.localPub.Equal(ristretto255.NewIdentityElement()) == 0 {
			break
		}
	}

	dh := ristretto255.NewIdentityElement().ScalarMult(s.localPriv, s.remotePub)
	s.send.Mix("dh", dh.Bytes())
	s.prevSendN = s.sendN
	s.sendN = 0
	s.localRatchetDone = true
}

// ReceiveMessage decrypts the given ciphertext and returns the plaintext. It handles out-of-order messages and performs
// ratchet steps as needed. State changes are committed only after the message authenticates successfully.
func (s *State) ReceiveMessage(ciphertext []byte) ([]byte, error) {
	if len(ciphertext) < Overhead {
		return nil, thyrse.ErrInvalidCiphertext
	}
	header := ciphertext[:headerSize]
	msg := ciphertext[headerSize:]

	pub, err := ristretto255.NewIdentityElement().SetCanonicalBytes(header[:32])
	if err != nil || pub.Equal(ristretto255.NewIdentityElement()) == 1 {
		return nil, thyrse.ErrInvalidCiphertext
	}
	n := binary.LittleEndian.Uint32(header[32:36])
	pn := binary.LittleEndian.Uint32(header[36:40])

	trial := s.clone()
	plaintext, err := trial.receiveMessage(header, msg, pub, n, pn)
	if err != nil {
		s.discard(trial)
		return nil, err
	}
	s.commit(trial)
	return plaintext, nil
}

func (s *State) receiveMessage(header, msg []byte, pub *ristretto255.Element, n, pn uint32) ([]byte, error) {
	// Check for a skipped message key.
	sk := newSK(pub, n)
	if p, ok := s.skipped[sk]; ok {
		p = p.Clone()
		p.Mix("header", header)
		plaintext, err := p.Open("message", nil, msg)
		p.Clear()
		if err != nil {
			return nil, err
		}
		delete(s.skipped, sk)
		return plaintext, nil
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
		s.localRatchetDone = false

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
	plaintext, err := p.Open("message", nil, msg)
	p.Clear()
	return plaintext, err
}

// clone returns a copy-on-write transaction. The sending and receiving
// protocols are cloned eagerly; skipped-key protocols are shared until one is
// selected, while the map itself is copied so additions and deletions remain
// local to the transaction.
func (s *State) clone() *State {
	trial := *s
	trial.send = s.send.Clone()
	trial.recv = s.recv.Clone()
	trial.skipped = make(map[skippedKey]*thyrse.Protocol, len(s.skipped))
	maps.Copy(trial.skipped, s.skipped)
	return &trial
}

// discard clears protocol states created by a failed transaction without
// invalidating skipped-key protocols still owned by the live state.
func (s *State) discard(trial *State) {
	trial.send.Clear()
	trial.recv.Clear()
	for k, p := range trial.skipped {
		if original, ok := s.skipped[k]; !ok || original != p {
			p.Clear()
		}
	}
}

// commit replaces the live state and clears protocol states that are no longer
// reachable after a successful transaction.
func (s *State) commit(trial *State) {
	s.send.Clear()
	s.recv.Clear()
	for k, p := range s.skipped {
		if next, ok := trial.skipped[k]; !ok || next != p {
			p.Clear()
		}
	}
	*s = *trial
}

func (s *State) advanceRecvChain(targetN uint32) error {
	if targetN < s.recvN {
		return nil
	}
	gap := targetN - s.recvN
	if gap > MaxSkip || len(s.skipped) > MaxSkip-int(gap) {
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
