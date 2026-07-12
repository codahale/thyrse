// Package adratchet implements an asynchronous double ratchet mechanism with Thyrse and Ristretto255.
//
// DH ratchet steps alternate between the initiator and responder. A single root protocol absorbs the DH sequence and
// forks independent chain protocols; each chain in turn forks an independent protocol for every message.
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
	root                    *thyrse.Protocol
	send, recv              *thyrse.Protocol
	sendN, recvN, prevSendN uint32
	skipped                 map[skippedKey]*thyrse.Protocol
}

const (
	// MaxSkip is the maximum number of skipped message states retained across all chains, as well as the maximum gap
	// accepted in a single chain.
	MaxSkip = 1000
	// Overhead is the number of bytes added to a message by State.SendMessage.
	Overhead = headerSize + thyrse.TagSize
)

// Initiate creates a double ratchet state for the initiating party and sends the first message. The given root protocol
// is consumed by the returned state.
// Panics if either public key is the identity element.
func Initiate(
	p *thyrse.Protocol,
	local *ristretto255.Scalar,
	remote *ristretto255.Element,
	plaintext []byte,
) (*State, []byte) {
	localPub := ristretto255.NewIdentityElement().ScalarBaseMult(local)
	if localPub.Equal(ristretto255.NewIdentityElement()) == 1 || remote.Equal(ristretto255.NewIdentityElement()) == 1 {
		panic("adratchet: identity public key")
	}
	s := &State{
		localPriv: local,
		localPub:  localPub,
		remotePub: remote,
		root:      p,
		skipped:   make(map[skippedKey]*thyrse.Protocol),
	}
	s.rotateSend()
	return s, s.SendMessage(plaintext)
}

// Respond receives the initiator's first message and creates a double ratchet state for the responding party. The given
// root protocol is consumed by the returned state on success and remains unchanged on failure.
// Panics if either public key is the identity element.
func Respond(
	p *thyrse.Protocol,
	local *ristretto255.Scalar,
	remote *ristretto255.Element,
	ciphertext []byte,
) (*State, []byte, error) {
	localPub := ristretto255.NewIdentityElement().ScalarBaseMult(local)
	if localPub.Equal(ristretto255.NewIdentityElement()) == 1 || remote.Equal(ristretto255.NewIdentityElement()) == 1 {
		panic("adratchet: identity public key")
	}
	s := &State{
		localPriv: local,
		localPub:  localPub,
		remotePub: remote,
		root:      p,
		skipped:   make(map[skippedKey]*thyrse.Protocol),
	}
	plaintext, err := s.ReceiveMessage(ciphertext)
	if err != nil {
		return nil, nil, err
	}
	return s, plaintext, nil
}

// SendMessage encrypts the given plaintext and returns the ciphertext, which includes a header with the current ratchet
// state.
func (s *State) SendMessage(plaintext []byte) []byte {
	// Encode the header.
	header := make([]byte, headerSize)
	copy(header[:32], s.localPub.Bytes())
	binary.LittleEndian.PutUint32(header[32:36], s.sendN)
	binary.LittleEndian.PutUint32(header[36:40], s.prevSendN)

	// Advance the sending chain and split off this message's protocol.
	p := forkMessage(s.send, s.sendN)
	s.sendN++

	// Mix in the header and seal the message.
	p.Mix("header", header)
	ciphertext := p.Seal("message", header, plaintext)
	p.Clear()
	return ciphertext
}

// rotateSend generates the local half of the next DH ratchet step and derives
// its sending chain from the root protocol.
func (s *State) rotateSend() {
	var localPriv *ristretto255.Scalar
	var localPub *ristretto255.Element
	for {
		var b [64]byte
		if _, err := rand.Read(b[:]); err != nil {
			panic(err)
		}
		localPriv, _ = ristretto255.NewScalar().SetUniformBytes(b[:])
		localPub = ristretto255.NewIdentityElement().ScalarBaseMult(localPriv)
		if localPub.Equal(ristretto255.NewIdentityElement()) == 0 {
			break
		}
	}

	dh := ristretto255.NewIdentityElement().ScalarMult(localPriv, s.remotePub)
	chain := s.deriveChain(localPub, dh)
	if s.send != nil {
		s.send.Clear()
	}
	s.localPriv = localPriv
	s.localPub = localPub
	s.send = chain
	s.prevSendN = s.sendN
	s.sendN = 0
}

// deriveChain absorbs one DH ratchet step into the root and splits off the
// chain associated with the advertised public key.
func (s *State) deriveChain(pub, dh *ristretto255.Element) *thyrse.Protocol {
	s.root.Mix("dh", dh.Bytes())
	return s.root.ForkN("chain", pub.Bytes())[0]
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

	newRemote := pub.Equal(s.remotePub) == 0
	if newRemote {
		// Catch up on the previous receiving chain.
		if err := s.advanceRecvChain(pn); err != nil {
			return nil, err
		}

		// Derive the receiving chain from the peer's half of the next DH step.
		dh := ristretto255.NewIdentityElement().ScalarMult(s.localPriv, pub)
		chain := s.deriveChain(pub, dh)
		if s.recv != nil {
			s.recv.Clear()
		}
		s.recv = chain

		// Update the remote public key and reset the receiving counter.
		s.remotePub = pub
		s.recvN = 0
	}
	if s.recv == nil {
		return nil, thyrse.ErrInvalidCiphertext
	}

	// Catch up on the current receiving chain.
	if err := s.advanceRecvChain(n); err != nil {
		return nil, err
	}

	// Advance the receiving chain and split off this message's protocol.
	p := forkMessage(s.recv, s.recvN)
	s.recvN++

	// Mix in the header and open the message.
	p.Mix("header", header)
	plaintext, err := p.Open("message", nil, msg)
	p.Clear()
	if err != nil {
		return nil, err
	}

	// A successfully authenticated new remote key obligates the local half of
	// the next DH step. No other operation rotates the local key.
	if newRemote {
		s.rotateSend()
	}
	return plaintext, nil
}

// clone returns a copy-on-write transaction. The sending and receiving
// protocols are cloned eagerly; skipped-key protocols are shared until one is
// selected, while the map itself is copied so additions and deletions remain
// local to the transaction.
func (s *State) clone() *State {
	trial := *s
	trial.root = s.root.Clone()
	if s.send != nil {
		trial.send = s.send.Clone()
	}
	if s.recv != nil {
		trial.recv = s.recv.Clone()
	}
	trial.skipped = make(map[skippedKey]*thyrse.Protocol, len(s.skipped))
	maps.Copy(trial.skipped, s.skipped)
	return &trial
}

// discard clears protocol states created by a failed transaction without
// invalidating skipped-key protocols still owned by the live state.
func (s *State) discard(trial *State) {
	trial.root.Clear()
	if trial.send != nil {
		trial.send.Clear()
	}
	if trial.recv != nil {
		trial.recv.Clear()
	}
	for k, p := range trial.skipped {
		if original, ok := s.skipped[k]; !ok || original != p {
			p.Clear()
		}
	}
}

// commit replaces the live state and clears protocol states that are no longer
// reachable after a successful transaction.
func (s *State) commit(trial *State) {
	s.root.Clear()
	if s.send != nil {
		s.send.Clear()
	}
	if s.recv != nil {
		s.recv.Clear()
	}
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
	if s.recv == nil {
		if targetN == 0 {
			return nil
		}
		return thyrse.ErrInvalidCiphertext
	}
	gap := targetN - s.recvN
	if gap > MaxSkip || len(s.skipped) > MaxSkip-int(gap) {
		return thyrse.ErrInvalidCiphertext
	}
	for s.recvN < targetN {
		p := forkMessage(s.recv, s.recvN)
		s.skipped[newSK(s.remotePub, s.recvN)] = p
		s.recvN++
	}
	return nil
}

func forkMessage(chain *thyrse.Protocol, n uint32) *thyrse.Protocol {
	var encoded [4]byte
	binary.LittleEndian.PutUint32(encoded[:], n)
	return chain.ForkN("message", encoded[:])[0]
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
