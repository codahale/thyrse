// Package adratchet implements an asynchronous double ratchet mechanism with Thyrse, Ristretto255, and ML-KEM-768.
//
// Hybrid ratchet steps alternate between the initiator and responder. A single root protocol absorbs each Ristretto255
// DH and ML-KEM shared secret and forks independent chain protocols; each chain in turn forks an independent protocol
// for every message.
package adratchet

import (
	"crypto/mlkem"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"maps"

	"github.com/codahale/thyrse"
	"github.com/gtank/ristretto255"
)

// State maintains the state of an asynchronous double ratchet.
type State struct {
	localPriv               *ristretto255.Scalar
	remotePub               *ristretto255.Element
	localKEM                *mlkem.DecapsulationKey768
	remoteKEM               *mlkem.EncapsulationKey768
	localRatchet            [ratchetHeaderSize]byte
	remoteRatchet           [sha256.Size]byte
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

// Initiate creates a double ratchet state for the initiating party and sends the first message using the responder's
// Ristretto255 and ML-KEM public keys. The given root protocol is consumed by the returned state.
// Panics if the Ristretto255 public key is the identity element.
func Initiate(
	p *thyrse.Protocol,
	remote *ristretto255.Element,
	remoteKEM *mlkem.EncapsulationKey768,
	plaintext []byte,
) (*State, []byte) {
	if remote.Equal(ristretto255.NewIdentityElement()) == 1 {
		panic("adratchet: identity public key")
	}
	s := &State{
		remotePub: remote,
		remoteKEM: remoteKEM,
		root:      p,
		skipped:   make(map[skippedKey]*thyrse.Protocol),
	}
	s.rotateSend()
	return s, s.SendMessage(plaintext)
}

// Respond receives the initiator's first message using the responder's Ristretto255 and ML-KEM private keys and
// creates a double ratchet state. The given root protocol is consumed by the returned state on success and remains
// unchanged on failure.
// Returns an error if the message is invalid.
// Panics if the Ristretto255 private key produces the identity element.
func Respond(
	p *thyrse.Protocol,
	local *ristretto255.Scalar,
	localKEM *mlkem.DecapsulationKey768,
	ciphertext []byte,
) (*State, []byte, error) {
	localPub := ristretto255.NewIdentityElement().ScalarBaseMult(local)
	if localPub.Equal(ristretto255.NewIdentityElement()) == 1 {
		panic("adratchet: identity public key")
	}
	s := &State{
		localPriv: local,
		localKEM:  localKEM,
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
	copy(header[:ratchetHeaderSize], s.localRatchet[:])
	binary.LittleEndian.PutUint32(header[messageNumberOffset:previousChainOffset], s.sendN)
	binary.LittleEndian.PutUint32(header[previousChainOffset:headerSize], s.prevSendN)

	// Advance the sending chain and split off this message's protocol.
	p := forkMessage(s.send, s.sendN)
	s.sendN++

	// Mix in the header and seal the message.
	p.Mix("header", header)
	ciphertext := p.Seal("message", header, plaintext)
	p.Clear()
	return ciphertext
}

// rotateSend generates the local half of the next hybrid ratchet step and
// derives its sending chain from the root protocol.
func (s *State) rotateSend() {
	var localPriv *ristretto255.Scalar
	var localPub *ristretto255.Element
	for {
		var b [64]byte
		_, _ = rand.Read(b[:])
		localPriv, _ = ristretto255.NewScalar().SetUniformBytes(b[:])
		localPub = ristretto255.NewIdentityElement().ScalarBaseMult(localPriv)
		if localPub.Equal(ristretto255.NewIdentityElement()) == 0 {
			break
		}
	}

	localKEM, err := mlkem.GenerateKey768()
	if err != nil {
		panic(err)
	}
	kemShared, kemCiphertext := s.remoteKEM.Encapsulate()

	var ratchet [ratchetHeaderSize]byte
	encodeRatchetHeader(ratchet[:], localPub, localKEM.EncapsulationKey(), kemCiphertext)
	dh := ristretto255.NewIdentityElement().ScalarMult(localPriv, s.remotePub)
	chain := s.deriveChain(ratchet[:], dh.Bytes(), kemShared)
	clear(kemShared)
	if s.send != nil {
		s.send.Clear()
	}
	s.localPriv = localPriv
	s.localKEM = localKEM
	s.localRatchet = ratchet
	s.send = chain
	s.prevSendN = s.sendN
	s.sendN = 0
}

// deriveChain absorbs one hybrid ratchet step into the root and splits off the
// chain associated with the complete public ratchet descriptor.
func (s *State) deriveChain(ratchet, dh, kem []byte) *thyrse.Protocol {
	s.root.Mix("dh", dh)
	s.root.Mix("ml-kem", kem)
	return s.root.ForkN("chain", ratchet)[0]
}

// ReceiveMessage decrypts the given ciphertext and returns the plaintext. It handles out-of-order messages and performs
// ratchet steps as needed. State changes are committed only after the message authenticates successfully.
func (s *State) ReceiveMessage(ciphertext []byte) ([]byte, error) {
	if len(ciphertext) < Overhead {
		return nil, thyrse.ErrInvalidCiphertext
	}
	header := ciphertext[:headerSize]
	msg := ciphertext[headerSize:]

	pub, err := ristretto255.NewIdentityElement().SetCanonicalBytes(header[dhPublicKeyOffset:kemPublicKeyOffset])
	if err != nil || pub.Equal(ristretto255.NewIdentityElement()) == 1 {
		return nil, thyrse.ErrInvalidCiphertext
	}
	kemPub, err := mlkem.NewEncapsulationKey768(header[kemPublicKeyOffset:kemCiphertextOffset])
	if err != nil {
		return nil, thyrse.ErrInvalidCiphertext
	}
	kemCiphertext := header[kemCiphertextOffset:messageNumberOffset]
	ratchetID := sha256.Sum256(header[:ratchetHeaderSize])
	n := binary.LittleEndian.Uint32(header[messageNumberOffset:previousChainOffset])
	pn := binary.LittleEndian.Uint32(header[previousChainOffset:headerSize])

	trial := s.clone()
	plaintext, err := trial.receiveMessage(header, msg, pub, kemPub, kemCiphertext, ratchetID, n, pn)
	if err != nil {
		s.discard(trial)
		return nil, err
	}
	s.commit(trial)
	return plaintext, nil
}

func (s *State) receiveMessage(
	header, msg []byte,
	pub *ristretto255.Element,
	kemPub *mlkem.EncapsulationKey768,
	kemCiphertext []byte,
	ratchetID [sha256.Size]byte,
	n, pn uint32,
) ([]byte, error) {
	// Check for a skipped message key.
	sk := newSK(ratchetID, n)
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

	newRemote := s.recv == nil || ratchetID != s.remoteRatchet
	if newRemote {
		// Catch up on the previous receiving chain.
		if err := s.advanceRecvChain(pn); err != nil {
			return nil, err
		}

		// Derive the receiving chain from the peer's half of the next hybrid step.
		kemShared, err := s.localKEM.Decapsulate(kemCiphertext)
		if err != nil {
			return nil, thyrse.ErrInvalidCiphertext
		}
		dh := ristretto255.NewIdentityElement().ScalarMult(s.localPriv, pub)
		chain := s.deriveChain(header[:ratchetHeaderSize], dh.Bytes(), kemShared)
		clear(kemShared)
		if s.recv != nil {
			s.recv.Clear()
		}
		s.recv = chain

		// Update the remote public key and reset the receiving counter.
		s.remotePub = pub
		s.remoteKEM = kemPub
		s.remoteRatchet = ratchetID
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
	// the next hybrid step. No other operation rotates the local keys.
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
		s.skipped[newSK(s.remoteRatchet, s.recvN)] = p
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
	ratchet [sha256.Size]byte
	n       uint32
}

func newSK(ratchet [sha256.Size]byte, n uint32) skippedKey {
	return skippedKey{
		ratchet: ratchet,
		n:       n,
	}
}

func encodeRatchetHeader(
	dst []byte,
	dh *ristretto255.Element,
	kem *mlkem.EncapsulationKey768,
	kemCiphertext []byte,
) {
	copy(dst[dhPublicKeyOffset:kemPublicKeyOffset], dh.Bytes())
	copy(dst[kemPublicKeyOffset:kemCiphertextOffset], kem.Bytes())
	copy(dst[kemCiphertextOffset:ratchetHeaderSize], kemCiphertext)
}

const (
	dhPublicKeyOffset   = 0
	kemPublicKeyOffset  = dhPublicKeyOffset + 32
	kemCiphertextOffset = kemPublicKeyOffset + mlkem.EncapsulationKeySize768
	ratchetHeaderSize   = kemCiphertextOffset + mlkem.CiphertextSize768
	messageNumberOffset = ratchetHeaderSize
	previousChainOffset = messageNumberOffset + 4
	headerSize          = previousChainOffset + 4
)
