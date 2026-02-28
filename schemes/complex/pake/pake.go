// Package pake provides a [Cpace]-style Password-Authenticated Key Exchange (PAKE), which allows two parties which
// share a possibly low-entropy secret (like a password) to establish a high-entropy shared protocol state for e.g.
// encrypted communications.
//
// [Cpace]: https://www.ietf.org/archive/id/draft-irtf-cfrg-cpace-06.html
package pake

import (
	"errors"

	"github.com/codahale/thyrse"
	"github.com/gtank/ristretto255"
)

// ErrInvalidHandshake is returned when some aspect of a handshake is invalid.
var ErrInvalidHandshake = errors.New("thyrse/pake: invalid handshake")

// Finish is a callback function to be called when a message is received from another party.
type Finish = func(in []byte) (*thyrse.Protocol, error)

// Initiate begins a key exchange as the initiator, using the given domain separation string, initiator ID, responder
// ID, session ID, password, and random value (which must be exactly 64 bytes). It returns a Finish function and a
// message to be sent to the responder. When the finish function is called with the responder's message, it will return
// a thyrse.Protocol with a shared state.
//
// Panics if rand is not exactly 64 bytes.
func Initiate(domain string, initiatorID, responderID, sessionID, password, rand []byte) (finish Finish, out []byte) {
	return exchange(domain, initiatorID, responderID, sessionID, password, rand, true)
}

// Respond establishes a key exchange as the responder, using the given domain separation string, initiator ID,
// responder ID, session ID, password, random value (which must be exactly 64 bytes), and the initiator's message.
// Returns a fully-keyed thyrse.Protocol and a message to be sent to the initiator to complete the exchange, or an
// error.
//
// Panics if rand is not exactly 64 bytes.
func Respond(domain string, initiatorID, responderID, sessionID, password, rand, msg []byte) (p *thyrse.Protocol, out []byte, err error) {
	finish, out := exchange(domain, initiatorID, responderID, sessionID, password, rand, false)
	p, err = finish(msg)
	return p, out, err
}

func exchange(domain string, initiatorID, responderID, sessionID, password, rand []byte, initiator bool) (finisher Finish, out []byte) {
	// Initialize a protocol and mix in the various data.
	p := thyrse.New(domain)
	p.Mix("initiator", initiatorID)
	p.Mix("responder", responderID)
	p.Mix("session", sessionID)
	p.Mix("password", password)

	// Derive a base point from the protocol state.
	gP, _ := ristretto255.NewIdentityElement().SetUniformBytes(p.Derive("generator", nil, 64))

	// Generate a random secret value.
	a, err := ristretto255.NewScalar().SetUniformBytes(rand)
	if err != nil {
		panic(err)
	}

	// Calculate the exchange point and encode it.
	out = ristretto255.NewIdentityElement().ScalarMult(a, gP).Bytes()

	// Return a continuation to be called when the message from the other party is received.
	return func(in []byte) (*thyrse.Protocol, error) {
		// Mix in the network messages based on role.
		if initiator {
			p.Mix("initiator-message", out)
			p.Mix("responder-message", in)
		} else {
			p.Mix("initiator-message", in)
			p.Mix("responder-message", out)
		}

		// Decode the responder's exchange point and check for contributory behavior.
		b, _ := ristretto255.NewIdentityElement().SetCanonicalBytes(in)
		if b == nil || b.Equal(ristretto255.NewIdentityElement()) == 1 {
			return nil, ErrInvalidHandshake
		}

		// Calculate the key point and mix it into the protocol.
		k := ristretto255.NewIdentityElement().ScalarMult(a, b)
		p.Mix("key-element", k.Bytes())

		// Return a fully keyed protocol.
		return p, nil
	}, out
}
