package pake_test

import (
	"errors"
	"fmt"
	"testing"

	"github.com/codahale/thyrse/schemes/complex/pake"
	"github.com/gtank/ristretto255"
)

func TestPake(t *testing.T) {
	t.Run("successful exchange", func(t *testing.T) {
		finish, initiate := pake.Initiate("example", []byte("a"), []byte("b"), []byte("s"), []byte("p"))
		pResponder, response, err := pake.Respond("example", []byte("a"), []byte("b"), []byte("s"), []byte("p"), initiate)
		if err != nil {
			t.Fatal(err)
		}
		pInitiator, err := finish(response)
		if err != nil {
			t.Fatal(err)
		}

		if pInitiator.Equal(pResponder) != 1 {
			t.Error("initiator and responder states differ")
		}
	})

	t.Run("wrong password", func(t *testing.T) {
		finish, initiate := pake.Initiate("example", []byte("a"), []byte("b"), []byte("s"), []byte("p1"))
		pResponder, response, err := pake.Respond("example", []byte("a"), []byte("b"), []byte("s"), []byte("p2"), initiate)
		if err != nil {
			t.Fatal(err)
		}
		pInitiator, err := finish(response)
		if err != nil {
			t.Fatal(err)
		}

		if got, want := pInitiator.Equal(pResponder), 0; got != want {
			t.Error("Equal() = true, want false")
		}
	})

	t.Run("wrong domain", func(t *testing.T) {
		finish, initiate := pake.Initiate("example1", []byte("a"), []byte("b"), []byte("s"), []byte("p"))
		pResponder, response, err := pake.Respond("example2", []byte("a"), []byte("b"), []byte("s"), []byte("p"), initiate)
		if err != nil {
			t.Fatal(err)
		}
		pInitiator, err := finish(response)
		if err != nil {
			t.Fatal(err)
		}

		if pInitiator.Equal(pResponder) != 0 {
			t.Error("Initiate/Respond() states equal, want different")
		}
	})

	t.Run("invalid responder message", func(t *testing.T) {
		finish, _ := pake.Initiate("example", []byte("a"), []byte("b"), []byte("s"), []byte("p"))

		_, err := finish(make([]byte, 31)) // invalid length
		if !errors.Is(err, pake.ErrInvalidHandshake) {
			t.Errorf("finish() err = %v, want ErrInvalidHandshake", err)
		}
	})

	t.Run("identity element", func(t *testing.T) {
		finish, _ := pake.Initiate("example", []byte("a"), []byte("b"), []byte("s"), []byte("p"))
		_, err := finish(ristretto255.NewIdentityElement().Bytes())
		if !errors.Is(err, pake.ErrInvalidHandshake) {
			t.Errorf("finish() err = %v, want ErrInvalidHandshake", err)
		}
	})

}

func Example() {
	// The initiator begins the exchange, generating a callback function and a message to send.
	finish, initiate := pake.Initiate(
		"example",
		[]byte("client"),
		[]byte("server"),
		[]byte("session"),
		[]byte("the bravest toaster"),
	)

	// The initiator sends `initiate` to the responder.

	// The responder receives the message and finishes their side of the exchange, establishing a fully keyed protocol
	// and generating a response message.
	pResponder, response, err := pake.Respond(
		"example",
		[]byte("client"),
		[]byte("server"),
		[]byte("session"),
		[]byte("the bravest toaster"),
		initiate,
	)
	if err != nil {
		panic(err)
	}

	// The responder sends `response` to the initiator.

	// The initiator finishes their side of the exchange, establishing a fully keyed protocol.
	pInitiator, err := finish(response)
	if err != nil {
		panic(err)
	}

	// The responder confirms possession of the shared state to the initiator.
	confirmation := pResponder.Seal("responder key confirmation", nil, nil)
	if _, err := pInitiator.Open("responder key confirmation", nil, confirmation); err != nil {
		panic(err)
	}

	// The initiator confirms possession of the shared state to the responder. The session is mutually authenticated only
	// after both confirmations succeed.
	confirmation = pInitiator.Seal("initiator key confirmation", nil, nil)
	if _, err := pResponder.Open("initiator key confirmation", nil, confirmation); err != nil {
		panic(err)
	}

	// Both initiator and responder now share a mutually authenticated protocol state.
	fmt.Printf("states equal: %t\n", pResponder.Equal(pInitiator) == 1)

	// Output:
	// states equal: true
}
