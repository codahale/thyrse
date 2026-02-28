package pake_test

import (
	"errors"
	"fmt"
	"testing"

	"github.com/codahale/thyrse/internal/testdata"
	"github.com/codahale/thyrse/schemes/complex/pake"
	"github.com/gtank/ristretto255"
)

func TestPake(t *testing.T) {
	drbg := testdata.New("thyrse pake")
	r1 := drbg.Data(64)
	r2 := drbg.Data(64)

	t.Run("successful exchange", func(t *testing.T) {
		finish, initiate := pake.Initiate("example", []byte("a"), []byte("b"), []byte("s"), []byte("p"), r1)
		pResponder, response, err := pake.Respond("example", []byte("a"), []byte("b"), []byte("s"), []byte("p"), r2, initiate)
		if err != nil {
			t.Fatal(err)
		}
		pInitiator, err := finish(response)
		if err != nil {
			t.Fatal(err)
		}

		if got, want := pInitiator.String(), pResponder.String(); got != want {
			t.Errorf("initiator = %s, responder = %s", got, want)
		}
	})

	t.Run("wrong password", func(t *testing.T) {
		finish, initiate := pake.Initiate("example", []byte("a"), []byte("b"), []byte("s"), []byte("p1"), r1)
		pResponder, response, err := pake.Respond("example", []byte("a"), []byte("b"), []byte("s"), []byte("p2"), r2, initiate)
		if err != nil {
			t.Fatal(err)
		}
		pInitiator, err := finish(response)
		if err != nil {
			t.Fatal(err)
		}

		if pInitiator.Equal(pResponder) == 1 {
			t.Error("different passwords should lead to different states")
		}
	})

	t.Run("wrong domain", func(t *testing.T) {
		finish, initiate := pake.Initiate("example1", []byte("a"), []byte("b"), []byte("s"), []byte("p"), r1)
		pResponder, response, err := pake.Respond("example2", []byte("a"), []byte("b"), []byte("s"), []byte("p"), r2, initiate)
		if err != nil {
			t.Fatal(err)
		}
		pInitiator, err := finish(response)
		if err != nil {
			t.Fatal(err)
		}

		if got, want := pInitiator.String(), pResponder.String(); got == want {
			t.Error("different domains should lead to different states")
		}
	})

	t.Run("invalid responder message", func(t *testing.T) {
		finish, _ := pake.Initiate("example", []byte("a"), []byte("b"), []byte("s"), []byte("p"), r1)

		_, err := finish(make([]byte, 31)) // invalid length
		if !errors.Is(err, pake.ErrInvalidHandshake) {
			t.Errorf("expected ErrInvalidHandshake, got %v", err)
		}
	})

	t.Run("identity element", func(t *testing.T) {
		finish, _ := pake.Initiate("example", []byte("a"), []byte("b"), []byte("s"), []byte("p"), r1)
		_, err := finish(ristretto255.NewIdentityElement().Bytes())
		if !errors.Is(err, pake.ErrInvalidHandshake) {
			t.Errorf("expected ErrInvalidHandshake, got %v", err)
		}
	})
}

func Example() {
	drbg := testdata.New("thyrse pake")
	r1 := drbg.Data(64)
	r2 := drbg.Data(64)

	// The initiator begins the exchange, generating a callback function and a message to send.
	finish, initiate := pake.Initiate(
		"example",
		[]byte("client"),
		[]byte("server"),
		[]byte("session"),
		[]byte("the bravest toaster"),
		r1,
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
		r2,
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

	// Both initiator and responder share a protocol state.
	fmt.Printf("responder: %x\n", pResponder.Derive("state", nil, 16))
	fmt.Printf("initiator: %x\n", pInitiator.Derive("state", nil, 16))

	// Output:
	// responder: e2cf17ff620b7883e7fe1a4670bb50aa
	// initiator: e2cf17ff620b7883e7fe1a4670bb50aa
}
