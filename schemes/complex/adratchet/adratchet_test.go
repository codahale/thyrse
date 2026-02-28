package adratchet_test

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/codahale/thyrse"
	"github.com/codahale/thyrse/internal/testdata"
	"github.com/codahale/thyrse/schemes/complex/adratchet"
)

func Example() {
	drbg := testdata.New("thyrse async double ratchet")

	// Alice has a private and public key.
	dA, qA := drbg.KeyPair()

	// Bea has a private and public key.
	dB, qB := drbg.KeyPair()

	// Alice and Bea have a shared protocol state, probably thanks to an ECDH handshake.
	p := thyrse.New("example")
	p.Mix("shared key", []byte("ok then"))

	// Alice sets up an asynchronous double ratchet for the initiator role.
	a := adratchet.NewInitiator(p.Clone(), dA, qB)

	// Bea sets up an asynchronous double ratchet for the responder role.
	b := adratchet.NewResponder(p.Clone(), dB, qA)

	// Alice sends Bea a message.
	msgA := a.SendMessage([]byte("this is my first message"))

	// Bea sends Alice a message.
	msgB := b.SendMessage([]byte("no, this is _my_ first message"))

	// Alice reads Bea's message.
	v, err := a.ReceiveMessage(msgB)
	if err != nil {
		panic(err)
	}
	fmt.Printf("message from B: %q\n", v)

	// Bea reads Alice's message.
	v, err = b.ReceiveMessage(msgA)
	if err != nil {
		panic(err)
	}
	fmt.Printf("message from A: %q\n", v)

	// Output:
	// message from B: "no, this is _my_ first message"
	// message from A: "this is my first message"
}

func TestState_ReceiveMessage(t *testing.T) {
	drbg := testdata.New("thyrse async double ratchet receive test")
	dA, qA := drbg.KeyPair()
	dB, qB := drbg.KeyPair()

	p := thyrse.New("test")
	p.Mix("shared key", []byte("secret"))

	t.Run("out of order", func(t *testing.T) {
		alice := adratchet.NewInitiator(p.Clone(), dA, qB)
		bea := adratchet.NewResponder(p.Clone(), dB, qA)

		// Alice sends 5 messages.
		msgs := make([][]byte, 5)
		for i := range 5 {
			msgs[i] = alice.SendMessage([]byte{byte(i)})
		}

		// Bea receives them out of order: 2, 0, 4, 1, 3.
		order := []int{2, 0, 4, 1, 3}
		for _, i := range order {
			v, err := bea.ReceiveMessage(msgs[i])
			if err != nil {
				t.Fatalf("ReceiveMessage(%d) failed: %v", i, err)
			}
			if got, want := v, []byte{byte(i)}; !bytes.Equal(got, want) {
				t.Errorf("ReceiveMessage(%d) = %v, want %v", i, got, want)
			}
		}
	})

	t.Run("DH ratchet", func(t *testing.T) {
		alice := adratchet.NewInitiator(p.Clone(), dA, qB)
		bea := adratchet.NewResponder(p.Clone(), dB, qA)

		// Alice sends msg 1.
		msg1 := alice.SendMessage([]byte("msg1"))

		// Bea receives msg 1.
		if _, err := bea.ReceiveMessage(msg1); err != nil {
			t.Fatalf("bea failed to receive msg1: %v", err)
		}

		// Bea sends msg 2 (triggers DH ratchet on Alice side when she receives it).
		msg2 := bea.SendMessage([]byte("msg2"))

		// Alice receives msg 2.
		if _, err := alice.ReceiveMessage(msg2); err != nil {
			t.Fatalf("alice failed to receive msg2: %v", err)
		}

		// Alice sends msg 3 and msg 4. (These will have a new DH key).
		msg3 := alice.SendMessage([]byte("msg3"))
		msg4 := alice.SendMessage([]byte("msg4"))

		// Bea receives msg 4 first.
		v, err := bea.ReceiveMessage(msg4)
		if err != nil {
			t.Fatalf("bea failed to receive msg4: %v", err)
		}
		if got, want := v, []byte("msg4"); !bytes.Equal(got, want) {
			t.Errorf("ReceiveMessage(msg4) = %q, want %q", got, want)
		}

		// Bea receives msg 3.
		v, err = bea.ReceiveMessage(msg3)
		if err != nil {
			t.Fatalf("bea failed to receive msg3: %v", err)
		}
		if got, want := v, []byte("msg3"); !bytes.Equal(got, want) {
			t.Errorf("ReceiveMessage(msg3) = %q, want %q", got, want)
		}
	})

	t.Run("invalid message", func(t *testing.T) {
		alice := adratchet.NewInitiator(p.Clone(), dA, qB)
		bea := adratchet.NewResponder(p.Clone(), dB, qA)

		msg := alice.SendMessage([]byte("hello"))
		msg[len(msg)-1] ^= 0xff // Corrupt the tag

		if _, err := bea.ReceiveMessage(msg); err == nil {
			t.Error("expected error for corrupted message, got none")
		}
	})

	t.Run("too short", func(t *testing.T) {
		bea := adratchet.NewResponder(p.Clone(), dB, qA)
		if _, err := bea.ReceiveMessage([]byte("too short")); err == nil {
			t.Error("expected error for too short message, got none")
		}
	})

	t.Run("already received", func(t *testing.T) {
		alice := adratchet.NewInitiator(p.Clone(), dA, qB)
		bea := adratchet.NewResponder(p.Clone(), dB, qA)

		msg := alice.SendMessage([]byte("hello"))
		if _, err := bea.ReceiveMessage(msg); err != nil {
			t.Fatalf("failed to receive message: %v", err)
		}

		if _, err := bea.ReceiveMessage(msg); err == nil {
			t.Error("expected error for already received message, got none")
		}
	})

	t.Run("gap too large", func(t *testing.T) {
		alice := adratchet.NewInitiator(p.Clone(), dA, qB)
		bea := adratchet.NewResponder(p.Clone(), dB, qA)

		var msg []byte
		for range 1002 {
			msg = alice.SendMessage([]byte("hello"))
		}

		if _, err := bea.ReceiveMessage(msg); err == nil {
			t.Error("expected error for gap too large, got none")
		}
	})

	t.Run("invalid public key", func(t *testing.T) {
		alice := adratchet.NewInitiator(p.Clone(), dA, qB)
		bea := adratchet.NewResponder(p.Clone(), dB, qA)

		msg := alice.SendMessage([]byte("hello"))
		// Ristretto255 points are 32 bytes, and the highest bit must be 0 for canonical encoding.
		msg[31] |= 0x80

		if _, err := bea.ReceiveMessage(msg); err == nil {
			t.Error("expected error for invalid public key, got none")
		}
	})

	t.Run("new key gap too large", func(t *testing.T) {
		alice := adratchet.NewInitiator(p.Clone(), dA, qB)
		bea := adratchet.NewResponder(p.Clone(), dB, qA)

		// Alice sends many messages under the first key.
		for range 1001 {
			alice.SendMessage([]byte("skipped"))
		}

		// Alice ratchets.
		alice.Ratchet()

		// Alice sends a message under the second key.
		msg := alice.SendMessage([]byte("new key"))

		// Bea receives it. pn should be 1001, which is > MaxSkip.
		if _, err := bea.ReceiveMessage(msg); err == nil {
			t.Error("expected error for new key gap too large, got none")
		}
	})
}

func FuzzReceiveMessage(f *testing.F) {
	drbg := testdata.New("thyrse adratchet fuzz")
	dA, _ := drbg.KeyPair()
	_, qB := drbg.KeyPair()
	alice := adratchet.NewInitiator(thyrse.New("fuzz"), dA, qB)

	for range 10 {
		f.Add(drbg.Data(128))
	}

	f.Fuzz(func(t *testing.T, ciphertext []byte) {
		v, err := alice.ReceiveMessage(ciphertext)
		if err == nil {
			t.Errorf("ReceiveMessage(ciphertext=%x) = plaintext=%x, want = err", ciphertext, v)
		}
	})
}
