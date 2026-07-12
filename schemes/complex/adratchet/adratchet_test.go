package adratchet_test

import (
	"bytes"
	"fmt"
	"slices"
	"testing"

	"github.com/codahale/thyrse"
	"github.com/codahale/thyrse/internal/testdata"
	"github.com/codahale/thyrse/schemes/complex/adratchet"
	"github.com/gtank/ristretto255"
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

	// Alice initiates the ratchet with her first message.
	a, msgA := adratchet.Initiate(p.Clone(), dA, qB, []byte("this is my first message"))

	// Bea receives the first message and establishes her ratchet state.
	b, v, err := adratchet.Respond(p.Clone(), dB, qA, msgA)
	if err != nil {
		panic(err)
	}
	fmt.Printf("message from A: %q\n", v)

	// Bea sends Alice a message.
	msgB := b.SendMessage([]byte("no, this is _my_ first message"))

	// Alice reads Bea's message.
	v, err = a.ReceiveMessage(msgB)
	if err != nil {
		panic(err)
	}
	fmt.Printf("message from B: %q\n", v)

	// Output:
	// message from A: "this is my first message"
	// message from B: "no, this is _my_ first message"
}

func TestInitiateRespondRejectIdentityKeys(t *testing.T) {
	drbg := testdata.New("thyrse async double ratchet identity")
	d, q := drbg.KeyPair()

	for name, f := range map[string]func(){
		"initiator local":  func() { adratchet.Initiate(thyrse.New("test"), ristretto255.NewScalar(), q, nil) },
		"initiator remote": func() { adratchet.Initiate(thyrse.New("test"), d, ristretto255.NewIdentityElement(), nil) },
		"responder local":  func() { adratchet.Respond(thyrse.New("test"), ristretto255.NewScalar(), q, nil) },
		"responder remote": func() { adratchet.Respond(thyrse.New("test"), d, ristretto255.NewIdentityElement(), nil) },
	} {
		t.Run(name, func(t *testing.T) {
			defer func() {
				if recover() == nil {
					t.Fatal("constructor did not panic")
				}
			}()
			f()
		})
	}
}

func newPair(
	t *testing.T,
	p *thyrse.Protocol,
	dA *ristretto255.Scalar,
	qA *ristretto255.Element,
	dB *ristretto255.Scalar,
	qB *ristretto255.Element,
) (*adratchet.State, *adratchet.State) {
	t.Helper()
	alice, initial := adratchet.Initiate(p.Clone(), dA, qB, []byte("initial"))
	bea, plaintext, err := adratchet.Respond(p.Clone(), dB, qA, initial)
	if err != nil {
		t.Fatalf("Respond() err = %v, want nil", err)
	}
	if !bytes.Equal(plaintext, []byte("initial")) {
		t.Fatalf("Respond() = %q, want %q", plaintext, "initial")
	}
	return alice, bea
}

func TestState_ReceiveMessage(t *testing.T) {
	drbg := testdata.New("thyrse async double ratchet receive test")
	dA, qA := drbg.KeyPair()
	dB, qB := drbg.KeyPair()

	p := thyrse.New("test")
	p.Mix("shared key", []byte("secret"))

	t.Run("failed initial message is retryable", func(t *testing.T) {
		alice, initial := adratchet.Initiate(p.Clone(), dA, qB, []byte("initial"))
		tampered := slices.Clone(initial)
		tampered[len(tampered)-1] ^= 0xff

		root := p.Clone()
		if _, _, err := adratchet.Respond(root, dB, qA, tampered); err == nil {
			t.Error("Respond() err = nil, want error")
		}
		bea, plaintext, err := adratchet.Respond(root, dB, qA, initial)
		if err != nil {
			t.Fatalf("Respond() retry err = %v, want nil", err)
		}
		if !bytes.Equal(plaintext, []byte("initial")) {
			t.Errorf("Respond() retry = %q, want %q", plaintext, "initial")
		}

		reply := bea.SendMessage([]byte("reply"))
		got, err := alice.ReceiveMessage(reply)
		if err != nil {
			t.Fatalf("ReceiveMessage() reply err = %v, want nil", err)
		}
		if !bytes.Equal(got, []byte("reply")) {
			t.Errorf("ReceiveMessage() reply = %q, want %q", got, "reply")
		}
	})

	t.Run("out of order", func(t *testing.T) {
		alice, bea := newPair(t, p, dA, qA, dB, qB)

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
				t.Fatalf("ReceiveMessage(%d) err = %v, want nil", i, err)
			}
			if got, want := v, []byte{byte(i)}; !bytes.Equal(got, want) {
				t.Errorf("ReceiveMessage(%d) = %v, want %v", i, got, want)
			}
		}
	})

	t.Run("DH ratchet", func(t *testing.T) {
		alice, bea := newPair(t, p, dA, qA, dB, qB)

		// Alice sends msg 1.
		msg1 := alice.SendMessage([]byte("msg1"))

		// Bea receives msg 1.
		if _, err := bea.ReceiveMessage(msg1); err != nil {
			t.Fatalf("ReceiveMessage() err = %v, want nil", err)
		}

		// Bea sends msg 2 (triggers DH ratchet on Alice side when she receives it).
		msg2 := bea.SendMessage([]byte("msg2"))

		// Alice receives msg 2.
		if _, err := alice.ReceiveMessage(msg2); err != nil {
			t.Fatalf("ReceiveMessage() err = %v, want nil", err)
		}

		// Alice sends msg 3 and msg 4. (These will have a new DH key).
		msg3 := alice.SendMessage([]byte("msg3"))
		msg4 := alice.SendMessage([]byte("msg4"))

		// Bea receives msg 4 first.
		v, err := bea.ReceiveMessage(msg4)
		if err != nil {
			t.Fatalf("ReceiveMessage() err = %v, want nil", err)
		}
		if got, want := v, []byte("msg4"); !bytes.Equal(got, want) {
			t.Errorf("ReceiveMessage(msg4) = %q, want %q", got, want)
		}

		// Bea receives msg 3.
		v, err = bea.ReceiveMessage(msg3)
		if err != nil {
			t.Fatalf("ReceiveMessage() err = %v, want nil", err)
		}
		if got, want := v, []byte("msg3"); !bytes.Equal(got, want) {
			t.Errorf("ReceiveMessage(msg3) = %q, want %q", got, want)
		}
	})

	t.Run("DH updates alternate", func(t *testing.T) {
		alice, bea := newPair(t, p, dA, qA, dB, qB)

		first := alice.SendMessage([]byte("first"))
		second := alice.SendMessage([]byte("second"))
		if !bytes.Equal(first[:32], second[:32]) {
			t.Fatal("initiator changed ratchet key within a sending chain")
		}

		if _, err := bea.ReceiveMessage(first); err != nil {
			t.Fatal(err)
		}
		reply := bea.SendMessage([]byte("reply"))
		reply2 := bea.SendMessage([]byte("reply 2"))
		if !bytes.Equal(reply[:32], reply2[:32]) {
			t.Fatal("responder changed ratchet key within a sending chain")
		}
		if bytes.Equal(first[:32], reply[:32]) {
			t.Fatal("responder did not change the ratchet key after receiving")
		}

		if _, err := alice.ReceiveMessage(reply); err != nil {
			t.Fatal(err)
		}
		msg := alice.SendMessage([]byte("next turn"))
		if bytes.Equal(msg[:32], first[:32]) {
			t.Fatal("initiator did not change the ratchet key after receiving")
		}
		got, err := bea.ReceiveMessage(msg)
		if err != nil {
			t.Fatalf("ReceiveMessage() err = %v, want nil", err)
		}
		if !bytes.Equal(got, []byte("next turn")) {
			t.Errorf("ReceiveMessage() = %q, want %q", got, "next turn")
		}
	})

	t.Run("failed new DH message is retryable", func(t *testing.T) {
		alice, bea := newPair(t, p, dA, qA, dB, qB)

		msg := bea.SendMessage([]byte("hello"))
		tampered := slices.Clone(msg)
		tampered[len(tampered)-1] ^= 0xff

		if _, err := alice.ReceiveMessage(tampered); err == nil {
			t.Error("ReceiveMessage() err = nil, want error")
		}
		got, err := alice.ReceiveMessage(msg)
		if err != nil {
			t.Fatalf("ReceiveMessage() retry err = %v, want nil", err)
		}
		if !bytes.Equal(got, []byte("hello")) {
			t.Errorf("ReceiveMessage() retry = %q, want %q", got, "hello")
		}

		reply := alice.SendMessage([]byte("reply"))
		got, err = bea.ReceiveMessage(reply)
		if err != nil {
			t.Fatalf("ReceiveMessage() reply err = %v, want nil", err)
		}
		if !bytes.Equal(got, []byte("reply")) {
			t.Errorf("ReceiveMessage() reply = %q, want %q", got, "reply")
		}
	})

	t.Run("failed current chain message is retryable", func(t *testing.T) {
		alice, bea := newPair(t, p, dA, qA, dB, qB)

		first := alice.SendMessage([]byte("first"))
		if _, err := bea.ReceiveMessage(first); err != nil {
			t.Fatal(err)
		}

		msg := alice.SendMessage([]byte("second"))
		tampered := slices.Clone(msg)
		tampered[len(tampered)-1] ^= 0xff
		if _, err := bea.ReceiveMessage(tampered); err == nil {
			t.Error("ReceiveMessage() err = nil, want error")
		}
		got, err := bea.ReceiveMessage(msg)
		if err != nil {
			t.Fatalf("ReceiveMessage() retry err = %v, want nil", err)
		}
		if !bytes.Equal(got, []byte("second")) {
			t.Errorf("ReceiveMessage() retry = %q, want %q", got, "second")
		}
	})

	t.Run("failed skipped message is retryable", func(t *testing.T) {
		alice, bea := newPair(t, p, dA, qA, dB, qB)

		first := alice.SendMessage([]byte("first"))
		second := alice.SendMessage([]byte("second"))
		if _, err := bea.ReceiveMessage(second); err != nil {
			t.Fatal(err)
		}

		tampered := slices.Clone(first)
		tampered[len(tampered)-1] ^= 0xff
		if _, err := bea.ReceiveMessage(tampered); err == nil {
			t.Error("ReceiveMessage() err = nil, want error")
		}
		got, err := bea.ReceiveMessage(first)
		if err != nil {
			t.Fatalf("ReceiveMessage() retry err = %v, want nil", err)
		}
		if !bytes.Equal(got, []byte("first")) {
			t.Errorf("ReceiveMessage() retry = %q, want %q", got, "first")
		}
	})

	t.Run("too short", func(t *testing.T) {
		alice, _ := adratchet.Initiate(p.Clone(), dA, qB, nil)
		if _, err := alice.ReceiveMessage([]byte("too short")); err == nil {
			t.Error("ReceiveMessage() err = nil, want error")
		}
	})

	t.Run("already received", func(t *testing.T) {
		alice, bea := newPair(t, p, dA, qA, dB, qB)

		msg := alice.SendMessage([]byte("hello"))
		if _, err := bea.ReceiveMessage(msg); err != nil {
			t.Fatalf("ReceiveMessage() err = %v, want nil", err)
		}

		if _, err := bea.ReceiveMessage(msg); err == nil {
			t.Error("ReceiveMessage() err = nil, want error")
		}
	})

	t.Run("gap too large", func(t *testing.T) {
		alice, bea := newPair(t, p, dA, qA, dB, qB)

		var msg []byte
		for range 1002 {
			msg = alice.SendMessage([]byte("hello"))
		}

		if _, err := bea.ReceiveMessage(msg); err == nil {
			t.Error("ReceiveMessage() err = nil, want error")
		}
	})

	t.Run("total skipped messages too large", func(t *testing.T) {
		alice, bea := newPair(t, p, dA, qA, dB, qB)

		var msg []byte
		for range 601 {
			msg = alice.SendMessage([]byte("first chain"))
		}
		if _, err := bea.ReceiveMessage(msg); err != nil {
			t.Fatalf("ReceiveMessage() first chain err = %v, want nil", err)
		}

		reply := bea.SendMessage([]byte("ratchet"))
		if _, err := alice.ReceiveMessage(reply); err != nil {
			t.Fatalf("ReceiveMessage() reply err = %v, want nil", err)
		}

		for range 501 {
			msg = alice.SendMessage([]byte("second chain"))
		}
		if _, err := bea.ReceiveMessage(msg); err == nil {
			t.Error("ReceiveMessage() err = nil, want error")
		}
	})

	t.Run("invalid public key", func(t *testing.T) {
		alice, bea := newPair(t, p, dA, qA, dB, qB)

		msg := alice.SendMessage([]byte("hello"))
		// Ristretto255 points are 32 bytes, and the highest bit must be 0 for canonical encoding.
		msg[31] |= 0x80

		if _, err := bea.ReceiveMessage(msg); err == nil {
			t.Error("ReceiveMessage() err = nil, want error")
		}
	})

	t.Run("identity public key", func(t *testing.T) {
		alice, bea := newPair(t, p, dA, qA, dB, qB)

		msg := alice.SendMessage([]byte("hello"))
		copy(msg[:32], ristretto255.NewIdentityElement().Bytes())

		if _, err := bea.ReceiveMessage(msg); err == nil {
			t.Error("ReceiveMessage() err = nil, want error")
		}
	})

	t.Run("new key gap too large", func(t *testing.T) {
		alice, bea := newPair(t, p, dA, qA, dB, qB)

		// Bea receives only the first message under Alice's first key.
		first := alice.SendMessage([]byte("first"))
		if _, err := bea.ReceiveMessage(first); err != nil {
			t.Fatal(err)
		}

		// Alice sends enough additional messages to put the end of the old
		// receiving chain beyond Bea's skip limit.
		for range 1001 {
			alice.SendMessage([]byte("skipped"))
		}

		// Bea's response advances Alice to her next sending chain.
		reply := bea.SendMessage([]byte("reply"))
		if _, err := alice.ReceiveMessage(reply); err != nil {
			t.Fatal(err)
		}

		// Alice sends a message under the second key.
		msg := alice.SendMessage([]byte("new key"))

		// Bea receives it. The gap in the previous chain is > MaxSkip.
		if _, err := bea.ReceiveMessage(msg); err == nil {
			t.Error("ReceiveMessage() err = nil, want error")
		}
	})
}

func FuzzReceiveMessage(f *testing.F) {
	drbg := testdata.New("thyrse adratchet fuzz")
	dA, _ := drbg.KeyPair()
	_, qB := drbg.KeyPair()
	alice, _ := adratchet.Initiate(thyrse.New("fuzz"), dA, qB, nil)

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
