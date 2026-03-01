package thyrse_test

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/codahale/thyrse"
)

// TestVectors verifies the reference implementation against the test vectors in §16 of
// docs/protocol-spec.md.

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

func TestVectorInitDerive(t *testing.T) {
	// §16.1: Init + Derive — minimal protocol producing output.
	p := thyrse.New("test.vector")
	got := p.Derive("output", nil, 32)
	want := mustHex("91a9244784060174970bbbe8395f7f7e4d055c16be368594c0707413dcdfcc58")
	if !bytes.Equal(got, want) {
		t.Errorf("Derive output:\n got %x\nwant %x", got, want)
	}
}

func TestVectorMixMixDerive(t *testing.T) {
	// §16.2: Init + Mix + Mix + Derive — multiple non-finalizing operations.
	p := thyrse.New("test.vector")
	p.Mix("key", []byte("test-key-material"))
	p.Mix("nonce", []byte("test-nonce-value"))
	got := p.Derive("output", nil, 32)
	want := mustHex("fcac8c24985876bdd4e034552fdbeedca786fb7689a196a3acaf643f1c1c2a6a")
	if !bytes.Equal(got, want) {
		t.Errorf("Derive output:\n got %x\nwant %x", got, want)
	}
}

func TestVectorSealDerive(t *testing.T) {
	// §16.3: Init + Mix + Seal + Derive — full AEAD followed by Derive.
	p := thyrse.New("test.vector")
	p.Mix("key", []byte("test-key-material"))
	sealed := p.Seal("message", nil, []byte("hello, world!"))
	deriveOut := p.Derive("output", nil, 32)

	wantSealed := mustHex("645c4ee5330811bf8f8a2070651ea3c503c78d7ef8f2c03fce2f7f2493a95fd299c4743a56048c4b8beccf2eeb")
	wantDerive := mustHex("3d0207b0f8e5238cadfb589172fffe8059827243b0b602c27f2cb2814031879b")
	if !bytes.Equal(sealed, wantSealed) {
		t.Errorf("Seal output:\n got %x\nwant %x", sealed, wantSealed)
	}
	if !bytes.Equal(deriveOut, wantDerive) {
		t.Errorf("Derive output:\n got %x\nwant %x", deriveOut, wantDerive)
	}
}

func TestVectorMaskSeal(t *testing.T) {
	// §16.4: Init + Mix + Mask + Seal — combined unauthenticated and authenticated encryption.
	p := thyrse.New("test.vector")
	p.Mix("key", []byte("test-key-material"))
	masked := p.Mask("unauthenticated", nil, []byte("mask this data"))
	sealed := p.Seal("authenticated", nil, []byte("seal this data"))

	wantMasked := mustHex("260ea77cc6b8ee60b060cac87e6f")
	wantSealed := mustHex("d3d859139486f7f39dd9228fac735abf9b1719ab161559cc834993b17296f801389aabdfcc52c659fcb2feeb48cb")
	if !bytes.Equal(masked, wantMasked) {
		t.Errorf("Mask output:\n got %x\nwant %x", masked, wantMasked)
	}
	if !bytes.Equal(sealed, wantSealed) {
		t.Errorf("Seal output:\n got %x\nwant %x", sealed, wantSealed)
	}
}

func TestVectorRatchetDerive(t *testing.T) {
	// §16.5: Init + Mix + Ratchet + Derive — forward secrecy.

	// Without Ratchet.
	p1 := thyrse.New("test.vector")
	p1.Mix("key", []byte("test-key-material"))
	gotNoRatchet := p1.Derive("output", nil, 32)
	wantNoRatchet := mustHex("7533c628ab03a2be92718588568284f73f467a54f173d8aaa2035ae3d2672945")
	if !bytes.Equal(gotNoRatchet, wantNoRatchet) {
		t.Errorf("Derive (no Ratchet):\n got %x\nwant %x", gotNoRatchet, wantNoRatchet)
	}

	// With Ratchet.
	p2 := thyrse.New("test.vector")
	p2.Mix("key", []byte("test-key-material"))
	p2.Ratchet("forward-secrecy")
	gotRatchet := p2.Derive("output", nil, 32)
	wantRatchet := mustHex("e1af44127866b8588c68e10f17ff7d1d37f12a4e3526a69d8cb220f241fefd31")
	if !bytes.Equal(gotRatchet, wantRatchet) {
		t.Errorf("Derive (after Ratchet):\n got %x\nwant %x", gotRatchet, wantRatchet)
	}
}

func TestVectorForkDerive(t *testing.T) {
	// §16.6: Fork + Derive — independent outputs from three branches.
	p := thyrse.New("test.vector")
	p.Mix("key", []byte("test-key-material"))
	left, right := p.Fork("role", []byte("prover"), []byte("verifier"))

	gotBase := p.Derive("output", nil, 32)
	gotLeft := left.Derive("output", nil, 32)
	gotRight := right.Derive("output", nil, 32)

	wantBase := mustHex("b5b07c94401b4d6e6b9a9289c1ad858327822f7cbe1e459e8d58ccc5b5f40b5d")
	wantLeft := mustHex("ab999f91045ddeb4b743a03c9256b9fd7a913e1ebb3fcd28bed9680534292d63")
	wantRight := mustHex("09236bba933c0d9937c93d2bc8ac77f65a87b380a88ad34ffec206e76892c0eb")
	if !bytes.Equal(gotBase, wantBase) {
		t.Errorf("Base Derive:\n got %x\nwant %x", gotBase, wantBase)
	}
	if !bytes.Equal(gotLeft, wantLeft) {
		t.Errorf("Clone 1 (prover) Derive:\n got %x\nwant %x", gotLeft, wantLeft)
	}
	if !bytes.Equal(gotRight, wantRight) {
		t.Errorf("Clone 2 (verifier) Derive:\n got %x\nwant %x", gotRight, wantRight)
	}
}

func TestVectorMixStream(t *testing.T) {
	// §16.7: MixStream — pre-hash of a 10000-byte input via KT128.
	data := make([]byte, 10000)
	for i := range data {
		data[i] = byte(i % 251)
	}

	p := thyrse.New("test.vector")
	p.Mix("key", []byte("test-key-material"))
	if err := p.MixStream("stream-data", bytes.NewReader(data)); err != nil {
		t.Fatal(err)
	}
	got := p.Derive("output", nil, 32)
	want := mustHex("7e7a81e3d8c4dd701883430697e1aa956b0ad990a1b0823bc3eaca1f9078d768")
	if !bytes.Equal(got, want) {
		t.Errorf("Derive output:\n got %x\nwant %x", got, want)
	}
}

func TestVectorSealOpenRoundTrip(t *testing.T) {
	// §16.8: Seal + Open round-trip — successful authenticated encryption and decryption.
	key := []byte("test-key-material")
	nonce := []byte("test-nonce-value")
	ad := []byte("associated data")
	plaintext := []byte("hello, world!")

	// Seal side.
	pSeal := thyrse.New("test.vector")
	pSeal.Mix("key", key)
	pSeal.Mix("nonce", nonce)
	pSeal.Mix("ad", ad)
	sealed := pSeal.Seal("message", nil, plaintext)
	sealDerive := pSeal.Derive("confirm", nil, 32)

	// Open side.
	pOpen := thyrse.New("test.vector")
	pOpen.Mix("key", key)
	pOpen.Mix("nonce", nonce)
	pOpen.Mix("ad", ad)
	opened, err := pOpen.Open("message", nil, sealed)
	if err != nil {
		t.Fatal(err)
	}
	openDerive := pOpen.Derive("confirm", nil, 32)

	wantSealed := mustHex("667911010907507537fa5ab3a8345d769cbc1167e26edaaa4a38f38a6430f09be3b7917b1ec1f30d667c811612")
	wantDerive := mustHex("1cf32253d292ddb3c3b5ccca4c20daa63f45da40cc47b4598c9643b347035bb9")
	if !bytes.Equal(sealed, wantSealed) {
		t.Errorf("Seal output:\n got %x\nwant %x", sealed, wantSealed)
	}
	if !bytes.Equal(opened, plaintext) {
		t.Errorf("Open plaintext:\n got %x\nwant %x", opened, plaintext)
	}
	if !bytes.Equal(sealDerive, wantDerive) {
		t.Errorf("Seal-side Derive:\n got %x\nwant %x", sealDerive, wantDerive)
	}
	if !bytes.Equal(openDerive, wantDerive) {
		t.Errorf("Open-side Derive:\n got %x\nwant %x", openDerive, wantDerive)
	}
}

func TestVectorSealOpenTampered(t *testing.T) {
	// §16.9: Seal + Open with tampered ciphertext — authentication fails, transcripts desynchronize.
	key := []byte("test-key-material")
	nonce := []byte("test-nonce-value")
	plaintext := []byte("hello, world!")

	// Seal side.
	pSeal := thyrse.New("test.vector")
	pSeal.Mix("key", key)
	pSeal.Mix("nonce", nonce)
	sealed := pSeal.Seal("message", nil, plaintext)
	sealDerive := pSeal.Derive("after", nil, 32)

	wantSealed := mustHex("179a9f4f36547f4ea60a196e670fc58051fc3cdd6ecc8f08a0a10256c7b443a402b852a75f1c38b1fffe3ec7f3")
	if !bytes.Equal(sealed, wantSealed) {
		t.Errorf("Seal output:\n got %x\nwant %x", sealed, wantSealed)
	}

	// Tamper with ciphertext (flip first byte).
	tampered := make([]byte, len(sealed))
	copy(tampered, sealed)
	tampered[0] ^= 0xff

	// Open side with tampered data.
	pOpen := thyrse.New("test.vector")
	pOpen.Mix("key", key)
	pOpen.Mix("nonce", nonce)
	_, err := pOpen.Open("message", nil, tampered)
	if err == nil {
		t.Fatal("Open must reject tampered ciphertext")
	}
	openDerive := pOpen.Derive("after", nil, 32)

	wantSealDerive := mustHex("658908d1d91755d5fb37ed7c6dce9d3710d34a5ec539510ab64b8a5b31ea0355")
	wantOpenDerive := mustHex("a978e9131f73341787f605755deeebd76e94999933717117bdb5f2aa56ac15e9")
	if !bytes.Equal(sealDerive, wantSealDerive) {
		t.Errorf("Seal-side Derive:\n got %x\nwant %x", sealDerive, wantSealDerive)
	}
	if !bytes.Equal(openDerive, wantOpenDerive) {
		t.Errorf("Open-side Derive [desynchronized]:\n got %x\nwant %x", openDerive, wantOpenDerive)
	}
}

func TestVectorMultipleSeals(t *testing.T) {
	// §16.10: Multiple Seals in sequence — each key differs via tag absorption.
	p := thyrse.New("test.vector")
	p.Mix("key", []byte("test-key-material"))
	p.Mix("nonce", []byte("test-nonce-value"))

	sealed1 := p.Seal("msg", nil, []byte("first message"))
	sealed2 := p.Seal("msg", nil, []byte("second message"))
	sealed3 := p.Seal("msg", nil, []byte("third message"))

	want1 := mustHex("d681dd5ad476651843c17f3cfbc54763223f105b8d47366467f7f73cbc4be367b26ad6a6ae04fc3bd49d14ee45")
	want2 := mustHex("2299b98eb976cf08820419f18f29f50fbf47cca91aa263faed9b18f7780a65166b19a9753b6ffc9c5bb93de6b736")
	want3 := mustHex("a20c4d8f8eb687a8da1eeb5d6ddb8ca054c6d022bc0d0d4cbe97928e2928beaede3810f480c413abff9255d69f")
	if !bytes.Equal(sealed1, want1) {
		t.Errorf("Seal 1:\n got %x\nwant %x", sealed1, want1)
	}
	if !bytes.Equal(sealed2, want2) {
		t.Errorf("Seal 2:\n got %x\nwant %x", sealed2, want2)
	}
	if !bytes.Equal(sealed3, want3) {
		t.Errorf("Seal 3:\n got %x\nwant %x", sealed3, want3)
	}
}
