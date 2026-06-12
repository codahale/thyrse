package thyrse

import (
	"bytes"
	"errors"
	"testing"

	"github.com/codahale/thyrse/internal/enc"
)

// newKeyed returns a Protocol initialized with label and a single Mix("key", key).
func newKeyed(label string, key []byte) *Protocol {
	p := New(label)
	p.Mix("key", key)
	return p
}

func TestDerive(t *testing.T) {
	t.Run("minimal", func(t *testing.T) {
		p := New("test")
		out := p.Derive("output", nil, 32)

		if got, want := len(out), 32; got != want {
			t.Fatalf("Derive() len = %d, want %d", got, want)
		}
	})

	t.Run("deterministic", func(t *testing.T) {
		p1 := New("test")
		p1.Mix("key", []byte("secret"))
		out1 := p1.Derive("output", nil, 32)

		p2 := New("test")
		p2.Mix("key", []byte("secret"))
		out2 := p2.Derive("output", nil, 32)

		if !bytes.Equal(out1, out2) {
			t.Fatalf("not deterministic:\n  got  %x\n  want %x", out1, out2)
		}
	})

	t.Run("domain separation", func(t *testing.T) {
		p1 := New("protocol-a")
		out1 := p1.Derive("output", nil, 32)

		p2 := New("protocol-b")
		out2 := p2.Derive("output", nil, 32)

		if bytes.Equal(out1, out2) {
			t.Fatal("different Init labels produced identical output")
		}
	})

	t.Run("multiple mix operations", func(t *testing.T) {
		p := New("test")
		p.Mix("key", []byte("key-material"))
		p.Mix("nonce", []byte("nonce-value"))
		out := p.Derive("output", nil, 64)

		if got, want := len(out), 64; got != want {
			t.Fatalf("Derive() len = %d, want %d", got, want)
		}

		p2 := New("test")
		p2.Mix("key", []byte("key-material"))
		p2.Mix("nonce", []byte("nonce-value"))
		out2 := p2.Derive("output", nil, 64)

		if !bytes.Equal(out, out2) {
			t.Fatal("not deterministic with multiple Mix operations")
		}
	})

	t.Run("after seal", func(t *testing.T) {
		key := []byte("key-material")

		p1 := New("test")
		p1.Mix("key", key)
		p1.Seal("msg", nil, []byte("plaintext"))
		out1 := p1.Derive("output", nil, 32)

		p2 := New("test")
		p2.Mix("key", key)
		p2.Seal("msg", nil, []byte("plaintext"))
		out2 := p2.Derive("output", nil, 32)

		if !bytes.Equal(out1, out2) {
			t.Fatal("not deterministic after Seal")
		}
	})

	t.Run("panics on zero length", func(t *testing.T) {
		defer func() {
			if r := recover(); r == nil {
				t.Fatal("Derive(0) did not panic")
			}
		}()

		p := New("test")
		p.Derive("output", nil, 0)
	})

	t.Run("panics on negative length", func(t *testing.T) {
		defer func() {
			if r := recover(); r == nil {
				t.Fatal("Derive(-1) did not panic")
			}
		}()

		p := New("test")
		p.Derive("output", nil, -1)
	})
}

func TestSeal(t *testing.T) {
	t.Run("round trip", func(t *testing.T) {
		key := []byte("32-byte-key-material-for-testing!")
		nonce := []byte("unique-nonce")
		ad := []byte("associated data")
		plaintext := []byte("hello, world!")

		enc := New("test.seal")
		enc.Mix("key", key)
		enc.Mix("nonce", nonce)
		enc.Mix("ad", ad)
		sealed := enc.Seal("message", nil, plaintext)

		dec := New("test.seal")
		dec.Mix("key", key)
		dec.Mix("nonce", nonce)
		dec.Mix("ad", ad)
		opened, err := dec.Open("message", nil, sealed)
		if err != nil {
			t.Fatalf("Open: %v", err)
		}

		if !bytes.Equal(opened, plaintext) {
			t.Fatalf("got %q, want %q", opened, plaintext)
		}
	})

	t.Run("empty plaintext", func(t *testing.T) {
		key := []byte("32-byte-key-material-for-testing!")

		enc := New("test.seal")
		enc.Mix("key", key)
		sealed := enc.Seal("msg", nil, nil)

		dec := New("test.seal")
		dec.Mix("key", key)
		opened, err := dec.Open("msg", nil, sealed)
		if err != nil {
			t.Fatalf("Open: %v", err)
		}

		if got, want := len(opened), 0; got != want {
			t.Fatalf("Open() len = %d, want %d", got, want)
		}
	})

	t.Run("sequential messages", func(t *testing.T) {
		key := []byte("32-byte-key-material-for-testing!")
		msgs := [][]byte{
			[]byte("first message"),
			[]byte("second message"),
			[]byte("third message"),
		}

		enc := New("test")
		enc.Mix("key", key)

		var sealed [][]byte
		for _, m := range msgs {
			sealed = append(sealed, enc.Seal("msg", nil, m))
		}

		dec := New("test")
		dec.Mix("key", key)

		for i, s := range sealed {
			pt, err := dec.Open("msg", nil, s)
			if err != nil {
				t.Fatalf("message %d: %v", i, err)
			}
			if !bytes.Equal(pt, msgs[i]) {
				t.Fatalf("message %d: got %q, want %q", i, pt, msgs[i])
			}
		}
	})

	t.Run("sequential seals produce different output", func(t *testing.T) {
		key := []byte("32-byte-key-material-for-testing!")
		pt := []byte("hello")

		p := New("test")
		p.Mix("key", key)
		sealed1 := p.Seal("msg", nil, pt)
		sealed2 := p.Seal("msg", nil, pt)

		if bytes.Equal(sealed1, sealed2) {
			t.Fatal("two sequential Seals produced identical output")
		}
	})
}

func TestOpen(t *testing.T) {
	key := []byte("32-byte-key-material-for-testing!")

	// Shared seal setup for tamper tests.
	seal := func() []byte {
		enc := newKeyed("test.seal", key)
		return enc.Seal("message", nil, []byte("secret"))
	}

	t.Run("tampered ciphertext", func(t *testing.T) {
		sealed := seal()
		tampered := make([]byte, len(sealed))
		copy(tampered, sealed)
		tampered[0] ^= 0xFF

		dec := newKeyed("test.seal", key)
		_, err := dec.Open("message", nil, tampered)
		if !errors.Is(err, ErrInvalidCiphertext) {
			t.Fatalf("got %v, want ErrInvalidCiphertext", err)
		}
	})

	t.Run("tampered tag", func(t *testing.T) {
		sealed := seal()
		tampered := make([]byte, len(sealed))
		copy(tampered, sealed)
		tampered[len(tampered)-1] ^= 0xFF

		dec := newKeyed("test.seal", key)
		_, err := dec.Open("message", nil, tampered)
		if !errors.Is(err, ErrInvalidCiphertext) {
			t.Fatalf("got %v, want ErrInvalidCiphertext", err)
		}
	})

	t.Run("input too short", func(t *testing.T) {
		p := New("test")
		ref := p.Clone()

		_, err := p.Open("msg", nil, make([]byte, TagSize-1))
		if !errors.Is(err, ErrInvalidCiphertext) {
			t.Fatalf("got %v, want ErrInvalidCiphertext", err)
		}

		got := p.Derive("check", nil, 32)
		want := ref.Derive("check", nil, 32)
		if bytes.Equal(got, want) {
			t.Fatal("short Open should advance and diverge state")
		}
	})
}

func TestMask(t *testing.T) {
	t.Run("round trip", func(t *testing.T) {
		key := []byte("32-byte-key-material-for-testing!")
		plaintext := []byte("hello, world!")

		enc := New("test.mask")
		enc.Mix("key", key)
		ciphertext := enc.Mask("message", nil, plaintext)

		dec := New("test.mask")
		dec.Mix("key", key)
		recovered := dec.Unmask("message", nil, ciphertext)

		if !bytes.Equal(recovered, plaintext) {
			t.Fatalf("got %q, want %q", recovered, plaintext)
		}
	})

	t.Run("empty plaintext", func(t *testing.T) {
		key := []byte("key")

		enc := New("test.mask")
		enc.Mix("key", key)
		ct := enc.Mask("msg", nil, nil)

		dec := New("test.mask")
		dec.Mix("key", key)
		pt := dec.Unmask("msg", nil, ct)

		if got, want := len(pt), 0; got != want {
			t.Fatalf("Unmask() len = %d, want %d", got, want)
		}
	})

	t.Run("then seal", func(t *testing.T) {
		key := []byte("key-material")
		pt := []byte("hello")

		enc := New("test")
		enc.Mix("key", key)
		ct1 := enc.Mask("mask-msg", nil, pt)
		sealed := enc.Seal("seal-msg", nil, pt)

		dec := New("test")
		dec.Mix("key", key)
		pt1 := dec.Unmask("mask-msg", nil, ct1)
		pt2, err := dec.Open("seal-msg", nil, sealed)
		if err != nil {
			t.Fatalf("Open: %v", err)
		}

		if !bytes.Equal(pt1, pt) {
			t.Fatalf("Unmask: got %q, want %q", pt1, pt)
		}
		if !bytes.Equal(pt2, pt) {
			t.Fatalf("Open: got %q, want %q", pt2, pt)
		}
	})
}

func TestRatchet(t *testing.T) {
	t.Run("changes derive output", func(t *testing.T) {
		p1 := New("test")
		p1.Mix("key", []byte("key"))
		out1 := p1.Derive("output", nil, 32)

		p2 := New("test")
		p2.Mix("key", []byte("key"))
		p2.Ratchet("ratchet")
		out2 := p2.Derive("output", nil, 32)

		if bytes.Equal(out1, out2) {
			t.Fatal("Ratchet did not change Derive output")
		}
	})
}

func TestFork(t *testing.T) {
	t.Run("branch independence", func(t *testing.T) {
		p := New("test")
		p.Mix("key", []byte("shared-key"))

		clones := p.ForkN("role", []byte("alice"), []byte("bob"))
		if got, want := len(clones), 2; got != want {
			t.Fatalf("ForkN() len = %d, want %d", got, want)
		}

		outBase := p.Derive("output", nil, 32)
		outAlice := clones[0].Derive("output", nil, 32)
		outBob := clones[1].Derive("output", nil, 32)

		if bytes.Equal(outBase, outAlice) {
			t.Fatal("base and clone[0] produced identical output")
		}
		if bytes.Equal(outBase, outBob) {
			t.Fatal("base and clone[1] produced identical output")
		}
		if bytes.Equal(outAlice, outBob) {
			t.Fatal("clone[0] and clone[1] produced identical output")
		}
	})

	t.Run("deterministic", func(t *testing.T) {
		fork := func() ([]byte, []byte) {
			p := New("test")
			p.Mix("key", []byte("key"))
			clones := p.ForkN("role", []byte("a"))
			return p.Derive("out", nil, 32), clones[0].Derive("out", nil, 32)
		}

		base1, clone1 := fork()
		base2, clone2 := fork()

		if !bytes.Equal(base1, base2) {
			t.Fatal("base not deterministic")
		}
		if !bytes.Equal(clone1, clone2) {
			t.Fatal("clone not deterministic")
		}
	})
}

func TestClone(t *testing.T) {
	t.Run("independent evolution", func(t *testing.T) {
		p := New("test")
		p.Mix("key", []byte("key"))

		clone := p.Clone()

		p.Mix("extra", []byte("a"))
		clone.Mix("extra", []byte("b"))

		out1 := p.Derive("output", nil, 32)
		out2 := clone.Derive("output", nil, 32)

		if bytes.Equal(out1, out2) {
			t.Fatal("Clone and original produced identical output after diverging")
		}
	})
}

func TestEqual(t *testing.T) {
	t.Run("same state", func(t *testing.T) {
		p1 := New("test")
		p1.Mix("key", []byte("secret"))

		p2 := New("test")
		p2.Mix("key", []byte("secret"))

		if p1.Equal(p2) != 1 {
			t.Fatal("identical protocols should be equal")
		}
	})

	t.Run("different label", func(t *testing.T) {
		p1 := New("protocol-a")
		p2 := New("protocol-b")

		if p1.Equal(p2) != 0 {
			t.Fatal("different labels should not be equal")
		}
	})

	t.Run("diverged mix", func(t *testing.T) {
		p1 := New("test")
		p1.Mix("key", []byte("a"))

		p2 := New("test")
		p2.Mix("key", []byte("b"))

		if p1.Equal(p2) != 0 {
			t.Fatal("diverged protocols should not be equal")
		}
	})

	t.Run("clone", func(t *testing.T) {
		p := New("test")
		p.Mix("key", []byte("secret"))
		clone := p.Clone()

		if p.Equal(clone) != 1 {
			t.Fatal("protocol and its clone should be equal")
		}
	})

	t.Run("diverged clone", func(t *testing.T) {
		p := New("test")
		p.Mix("key", []byte("secret"))
		clone := p.Clone()

		p.Mix("extra", []byte("a"))
		clone.Mix("extra", []byte("b"))

		if p.Equal(clone) != 0 {
			t.Fatal("diverged clone should not be equal")
		}
	})
}

func TestString(t *testing.T) {
	t.Run("non-empty", func(t *testing.T) {
		p := New("test")
		s := p.String()
		if s == "" {
			t.Fatal("String() should not be empty")
		}
	})

	t.Run("same state same string", func(t *testing.T) {
		p1 := New("test")
		p1.Mix("key", []byte("secret"))

		p2 := New("test")
		p2.Mix("key", []byte("secret"))

		if p1.String() != p2.String() {
			t.Fatal("identical protocols should produce same String()")
		}
	})

	t.Run("different state different string", func(t *testing.T) {
		p1 := New("test")
		p1.Mix("key", []byte("a"))

		p2 := New("test")
		p2.Mix("key", []byte("b"))

		if p1.String() == p2.String() {
			t.Fatal("different protocols should produce different String()")
		}
	})

	t.Run("non-mutating", func(t *testing.T) {
		p := New("test")
		p.Mix("key", []byte("secret"))
		clone := p.Clone()

		_ = p.String()

		if p.Equal(clone) != 1 {
			t.Fatal("String() should not mutate protocol state")
		}
	})
}

func TestForkN(t *testing.T) {
	t.Run("three values", func(t *testing.T) {
		p := New("test")
		p.Mix("key", []byte("shared"))

		clones := p.ForkN("role", []byte("alice"), []byte("bob"), []byte("carol"))
		if got, want := len(clones), 3; got != want {
			t.Fatalf("ForkN() len = %d, want %d", got, want)
		}

		outBase := p.Derive("out", nil, 32)
		outA := clones[0].Derive("out", nil, 32)
		outB := clones[1].Derive("out", nil, 32)
		outC := clones[2].Derive("out", nil, 32)

		all := [][]byte{outBase, outA, outB, outC}
		for i := range all {
			for j := i + 1; j < len(all); j++ {
				if bytes.Equal(all[i], all[j]) {
					t.Fatalf("outputs %d and %d are identical", i, j)
				}
			}
		}
	})

	t.Run("deterministic", func(t *testing.T) {
		fork := func() ([]byte, []byte, []byte, []byte) {
			p := New("test")
			p.Mix("key", []byte("shared"))
			clones := p.ForkN("role", []byte("a"), []byte("b"), []byte("c"))
			return p.Derive("out", nil, 32),
				clones[0].Derive("out", nil, 32),
				clones[1].Derive("out", nil, 32),
				clones[2].Derive("out", nil, 32)
		}

		b1, a1, b1b, c1 := fork()
		b2, a2, b2b, c2 := fork()

		if !bytes.Equal(b1, b2) || !bytes.Equal(a1, a2) || !bytes.Equal(b1b, b2b) || !bytes.Equal(c1, c2) {
			t.Fatal("ForkN is not deterministic")
		}
	})
}

func TestClear(t *testing.T) {
	t.Run("zeros state", func(t *testing.T) {
		p := New("test")
		p.Mix("key", []byte("secret"))

		// Derive before clearing to get a reference output.
		ref := p.Clone()
		out1 := ref.Derive("output", nil, 32)

		p.Clear()

		// After Clear, the hasher should be nil.
		if p.h != nil {
			t.Fatal("hasher not nil after Clear")
		}

		// A fresh protocol with the same inputs should still produce the reference output,
		// confirming Clear didn't corrupt shared state.
		p2 := New("test")
		p2.Mix("key", []byte("secret"))
		out2 := p2.Derive("output", nil, 32)

		if !bytes.Equal(out1, out2) {
			t.Fatal("Clear corrupted shared state")
		}
	})
}

func TestResetChainEncoding(t *testing.T) {
	var chainValue [chainValueSize]byte
	for i := range chainValue {
		chainValue[i] = byte(i)
	}

	var tag [16]byte
	for i := range tag {
		tag[i] = byte(i + len(chainValue))
	}

	for _, tc := range []struct {
		name string
		tag  []byte
	}{
		{name: "without tag"},
		{name: "with tag", tag: tag[:]},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := New("discarded")
			got.resetChain(opMask, chainValue[:], tc.tag)

			want := New("discarded")
			want.h.Reset()
			_, _ = want.h.Write([]byte{opMask})
			_, _ = want.h.Write(chainValue[:])
			_, _ = want.h.Write(enc.RightEncode(nil, uint64(len(chainValue))))
			valueCount := uint64(1)
			if len(tc.tag) > 0 {
				_, _ = want.h.Write(tc.tag)
				_, _ = want.h.Write(enc.RightEncode(nil, uint64(len(tc.tag))))
				valueCount++
			}
			_, _ = want.h.Write(enc.RightEncode(nil, valueCount))
			_, _ = want.h.Write([]byte{opChain})

			if got.Equal(want) != 1 {
				t.Fatal("optimized chain frame does not match generic encoding")
			}
		})
	}
}
