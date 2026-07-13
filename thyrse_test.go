package thyrse

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"slices"
	"testing"

	"github.com/codahale/thyrse/internal/enc"
)

// newKeyed returns a Protocol initialized with label and a single Mix("key", key).
func newKeyed(label string, key []byte) *Protocol {
	p := New(label)
	p.Mix("key", key)
	return p
}

func TestMixWriter(t *testing.T) {
	t.Run("matches Mix", func(t *testing.T) {
		got := New("test")
		w := got.MixWriter("data")
		for _, chunk := range [][]byte{[]byte("one"), nil, []byte("two"), []byte("three")} {
			if n, err := w.Write(chunk); err != nil || n != len(chunk) {
				t.Fatalf("Write() = (%d, %v), want (%d, nil)", n, err, len(chunk))
			}
		}
		if err := w.Close(); err != nil {
			t.Fatalf("Close() err = %v, want nil", err)
		}

		want := New("test")
		want.Mix("data", []byte("onetwothree"))
		if got.Equal(want) != 1 {
			t.Fatal("MixWriter transcript differs from Mix")
		}
	})

	t.Run("empty", func(t *testing.T) {
		got := New("test")
		if err := got.MixWriter("data").Close(); err != nil {
			t.Fatalf("Close() err = %v, want nil", err)
		}

		want := New("test")
		want.Mix("data", nil)
		if got.Equal(want) != 1 {
			t.Fatal("empty MixWriter transcript differs from Mix")
		}
	})

	t.Run("closed", func(t *testing.T) {
		got := New("test")
		w := got.MixWriter("data")
		if _, err := w.Write([]byte("one")); err != nil {
			t.Fatalf("Write() err = %v, want nil", err)
		}
		if err := w.Close(); err != nil {
			t.Fatalf("Close() err = %v, want nil", err)
		}
		if err := w.Close(); err != nil {
			t.Fatalf("second Close() err = %v, want nil", err)
		}
		if n, err := w.Write([]byte("two")); n != 0 || !errors.Is(err, io.ErrClosedPipe) {
			t.Fatalf("Write() after Close() = (%d, %v), want (0, io.ErrClosedPipe)", n, err)
		}

		want := New("test")
		want.Mix("data", []byte("one"))
		if got.Equal(want) != 1 {
			t.Fatal("Close or rejected Write mutated the transcript")
		}
	})

	t.Run("clone", func(t *testing.T) {
		got := New("test")
		w := got.MixWriter("data")
		if _, err := w.Write([]byte("one")); err != nil {
			t.Fatalf("Write() err = %v, want nil", err)
		}

		clone, cloneWriter := w.Clone()
		if err := cloneWriter.Close(); err != nil {
			t.Fatalf("clone Close() err = %v, want nil", err)
		}
		wantClone := New("test")
		wantClone.Mix("data", []byte("one"))
		if clone.Equal(wantClone) != 1 {
			t.Fatal("cloned MixWriter transcript differs from Mix")
		}

		if _, err := w.Write([]byte("two")); err != nil {
			t.Fatalf("Write() after Clone() err = %v, want nil", err)
		}
		if err := w.Close(); err != nil {
			t.Fatalf("Close() err = %v, want nil", err)
		}
		want := New("test")
		want.Mix("data", []byte("onetwo"))
		if got.Equal(want) != 1 {
			t.Fatal("original MixWriter was affected by clone")
		}
	})
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
		if enc.Equal(dec) != 1 {
			t.Fatal("Seal and successful Open produced divergent states")
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
	seal := func(plaintext []byte) (*Protocol, []byte) {
		enc := newKeyed("test.seal", key)
		return enc, enc.Seal("message", nil, plaintext)
	}

	t.Run("tampered ciphertext", func(t *testing.T) {
		enc, sealed := seal([]byte("secret"))
		tampered := make([]byte, len(sealed))
		copy(tampered, sealed)
		tampered[0] ^= 0xFF

		dec := newKeyed("test.seal", key)
		_, err := dec.Open("message", nil, tampered)
		if !errors.Is(err, ErrInvalidCiphertext) {
			t.Fatalf("got %v, want ErrInvalidCiphertext", err)
		}
		if enc.Equal(dec) == 1 {
			t.Fatal("ciphertext error did not diverge state")
		}
	})

	t.Run("tampered tag", func(t *testing.T) {
		enc, sealed := seal([]byte("secret"))
		tampered := make([]byte, len(sealed))
		copy(tampered, sealed)
		tampered[len(tampered)-1] ^= 0xFF

		dec := newKeyed("test.seal", key)
		_, err := dec.Open("message", nil, tampered)
		if !errors.Is(err, ErrInvalidCiphertext) {
			t.Fatalf("got %v, want ErrInvalidCiphertext", err)
		}
		if enc.Equal(dec) == 1 {
			t.Fatal("tag-only error did not diverge state")
		}
	})

	t.Run("truncated tag", func(t *testing.T) {
		enc, sealed := seal(nil)
		dec := newKeyed("test.seal", key)
		_, err := dec.Open("message", nil, sealed[:len(sealed)-1])
		if !errors.Is(err, ErrInvalidCiphertext) {
			t.Fatalf("got %v, want ErrInvalidCiphertext", err)
		}
		if enc.Equal(dec) == 1 {
			t.Fatal("truncated tag did not diverge state")
		}
	})

	t.Run("different tags produce different states", func(t *testing.T) {
		_, sealed := seal([]byte("secret"))
		bad1 := slices.Clone(sealed)
		bad2 := slices.Clone(sealed)
		bad1[len(bad1)-1] ^= 1
		bad2[len(bad2)-1] ^= 2

		dec1 := newKeyed("test.seal", key)
		dec2 := newKeyed("test.seal", key)
		_, _ = dec1.Open("message", nil, bad1)
		_, _ = dec2.Open("message", nil, bad2)
		if dec1.Equal(dec2) == 1 {
			t.Fatal("different received tags produced equal states")
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
	const redacted = "thyrse.Protocol{redacted}"
	p1 := New("test")
	p1.Mix("key", []byte("a"))
	p2 := New("test")
	p2.Mix("key", []byte("b"))

	if p1.Equal(p2) != 0 {
		t.Fatal("test protocols should have different states")
	}
	if got := p1.String(); got != redacted {
		t.Fatalf("String() = %q, want %q", got, redacted)
	}
	if got := p1.GoString(); got != redacted {
		t.Fatalf("GoString() = %q, want %q", got, redacted)
	}
	for _, format := range []string{"%v", "%+v", "%#v"} {
		t.Run(format, func(t *testing.T) {
			got1 := fmt.Sprintf(format, p1)
			got2 := fmt.Sprintf(format, p2)
			if got1 != redacted || got2 != redacted {
				t.Fatalf("formatting = (%q, %q), want (%q, %q)", got1, got2, redacted, redacted)
			}
		})
	}
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

	t.Run("binds complete descriptor", func(t *testing.T) {
		fork := func(values ...[]byte) (*Protocol, []*Protocol) {
			p := New("test")
			p.Mix("key", []byte("shared"))
			return p, p.ForkN("role", values...)
		}

		base1, branches1 := fork([]byte("alice"), []byte("bob"))
		base2, branches2 := fork([]byte("alice"), []byte("carol"))
		if base1.Equal(base2) == 1 {
			t.Fatal("parent does not bind all branch values")
		}
		if branches1[0].Equal(branches2[0]) == 1 {
			t.Fatal("branch does not bind sibling values")
		}
	})

	t.Run("positions separate duplicate values", func(t *testing.T) {
		p := New("test")
		branches := p.ForkN("role", nil, nil)
		if branches[0].Equal(branches[1]) == 1 {
			t.Fatal("duplicate values produced equal branches")
		}
	})

	t.Run("uses derived chain values", func(t *testing.T) {
		values := [][]byte{[]byte("alice"), []byte("bob")}

		wantSource := New("test")
		wantSource.Mix("key", []byte("shared"))
		wantSource.writeForkOp("role", values)

		parentCV := wantSource.finalize(nil)
		wantParent := New("discarded")
		wantParent.resetChain(opFork, parentCV[:])

		wantBranches := make([]*Protocol, len(values))
		for i := range values {
			var branchCV [chainValueSize]byte
			_, _ = wantSource.h.Read(branchCV[:])
			wantBranches[i] = New("discarded")
			wantBranches[i].resetChain(opFork, branchCV[:])
		}

		gotParent := New("test")
		gotParent.Mix("key", []byte("shared"))
		gotBranches := gotParent.ForkN("role", values...)

		if gotParent.Equal(wantParent) != 1 {
			t.Fatal("parent was not seeded from the first fork output")
		}
		for i := range gotBranches {
			if gotBranches[i].Equal(wantBranches[i]) != 1 {
				t.Fatalf("branch %d was not seeded from its fork output", i)
			}
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

	got := New("discarded")
	got.resetChain(opMask, chainValue[:])

	want := New("discarded")
	want.h.Reset()
	_, _ = want.h.Write([]byte{opMask})
	_, _ = want.h.Write(chainValue[:])
	_, _ = want.h.Write(enc.RightEncode(nil, uint64(len(chainValue))))
	_, _ = want.h.Write(enc.RightEncode(nil, 1))
	_, _ = want.h.Write([]byte{opChain})

	if got.Equal(want) != 1 {
		t.Fatal("optimized chain frame does not match generic encoding")
	}
}
