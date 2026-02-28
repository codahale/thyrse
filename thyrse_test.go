package thyrse

import (
	"bytes"
	"encoding/hex"
	"errors"
	"testing"
)

func TestDerive(t *testing.T) {
	t.Run("minimal", func(t *testing.T) {
		p := New("test")
		out := p.Derive("output", nil, 32)

		if len(out) != 32 {
			t.Fatalf("got %d bytes, want 32", len(out))
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
			t.Fatalf("not deterministic:\n  %s\n  %s", hex.EncodeToString(out1), hex.EncodeToString(out2))
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

		if len(out) != 64 {
			t.Fatalf("got %d bytes, want 64", len(out))
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

		if len(opened) != 0 {
			t.Fatalf("got %d bytes, want 0", len(opened))
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
	t.Run("tampered ciphertext", func(t *testing.T) {
		key := []byte("32-byte-key-material-for-testing!")

		enc := New("test.seal")
		enc.Mix("key", key)
		sealed := enc.Seal("message", nil, []byte("secret"))

		tampered := make([]byte, len(sealed))
		copy(tampered, sealed)
		tampered[0] ^= 0xFF

		dec := New("test.seal")
		dec.Mix("key", key)
		_, err := dec.Open("message", nil, tampered)
		if !errors.Is(err, ErrInvalidCiphertext) {
			t.Fatalf("got %v, want ErrInvalidCiphertext", err)
		}
	})

	t.Run("tampered tag", func(t *testing.T) {
		key := []byte("32-byte-key-material-for-testing!")

		enc := New("test.seal")
		enc.Mix("key", key)
		sealed := enc.Seal("message", nil, []byte("secret"))

		tampered := make([]byte, len(sealed))
		copy(tampered, sealed)
		tampered[len(tampered)-1] ^= 0xFF

		dec := New("test.seal")
		dec.Mix("key", key)
		_, err := dec.Open("message", nil, tampered)
		if !errors.Is(err, ErrInvalidCiphertext) {
			t.Fatalf("got %v, want ErrInvalidCiphertext", err)
		}
	})

	t.Run("input too short", func(t *testing.T) {
		p := New("test")
		_, err := p.Open("msg", nil, make([]byte, TagSize-1))
		if !errors.Is(err, ErrInvalidCiphertext) {
			t.Fatalf("got %v, want ErrInvalidCiphertext", err)
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

		if len(pt) != 0 {
			t.Fatalf("got %d bytes, want 0", len(pt))
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

		clones := p.Fork("role", []byte("alice"), []byte("bob"))
		if len(clones) != 2 {
			t.Fatalf("got %d clones, want 2", len(clones))
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
			clones := p.Fork("role", []byte("a"))
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

func TestMixStream(t *testing.T) {
	t.Run("deterministic", func(t *testing.T) {
		data := make([]byte, 100000)
		for i := range data {
			data[i] = byte(i)
		}

		p := New("test")
		if err := p.MixStream("large-data", bytes.NewReader(data)); err != nil {
			t.Fatal(err)
		}
		out := p.Derive("output", nil, 32)

		p2 := New("test")
		if err := p2.MixStream("large-data", bytes.NewReader(data)); err != nil {
			t.Fatal(err)
		}
		out2 := p2.Derive("output", nil, 32)

		if !bytes.Equal(out, out2) {
			t.Fatal("not deterministic")
		}
	})
}

func TestMixWriter(t *testing.T) {
	data := make([]byte, 100000)
	for i := range data {
		data[i] = byte(i)
	}

	// Reference output via MixStream.
	ref := New("test")
	if err := ref.MixStream("large-data", bytes.NewReader(data)); err != nil {
		t.Fatal(err)
	}
	want := ref.Derive("output", nil, 32)

	t.Run("one-shot write matches MixStream", func(t *testing.T) {
		p := New("test")
		mw := p.MixWriter("large-data")
		if _, err := mw.Write(data); err != nil {
			t.Fatal(err)
		}
		if err := mw.Close(); err != nil {
			t.Fatal(err)
		}

		got := p.Derive("output", nil, 32)
		if !bytes.Equal(got, want) {
			t.Error("one-shot write: transcript mismatch")
		}
	})

	t.Run("incremental writes match MixStream", func(t *testing.T) {
		p := New("test")
		mw := p.MixWriter("large-data")
		for i := 0; i < len(data); i += 1000 {
			end := min(i+1000, len(data))
			if _, err := mw.Write(data[i:end]); err != nil {
				t.Fatal(err)
			}
		}
		if err := mw.Close(); err != nil {
			t.Fatal(err)
		}

		got := p.Derive("output", nil, 32)
		if !bytes.Equal(got, want) {
			t.Error("incremental writes: transcript mismatch")
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

func TestClear(t *testing.T) {
	t.Run("zeros state", func(t *testing.T) {
		p := New("test")
		p.Mix("key", []byte("secret"))

		// Derive before clearing to get a reference output.
		ref := p.Clone()
		out1 := ref.Derive("output", nil, 32)

		p.Clear()

		// After Clear, the initLabel should be nil.
		if p.initLabel != "" {
			t.Fatal("initLabel not zeroed")
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
