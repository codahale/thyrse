package k12

import (
	"bytes"
	"fmt"
	"testing"
)

// ptn returns a byte slice of length n using the KT128 test pattern:
// repeating 0x00..0xFA (251 bytes).
func ptn(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i % 251)
	}
	return b
}

func TestClone(t *testing.T) {
	sizes := []int{0, 1, BlockSize - 1, BlockSize, BlockSize + 1, 83521}
	for _, size := range sizes {
		t.Run(fmt.Sprintf("%d", size), func(t *testing.T) {
			msg := ptn(size)

			// Write all data, clone, verify both produce the same output.
			h := New()
			_, _ = h.Write(msg)

			clone := h.Clone()

			// Use readCustom with a custom string to test clone + custom finalization.
			want := make([]byte, 64)
			_, _ = h.ReadCustom([]byte("test"), want)

			got := make([]byte, 64)
			_, _ = clone.ReadCustom([]byte("test"), got)

			if !bytes.Equal(got, want) {
				t.Errorf("size=%d: clone output mismatch", size)
			}
		})
	}

	t.Run("independent after clone", func(t *testing.T) {
		h := New()
		_, _ = h.Write(ptn(BlockSize + 1))

		clone := h.Clone()

		// Write more data to the original only.
		_, _ = h.Write([]byte("extra"))

		out1 := make([]byte, 64)
		_, _ = h.ReadCustom([]byte("test"), out1)

		out2 := make([]byte, 64)
		_, _ = clone.ReadCustom([]byte("test"), out2)

		if bytes.Equal(out1, out2) {
			t.Error("clone and original produced identical output after diverging")
		}
	})
}

func TestChain(t *testing.T) {
	t.Run("different customizations produce different outputs", func(t *testing.T) {
		h := New()
		_, _ = h.Write(ptn(100))

		dstA := make([]byte, 32)
		dstB := make([]byte, 32)
		h.Chain(0x01, dstA, 0x02, dstB)

		if bytes.Equal(dstA, dstB) {
			t.Error("Chain with different customization values produced identical outputs")
		}
	})

	t.Run("swapped customizations swap outputs", func(t *testing.T) {
		// Chain with (1, 2).
		h1 := New()
		_, _ = h1.Write(ptn(100))
		ab1 := make([]byte, 32)
		ab2 := make([]byte, 32)
		h1.Chain(0x01, ab1, 0x02, ab2)

		// Chain with (2, 1).
		h2 := New()
		_, _ = h2.Write(ptn(100))
		ba1 := make([]byte, 32)
		ba2 := make([]byte, 32)
		h2.Chain(0x02, ba1, 0x01, ba2)

		if !bytes.Equal(ab1, ba2) {
			t.Error("swapped customizations: A output from (1,2) != B output from (2,1)")
		}
		if !bytes.Equal(ab2, ba1) {
			t.Error("swapped customizations: B output from (1,2) != A output from (2,1)")
		}
	})

	t.Run("matches sequential finalization (single-node)", func(t *testing.T) {
		// Single-node: message fits in one chunk.
		msg := ptn(100)

		h := New()
		_, _ = h.Write(msg)
		dstA := make([]byte, 32)
		dstB := make([]byte, 32)
		h.Chain(0x20, dstA, 0x21, dstB)

		// Compare with sequential readCustom.
		hA := New()
		_, _ = hA.Write(msg)
		wantA := make([]byte, 32)
		_, _ = hA.ReadCustom([]byte{0x20}, wantA)

		hB := New()
		_, _ = hB.Write(msg)
		wantB := make([]byte, 32)
		_, _ = hB.ReadCustom([]byte{0x21}, wantB)

		if !bytes.Equal(dstA, wantA) {
			t.Errorf("Chain dstA mismatch with sequential\ngot  %x\nwant %x", dstA, wantA)
		}
		if !bytes.Equal(dstB, wantB) {
			t.Errorf("Chain dstB mismatch with sequential\ngot  %x\nwant %x", dstB, wantB)
		}
	})

	t.Run("matches sequential finalization (tree-mode)", func(t *testing.T) {
		// Tree-mode: message > 8192 bytes.
		msg := ptn(BlockSize*3 + 500)

		h := New()
		_, _ = h.Write(msg)
		dstA := make([]byte, 32)
		dstB := make([]byte, 32)
		h.Chain(0x20, dstA, 0x21, dstB)

		// Compare with sequential readCustom.
		hA := New()
		_, _ = hA.Write(msg)
		wantA := make([]byte, 32)
		_, _ = hA.ReadCustom([]byte{0x20}, wantA)

		hB := New()
		_, _ = hB.Write(msg)
		wantB := make([]byte, 32)
		_, _ = hB.ReadCustom([]byte{0x21}, wantB)

		if !bytes.Equal(dstA, wantA) {
			t.Errorf("Chain dstA mismatch with sequential\ngot  %x\nwant %x", dstA, wantA)
		}
		if !bytes.Equal(dstB, wantB) {
			t.Errorf("Chain dstB mismatch with sequential\ngot  %x\nwant %x", dstB, wantB)
		}
	})

	t.Run("tree-mode with large message", func(t *testing.T) {
		// Test with a message that exercises multi-leaf tree hashing.
		msg := ptn(83521)

		h := New()
		_, _ = h.Write(msg)
		dstA := make([]byte, 32)
		dstB := make([]byte, 32)
		h.Chain(0x30, dstA, 0x31, dstB)

		if bytes.Equal(dstA, dstB) {
			t.Error("Chain with different customization values produced identical outputs for large message")
		}

		// Verify against sequential.
		hA := New()
		_, _ = hA.Write(msg)
		wantA := make([]byte, 32)
		_, _ = hA.ReadCustom([]byte{0x30}, wantA)

		if !bytes.Equal(dstA, wantA) {
			t.Errorf("Chain dstA mismatch with sequential for large message\ngot  %x\nwant %x", dstA, wantA)
		}
	})

	t.Run("clone before chain preserves original", func(t *testing.T) {
		h := New()
		_, _ = h.Write(ptn(100))

		// Chain on a clone, then chain on another clone — results must match.
		c1 := h.Clone()
		dstA := make([]byte, 32)
		dstB := make([]byte, 32)
		c1.Chain(0x01, dstA, 0x02, dstB)

		c2 := h.Clone()
		dstA2 := make([]byte, 32)
		dstB2 := make([]byte, 32)
		c2.Chain(0x01, dstA2, 0x02, dstB2)

		if !bytes.Equal(dstA, dstA2) || !bytes.Equal(dstB, dstB2) {
			t.Error("Chain on two clones of the same hasher produced different results")
		}
	})
}
