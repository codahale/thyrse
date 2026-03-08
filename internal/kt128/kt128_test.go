package kt128

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"io"
	"slices"
	"strings"
	"testing"

	"github.com/codahale/thyrse/internal/testdata"
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

func unhex(s string) []byte {
	s = strings.ReplaceAll(s, " ", "")
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

// readCustom finalizes h with the given customization string and reads output.
// This is a test helper for RFC vector compatibility.
func readCustom(h *Hasher, custom []byte, out []byte) {
	_, _ = h.ReadCustom(custom, out)
}

// sumHelper returns a 32-byte hash without modifying the original hasher.
// Test-only replacement for the removed Sum method.
func sumHelper(h *Hasher) []byte {
	clone := h.clone()
	out := make([]byte, 32)
	_, _ = clone.Read(out)
	return out
}

// RFC 9861 Section 5 KT128 test vectors.
var rfcVectors = []struct {
	name   string
	msg    []byte
	custom []byte
	outLen int
	want   []byte // full output (or last 32 bytes for 10032 case)
	last32 bool   // if true, want is the last 32 bytes of outLen output
}{
	{
		name:   "empty/empty/32",
		msg:    nil,
		custom: nil,
		outLen: 32,
		want:   unhex("1AC2D450FC3B4205D19DA7BFCA1B37513C0803577AC7167F06FE2CE1F0EF39E5"),
	},
	{
		name:   "empty/empty/64",
		msg:    nil,
		custom: nil,
		outLen: 64,
		want: unhex("1AC2D450FC3B4205D19DA7BFCA1B37513C0803577AC7167F06FE2CE1F0EF39E5" +
			"4269C056B8C82E48276038B6D292966CC07A3D4645272E31FF38508139EB0A71"),
	},
	{
		name:   "empty/empty/10032",
		msg:    nil,
		custom: nil,
		outLen: 10032,
		want:   unhex("E8DC563642F7228C84684C898405D3A834799158C079B12880277A1D28E2FF6D"),
		last32: true,
	},
	{
		name:   "ptn(1)/empty/32",
		msg:    ptn(1),
		custom: nil,
		outLen: 32,
		want:   unhex("2BDA92450E8B147F8A7CB629E784A058EFCA7CF7D8218E02D345DFAA65244A1F"),
	},
	{
		name:   "ptn(17)/empty/32",
		msg:    ptn(17),
		custom: nil,
		outLen: 32,
		want:   unhex("6BF75FA2239198DB4772E36478F8E19B0F371205F6A9A93A273F51DF37122888"),
	},
	{
		name:   "ptn(289)/empty/32",
		msg:    ptn(289),
		custom: nil,
		outLen: 32,
		want:   unhex("0C315EBCDEDBF61426DE7DCF8FB725D1E74675D7F5327A5067F367B108ECB67C"),
	},
	{
		name:   "ptn(4913)/empty/32",
		msg:    ptn(4913),
		custom: nil,
		outLen: 32,
		want:   unhex("CB552E2EC77D9910701D578B457DDF772C12E322E4EE7FE417F92C758F0D59D0"),
	},
	{
		name:   "ptn(83521)/empty/32",
		msg:    ptn(83521),
		custom: nil,
		outLen: 32,
		want:   unhex("8701045E22205345FF4DDA05555CBB5C3AF1A771C2B89BAEF37DB43D9998B9FE"),
	},
	{
		name:   "ptn(1419857)/empty/32",
		msg:    ptn(1419857),
		custom: nil,
		outLen: 32,
		want:   unhex("844D610933B1B9963CBDEB5AE3B6B05CC7CBD67CEEDF883EB678A0A8E0371682"),
	},
	{
		name:   "ptn(24137569)/empty/32",
		msg:    ptn(24137569),
		custom: nil,
		outLen: 32,
		want:   unhex("3C390782A8A4E89FA6367F72FEAAF13255C8D95878481D3CD8CE85F58E880AF8"),
	},
	{
		name:   "empty/ptn(1)/32",
		msg:    nil,
		custom: ptn(1),
		outLen: 32,
		want:   unhex("FAB658DB63E94A246188BF7AF69A133045F46EE984C56E3C3328CAAF1AA1A583"),
	},
	{
		name:   "0xFF/ptn(41)/32",
		msg:    []byte{0xFF},
		custom: ptn(41),
		outLen: 32,
		want:   unhex("D848C5068CED736F4462159B9867FD4C20B808ACC3D5BC48E0B06BA0A3762EC4"),
	},
	{
		name:   "0xFFx3/ptn(1681)/32",
		msg:    []byte{0xFF, 0xFF, 0xFF},
		custom: ptn(1681),
		outLen: 32,
		want:   unhex("C389E5009AE57120854C2E8C64670AC01358CF4C1BAF89447A724234DC7CED74"),
	},
	{
		name:   "0xFFx7/ptn(68921)/32",
		msg:    []byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF},
		custom: ptn(68921),
		outLen: 32,
		want:   unhex("75D2F86A2E644566726B4FBCFC5657B9DBCF070C7B0DCA06450AB291D7443BCF"),
	},
	{
		name:   "ptn(8191)/empty/32",
		msg:    ptn(8191),
		custom: nil,
		outLen: 32,
		want:   unhex("1B577636F723643E990CC7D6A659837436FD6A103626600EB8301CD1DBE553D6"),
	},
	{
		name:   "ptn(8192)/empty/32",
		msg:    ptn(8192),
		custom: nil,
		outLen: 32,
		want:   unhex("48F256F6772F9EDFB6A8B661EC92DC93B95EBD05A08A17B39AE3490870C926C3"),
	},
	{
		name:   "ptn(8192)/ptn(8189)/32",
		msg:    ptn(8192),
		custom: ptn(8189),
		outLen: 32,
		want:   unhex("3ED12F70FB05DDB58689510AB3E4D23C6C603384 9AA01E1D8C220A297FEDCD0B"),
	},
	{
		name:   "ptn(8192)/ptn(8190)/32",
		msg:    ptn(8192),
		custom: ptn(8190),
		outLen: 32,
		want:   unhex("6A7C1B6A5CD0D8C9CA943A4A216CC646045 59A2EA45F78570A15253D67BA00AE"),
	},
}

func TestRFCVectors(t *testing.T) {
	for _, tc := range rfcVectors {
		t.Run(tc.name, func(t *testing.T) {
			h := New()
			if tc.msg != nil {
				_, _ = h.Write(tc.msg)
			}

			out := make([]byte, tc.outLen)
			readCustom(h, tc.custom, out)

			var got []byte
			if tc.last32 {
				got = out[len(out)-32:]
			} else {
				got = out
			}

			if !bytes.Equal(got, tc.want) {
				t.Errorf("got  %x", got)
				t.Errorf("want %x", tc.want)
			}
		})
	}
}

func TestIncremental(t *testing.T) {
	// Verify that incremental writes produce the same result as one-shot.
	msg := ptn(83521)

	// One-shot.
	h1 := New()
	_, _ = h1.Write(msg)
	want := make([]byte, 64)
	_, _ = h1.Read(want)

	// Incremental with various chunk sizes.
	for _, chunkSize := range []int{1, 7, 168, 1000, 8192, 8193, len(msg)} {
		t.Run(fmt.Sprintf("chunk=%d", chunkSize), func(t *testing.T) {
			h := New()
			for i := 0; i < len(msg); i += chunkSize {
				end := min(i+chunkSize, len(msg))
				_, _ = h.Write(msg[i:end])
			}
			got := make([]byte, 64)
			_, _ = h.Read(got)
			if !bytes.Equal(got, want) {
				t.Errorf("chunk=%d: mismatch", chunkSize)
			}
		})
	}
}

func TestIncrementalRead(t *testing.T) {
	h := New()
	_, _ = h.Write(ptn(4913))

	// Read in various sizes.
	var buf bytes.Buffer
	sizes := []int{1, 7, 16, 32, 64, 100, 168, 200}
	for _, s := range sizes {
		tmp := make([]byte, s)
		_, _ = h.Read(tmp)
		buf.Write(tmp)
	}
	got := buf.Bytes()

	// Compare with one-shot.
	h2 := New()
	_, _ = h2.Write(ptn(4913))
	want := make([]byte, len(got))
	_, _ = h2.Read(want)

	if !bytes.Equal(got, want) {
		t.Error("Read() incremental mismatch")
	}
}

func TestSumNonDestructive(t *testing.T) {
	h := New()
	_, _ = h.Write(ptn(4913))

	// Sum should not affect subsequent Read.
	sum := sumHelper(h)

	h2 := New()
	_, _ = h2.Write(ptn(4913))
	out := make([]byte, 32)
	_, _ = h2.Read(out)

	if !bytes.Equal(sum, out) {
		t.Error("sumHelper() result differs from Read()")
	}

	// After sumHelper, Write+Read should still work on original hasher.
	_, _ = h.Write(ptn(100))
	got := make([]byte, 32)
	_, _ = h.Read(got)

	h3 := New()
	_, _ = h3.Write(ptn(4913))
	_, _ = h3.Write(ptn(100))
	want := make([]byte, 32)
	_, _ = h3.Read(want)

	if !bytes.Equal(got, want) {
		t.Error("Read() after sumHelper()+Write() produced wrong result")
	}
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
			readCustom(h, []byte("test"), want)

			got := make([]byte, 64)
			readCustom(clone, []byte("test"), got)

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
		readCustom(h, []byte("test"), out1)

		out2 := make([]byte, 64)
		readCustom(clone, []byte("test"), out2)

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
		h.Chain([]byte("A"), dstA, []byte("B"), dstB)

		if bytes.Equal(dstA, dstB) {
			t.Error("Chain with different customization strings produced identical outputs")
		}
	})

	t.Run("swapped customizations swap outputs", func(t *testing.T) {
		// Chain with (A, B).
		h1 := New()
		_, _ = h1.Write(ptn(100))
		ab1 := make([]byte, 32)
		ab2 := make([]byte, 32)
		h1.Chain([]byte("A"), ab1, []byte("B"), ab2)

		// Chain with (B, A).
		h2 := New()
		_, _ = h2.Write(ptn(100))
		ba1 := make([]byte, 32)
		ba2 := make([]byte, 32)
		h2.Chain([]byte("B"), ba1, []byte("A"), ba2)

		if !bytes.Equal(ab1, ba2) {
			t.Error("swapped customizations: A output from (A,B) != B output from (B,A)")
		}
		if !bytes.Equal(ab2, ba1) {
			t.Error("swapped customizations: B output from (A,B) != A output from (B,A)")
		}
	})

	t.Run("matches sequential finalization (single-node)", func(t *testing.T) {
		// Single-node: message fits in one chunk.
		msg := ptn(100)

		h := New()
		_, _ = h.Write(msg)
		dstA := make([]byte, 32)
		dstB := make([]byte, 32)
		h.Chain([]byte("X"), dstA, []byte("Y"), dstB)

		// Compare with sequential readCustom.
		hA := New()
		_, _ = hA.Write(msg)
		wantA := make([]byte, 32)
		readCustom(hA, []byte("X"), wantA)

		hB := New()
		_, _ = hB.Write(msg)
		wantB := make([]byte, 32)
		readCustom(hB, []byte("Y"), wantB)

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
		h.Chain([]byte("X"), dstA, []byte("Y"), dstB)

		// Compare with sequential readCustom.
		hA := New()
		_, _ = hA.Write(msg)
		wantA := make([]byte, 32)
		readCustom(hA, []byte("X"), wantA)

		hB := New()
		_, _ = hB.Write(msg)
		wantB := make([]byte, 32)
		readCustom(hB, []byte("Y"), wantB)

		if !bytes.Equal(dstA, wantA) {
			t.Errorf("Chain dstA mismatch with sequential\ngot  %x\nwant %x", dstA, wantA)
		}
		if !bytes.Equal(dstB, wantB) {
			t.Errorf("Chain dstB mismatch with sequential\ngot  %x\nwant %x", dstB, wantB)
		}
	})

	t.Run("empty customization via Chain matches Read", func(t *testing.T) {
		msg := ptn(4913)

		h := New()
		_, _ = h.Write(msg)
		dstA := make([]byte, 32)
		dstB := make([]byte, 32)
		h.Chain(nil, dstA, nil, dstB)

		// Both should match Read() with empty customization.
		hRef := New()
		_, _ = hRef.Write(msg)
		want := make([]byte, 32)
		_, _ = hRef.Read(want)

		if !bytes.Equal(dstA, want) {
			t.Errorf("Chain(nil) dstA != Read()\ngot  %x\nwant %x", dstA, want)
		}
		if !bytes.Equal(dstB, want) {
			t.Errorf("Chain(nil) dstB != Read()\ngot  %x\nwant %x", dstB, want)
		}
	})

	t.Run("tree-mode with large message", func(t *testing.T) {
		// Test with a message that exercises multi-leaf tree hashing.
		msg := ptn(83521)

		h := New()
		_, _ = h.Write(msg)
		dstA := make([]byte, 32)
		dstB := make([]byte, 32)
		h.Chain([]byte("alpha"), dstA, []byte("beta"), dstB)

		if bytes.Equal(dstA, dstB) {
			t.Error("Chain with different customization strings produced identical outputs for large message")
		}

		// Verify against sequential.
		hA := New()
		_, _ = hA.Write(msg)
		wantA := make([]byte, 32)
		readCustom(hA, []byte("alpha"), wantA)

		if !bytes.Equal(dstA, wantA) {
			t.Errorf("Chain dstA mismatch with sequential for large message\ngot  %x\nwant %x", dstA, wantA)
		}
	})

	t.Run("different length customizations (sequential fallback)", func(t *testing.T) {
		msg := ptn(100)

		h := New()
		_, _ = h.Write(msg)
		dstA := make([]byte, 32)
		dstB := make([]byte, 32)
		h.Chain([]byte("X"), dstA, []byte("long custom string"), dstB)

		// Compare with sequential readCustom.
		hA := New()
		_, _ = hA.Write(msg)
		wantA := make([]byte, 32)
		readCustom(hA, []byte("X"), wantA)

		hB := New()
		_, _ = hB.Write(msg)
		wantB := make([]byte, 32)
		readCustom(hB, []byte("long custom string"), wantB)

		if !bytes.Equal(dstA, wantA) {
			t.Errorf("Chain dstA mismatch with sequential\ngot  %x\nwant %x", dstA, wantA)
		}
		if !bytes.Equal(dstB, wantB) {
			t.Errorf("Chain dstB mismatch with sequential\ngot  %x\nwant %x", dstB, wantB)
		}
	})

	t.Run("clone before chain preserves original", func(t *testing.T) {
		h := New()
		_, _ = h.Write(ptn(100))

		// Chain on a clone, then chain on another clone — results must match.
		c1 := h.Clone()
		dstA := make([]byte, 32)
		dstB := make([]byte, 32)
		c1.Chain([]byte("A"), dstA, []byte("B"), dstB)

		c2 := h.Clone()
		dstA2 := make([]byte, 32)
		dstB2 := make([]byte, 32)
		c2.Chain([]byte("A"), dstA2, []byte("B"), dstB2)

		if !bytes.Equal(dstA, dstA2) || !bytes.Equal(dstB, dstB2) {
			t.Error("Chain on two clones of the same hasher produced different results")
		}
	})
}

var sizes = slices.Concat(testdata.Sizes, []testdata.Size{
	{Name: "8KiB+1B", N: BlockSize + 1},
})

func BenchmarkWrite(b *testing.B) {
	for _, size := range sizes {
		b.Run(size.Name, func(b *testing.B) {
			msg := ptn(size.N)
			out := make([]byte, 32)
			b.SetBytes(int64(size.N))
			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				h := New()
				_, _ = h.Write(msg)
				_, _ = h.Read(out)
			}
		})
	}
}

func BenchmarkWriteStreaming(b *testing.B) {
	for _, size := range sizes {
		if size.N < 2*BlockSize {
			continue
		}
		b.Run(size.Name, func(b *testing.B) {
			msg := ptn(size.N)
			out := make([]byte, 32)
			b.SetBytes(int64(size.N))
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				h := New()
				for i := 0; i < len(msg); i += BlockSize {
					end := min(i+BlockSize, len(msg))
					_, _ = h.Write(msg[i:end])
				}
				_, _ = h.Read(out)
			}
		})
	}
}

func BenchmarkRead(b *testing.B) {
	for _, outSize := range []int{32, 64, 256, 1024} {
		b.Run(fmt.Sprintf("%d", outSize), func(b *testing.B) {
			out := make([]byte, outSize)
			b.SetBytes(int64(outSize))
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				h := New()
				_, _ = h.Write(ptn(BlockSize + 1))
				_, _ = io.ReadFull(h, out)
			}
		})
	}
}
