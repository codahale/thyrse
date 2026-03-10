package keccak

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/codahale/thyrse/internal/testdata"
)

// fuzzEncryptN cross-validates xN assembly encrypt against x1 generic reference.
// nInst is 2 or 8. nBlocks is the number of Rate-sized blocks per instance.
func fuzzEncryptN(t *testing.T, nInst, nBlocks int, seed string) {
	t.Helper()
	n := nBlocks * Rate
	stride := n
	drbg := testdata.New(seed)

	pt := drbg.Data(nInst * stride)

	// Distinct seed per instance.
	seeds := make([][]byte, nInst)
	for i := range nInst {
		seeds[i] = drbg.Data(200)
	}

	// x1 generic reference per instance.
	sGen := make([]State1, nInst)
	ctGen := make([]byte, nInst*stride)
	for inst := range nInst {
		seedState1(&sGen[inst], seeds[inst])
		genericEncrypt1(&sGen[inst], pt[inst*stride:(inst+1)*stride], ctGen[inst*stride:(inst+1)*stride])
	}

	// Assembly path.
	ctAsm := make([]byte, nInst*stride)
	switch nInst {
	case 2:
		var s State2
		for i := range 25 {
			for j := range 2 {
				seedLane(s.lane2(i, j), seeds[j], i)
			}
		}
		s.FastLoopEncrypt168(pt, ctAsm, stride)
		checkState2(t, &s, sGen[:])
	case 8:
		var s State8
		for i := range 25 {
			for j := range 8 {
				seedLane(&s.a[i][j], seeds[j], i)
			}
		}
		s.FastLoopEncrypt168(pt, ctAsm, stride)
		checkState8(t, &s, sGen[:])
	}

	if !bytes.Equal(ctGen, ctAsm) {
		for i := range len(ctGen) {
			if ctGen[i] != ctAsm[i] {
				t.Fatalf("x%d encrypt: first difference at byte %d (offset %d in instance %d): gen=%02x asm=%02x",
					nInst, i, i%stride, i/stride, ctGen[i], ctAsm[i])
			}
		}
	}
}

// fuzzDecryptN cross-validates xN assembly decrypt against x1 generic reference.
func fuzzDecryptN(t *testing.T, nInst, nBlocks int, seed string) {
	t.Helper()
	n := nBlocks * Rate
	stride := n
	drbg := testdata.New(seed)

	ct := drbg.Data(nInst * stride)

	seeds := make([][]byte, nInst)
	for i := range nInst {
		seeds[i] = drbg.Data(200)
	}

	sGen := make([]State1, nInst)
	ptGen := make([]byte, nInst*stride)
	for inst := range nInst {
		seedState1(&sGen[inst], seeds[inst])
		genericDecrypt1(&sGen[inst], ct[inst*stride:(inst+1)*stride], ptGen[inst*stride:(inst+1)*stride])
	}

	ptAsm := make([]byte, nInst*stride)
	switch nInst {
	case 2:
		var s State2
		for i := range 25 {
			for j := range 2 {
				seedLane(s.lane2(i, j), seeds[j], i)
			}
		}
		s.FastLoopDecrypt168(ct, ptAsm, stride)
		checkState2(t, &s, sGen[:])
	case 8:
		var s State8
		for i := range 25 {
			for j := range 8 {
				seedLane(&s.a[i][j], seeds[j], i)
			}
		}
		s.FastLoopDecrypt168(ct, ptAsm, stride)
		checkState8(t, &s, sGen[:])
	}

	if !bytes.Equal(ptGen, ptAsm) {
		for i := range len(ptGen) {
			if ptGen[i] != ptAsm[i] {
				t.Fatalf("x%d decrypt: first difference at byte %d (offset %d in instance %d): gen=%02x asm=%02x",
					nInst, i, i%stride, i/stride, ptGen[i], ptAsm[i])
			}
		}
	}
}

func seedLane(dst *uint64, seed []byte, lane int) {
	off := lane * 8
	*dst = uint64(seed[off]) | uint64(seed[off+1])<<8 | uint64(seed[off+2])<<16 | uint64(seed[off+3])<<24 |
		uint64(seed[off+4])<<32 | uint64(seed[off+5])<<40 | uint64(seed[off+6])<<48 | uint64(seed[off+7])<<56
}

func checkState2(t *testing.T, s *State2, sGen []State1) {
	t.Helper()
	for i := range 25 {
		for j := range 2 {
			if s.lane2val(i, j) != sGen[j].a[i] {
				t.Fatalf("state lane %d inst %d: gen=%016x asm=%016x", i, j, sGen[j].a[i], s.lane2val(i, j))
			}
		}
	}
}

func checkState8(t *testing.T, s *State8, sGen []State1) {
	t.Helper()
	for i := range 25 {
		for j := range 8 {
			if s.a[i][j] != sGen[j].a[i] {
				t.Fatalf("state lane %d inst %d: gen=%016x asm=%016x", i, j, sGen[j].a[i], s.a[i][j])
			}
		}
	}
}

func FuzzFastLoopEncrypt168(f *testing.F) {
	for _, nBlocks := range []int{1, 2, 3, 5, 10, 50} {
		f.Add(nBlocks, "seed")
	}
	f.Fuzz(func(t *testing.T, nBlocks int, seed string) {
		if nBlocks < 1 || nBlocks > 200 {
			t.Skip()
		}
		for _, nInst := range []int{2, 8} {
			t.Run(fmt.Sprintf("x%d", nInst), func(t *testing.T) {
				fuzzEncryptN(t, nInst, nBlocks, seed)
			})
		}
	})
}

func FuzzFastLoopDecrypt168(f *testing.F) {
	for _, nBlocks := range []int{1, 2, 3, 5, 10, 50} {
		f.Add(nBlocks, "seed")
	}
	f.Fuzz(func(t *testing.T, nBlocks int, seed string) {
		if nBlocks < 1 || nBlocks > 200 {
			t.Skip()
		}
		for _, nInst := range []int{2, 8} {
			t.Run(fmt.Sprintf("x%d", nInst), func(t *testing.T) {
				fuzzDecryptN(t, nInst, nBlocks, seed)
			})
		}
	})
}
