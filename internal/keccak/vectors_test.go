package keccak

import (
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

type permuteCase1 struct {
	In  string `json:"in"`
	Out string `json:"out"`
}

type permuteCaseN struct {
	In  []string `json:"in"`
	Out []string `json:"out"`
}

type spongeCase struct {
	Rate   int    `json:"Rate"`
	DS     byte   `json:"ds"`
	Msg    string `json:"msg"`
	OutLen int    `json:"out_len"`
	Out    string `json:"out"`
}

type vectorFile struct {
	Permute1 []permuteCase1 `json:"permute1"`
	Permute2 []permuteCaseN `json:"permute2"`
	Sponge   []spongeCase   `json:"sponge"`
}

var (
	vectorsOnce sync.Once
	vectorsData vectorFile
	vectorsErr  error
)

func loadVectors(t *testing.T) vectorFile {
	t.Helper()
	vectorsOnce.Do(func() {
		path := filepath.Join("testdata", "keccakp_vectors.json")
		raw, err := os.ReadFile(path)
		if err != nil {
			vectorsErr = err
			return
		}
		vectorsErr = json.Unmarshal(raw, &vectorsData)
	})
	if vectorsErr != nil {
		t.Fatalf("load vectors: %v", vectorsErr)
	}
	return vectorsData
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("decode hex: %v", err)
	}
	return b
}

func state1FromBytes(t *testing.T, in []byte) State1 {
	t.Helper()
	if len(in) != stateBytes {
		t.Fatalf("state1 bytes: got %d want %d", len(in), stateBytes)
	}
	var s State1
	for lane := range lanes {
		base := lane * 8
		s.a[lane] = binary.LittleEndian.Uint64(in[base : base+8])
	}
	return s
}

func state1Bytes(s *State1) []byte {
	out := make([]byte, stateBytes)
	for lane := range lanes {
		base := lane * 8
		binary.LittleEndian.PutUint64(out[base:base+8], s.a[lane])
	}
	return out
}

func stateNSetBytes[T ~int](slices [][]byte, width T, set func(inst, lane int, v uint64)) {
	for inst := range int(width) {
		for lane := range lanes {
			base := lane * 8
			set(inst, lane, binary.LittleEndian.Uint64(slices[inst][base:base+8]))
		}
	}
}

func stateNFromHex[T ~int](t *testing.T, in []string, width T) [][]byte {
	t.Helper()
	if len(in) != int(width) {
		t.Fatalf("state width: got %d want %d", len(in), width)
	}
	out := make([][]byte, len(in))
	for i := range in {
		out[i] = mustHex(t, in[i])
	}
	return out
}

func TestDuplexSpongeVectors(t *testing.T) {
	vectors := loadVectors(t)
	for i, tc := range vectors.Sponge {
		if tc.Rate != Rate {
			continue
		}
		msg := mustHex(t, tc.Msg)
		want := mustHex(t, tc.Out)

		var d State1
		d.Absorb(msg)
		d.PadPermute(tc.DS)

		got := make([]byte, tc.OutLen)
		d.Squeeze(got)
		if string(got) != string(want) {
			t.Fatalf("sponge[%d] mismatch: msg_len=%d ds=0x%02x out_len=%d",
				i, len(msg), tc.DS, tc.OutLen)
		}
	}
}

func TestPermuteVectorsState1(t *testing.T) {
	vectors := loadVectors(t)
	for i, tc := range vectors.Permute1 {
		in := mustHex(t, tc.In)
		want := mustHex(t, tc.Out)
		s := state1FromBytes(t, in)
		s.permute12()
		got := state1Bytes(&s)
		if string(got) != string(want) {
			t.Fatalf("permute1[%d] mismatch", i)
		}
	}
}

func TestPermuteVectorsState2(t *testing.T) {
	vectors := loadVectors(t)
	for i, tc := range vectors.Permute2 {
		ins := stateNFromHex(t, tc.In, 2)
		wants := stateNFromHex(t, tc.Out, 2)
		for inst := range 2 {
			s := state1FromBytes(t, ins[inst])
			s.permute12()
			got := state1Bytes(&s)
			if string(got) != string(wants[inst]) {
				t.Fatalf("permute2[%d] inst %d mismatch", i, inst)
			}
		}
	}
}

func TestDuplexEncryptDecryptRoundTrip(t *testing.T) {
	for _, size := range []int{0, 1, 7, 8, 100, 167, 168, 169, 336, 1000} {
		pt := make([]byte, size)
		for i := range pt {
			pt[i] = byte(i)
		}

		// Encrypt.
		var enc State1
		enc.Absorb([]byte("test-key"))
		enc.PadPermute(0x08)
		ct := make([]byte, size)
		enc.encrypt(ct, pt)
		encPos := enc.pos

		// Decrypt with same init.
		var dec State1
		dec.Absorb([]byte("test-key"))
		dec.PadPermute(0x08)
		recovered := make([]byte, size)
		dec.decrypt(recovered, ct)
		decPos := dec.pos

		if string(recovered) != string(pt) {
			t.Fatalf("size=%d: plaintext mismatch", size)
		}
		if encPos != decPos {
			t.Fatalf("size=%d: pos mismatch enc=%d dec=%d", size, encPos, decPos)
		}
		if size > 0 && string(ct) == string(pt) {
			t.Fatalf("size=%d: ciphertext equals plaintext", size)
		}
	}
}

func TestDuplexAbsorbCV(t *testing.T) {
	// Build a State1 with known lane values.
	var leaf State1
	leaf.a[0] = 0x0102030405060708
	leaf.a[1] = 0x090a0b0c0d0e0f10
	leaf.a[2] = 0x1112131415161718
	leaf.a[3] = 0x191a1b1c1d1e1f20

	// Absorb via AbsorbCV.
	var d1 State1
	d1.AbsorbCV(&leaf)

	// Absorb via manual byte extraction + Absorb.
	var cv [32]byte
	binary.LittleEndian.PutUint64(cv[0:8], leaf.a[0])
	binary.LittleEndian.PutUint64(cv[8:16], leaf.a[1])
	binary.LittleEndian.PutUint64(cv[16:24], leaf.a[2])
	binary.LittleEndian.PutUint64(cv[24:32], leaf.a[3])
	var d2 State1
	d2.Absorb(cv[:])

	if d1 != d2 {
		t.Fatal("AbsorbCV and Absorb(cv[:]) diverged")
	}
}

func TestDuplexEqual(t *testing.T) {
	var a, b State1
	a.Absorb([]byte("same"))
	b.Absorb([]byte("same"))
	if got, want := a.Equal(&b), 1; got != want {
		t.Fatalf("Equal() = %d, want %d", got, want)
	}

	b.Absorb([]byte("x"))
	if got, want := a.Equal(&b), 0; got != want {
		t.Fatalf("Equal() = %d, want %d", got, want)
	}
}
