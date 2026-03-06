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
	Permute4 []permuteCaseN `json:"permute4"`
	Permute8 []permuteCaseN `json:"permute8"`
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
		path := filepath.Join("testdata", "legacy_vectors.json")
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
	if len(in) != StateBytes {
		t.Fatalf("state1 bytes: got %d want %d", len(in), StateBytes)
	}
	var s State1
	for lane := range Lanes {
		base := lane * 8
		s.a[lane] = binary.LittleEndian.Uint64(in[base : base+8])
	}
	return s
}

func state1Bytes(s *State1) []byte {
	out := make([]byte, StateBytes)
	for lane := range Lanes {
		base := lane * 8
		binary.LittleEndian.PutUint64(out[base:base+8], s.a[lane])
	}
	return out
}

func stateNSetBytes[T ~int](slices [][]byte, width T, set func(inst, lane int, v uint64)) {
	for inst := range int(width) {
		for lane := range Lanes {
			base := lane * 8
			set(inst, lane, binary.LittleEndian.Uint64(slices[inst][base:base+8]))
		}
	}
}

func stateNBytes(width int, get func(inst, lane int) uint64) [][]byte {
	out := make([][]byte, width)
	for inst := range width {
		b := make([]byte, StateBytes)
		for lane := range Lanes {
			base := lane * 8
			binary.LittleEndian.PutUint64(b[base:base+8], get(inst, lane))
		}
		out[inst] = b
	}
	return out
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

		var d Duplex
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
		s.Permute12()
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
		var s State2
		stateNSetBytes(ins, 2, func(inst, lane int, v uint64) { s.a[lane][inst] = v })
		s.Permute12()
		for inst, got := range stateNBytes(2, func(i, lane int) uint64 { return s.a[lane][i] }) {
			if string(got) != string(wants[inst]) {
				t.Fatalf("permute2[%d] lane %d mismatch", i, inst)
			}
		}
	}
}

func TestPermuteVectorsState4(t *testing.T) {
	vectors := loadVectors(t)
	for i, tc := range vectors.Permute4 {
		ins := stateNFromHex(t, tc.In, 4)
		wants := stateNFromHex(t, tc.Out, 4)
		var s State4
		stateNSetBytes(ins, 4, func(inst, lane int, v uint64) { s.a[lane][inst] = v })
		s.Permute12()
		for inst, got := range stateNBytes(4, func(i, lane int) uint64 { return s.a[lane][i] }) {
			if string(got) != string(wants[inst]) {
				t.Fatalf("permute4[%d] lane %d mismatch", i, inst)
			}
		}
	}
}

func TestPermuteVectorsState8(t *testing.T) {
	vectors := loadVectors(t)
	for i, tc := range vectors.Permute8 {
		ins := stateNFromHex(t, tc.In, 8)
		wants := stateNFromHex(t, tc.Out, 8)
		var s State8
		stateNSetBytes(ins, 8, func(inst, lane int, v uint64) { s.a[lane][inst] = v })
		s.Permute12()
		for inst, got := range stateNBytes(8, func(i, lane int) uint64 { return s.a[lane][i] }) {
			if string(got) != string(wants[inst]) {
				t.Fatalf("permute8[%d] lane %d mismatch", i, inst)
			}
		}
	}
}
