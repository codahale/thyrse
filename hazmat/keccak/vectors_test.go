package keccak

import (
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
	Rate   int    `json:"rate"`
	DS     byte   `json:"ds"`
	Msg    string `json:"msg"`
	OutLen int    `json:"out_len"`
	Out    string `json:"out"`
}

type overwriteCase struct {
	Rate              int    `json:"rate"`
	State             string `json:"state"`
	Plain             string `json:"plain"`
	Cipher            string `json:"cipher"`
	StateAfterEncrypt string `json:"state_after_encrypt"`
	Decrypted         string `json:"decrypted"`
	StateAfterDecrypt string `json:"state_after_decrypt"`
}

type vectorFile struct {
	Permute1  []permuteCase1  `json:"permute1"`
	Permute2  []permuteCaseN  `json:"permute2"`
	Permute4  []permuteCaseN  `json:"permute4"`
	Permute8  []permuteCaseN  `json:"permute8"`
	Sponge    []spongeCase    `json:"sponge"`
	Overwrite []overwriteCase `json:"overwrite"`
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
	for i := range StateBytes {
		s.setByte(i, in[i])
	}
	return s
}

func state1Bytes(s *State1) []byte {
	out := make([]byte, StateBytes)
	for i := range StateBytes {
		out[i] = s.getByte(i)
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
		for inst := range 2 {
			for b := range StateBytes {
				s.setByte(inst, b, ins[inst][b])
			}
		}
		s.Permute12()
		for inst := range 2 {
			got := make([]byte, StateBytes)
			for b := range StateBytes {
				got[b] = s.getByte(inst, b)
			}
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
		for inst := range 4 {
			for b := range StateBytes {
				s.setByte(inst, b, ins[inst][b])
			}
		}
		s.Permute12()
		for inst := range 4 {
			got := make([]byte, StateBytes)
			for b := range StateBytes {
				got[b] = s.getByte(inst, b)
			}
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
		for inst := range 8 {
			for b := range StateBytes {
				s.setByte(inst, b, ins[inst][b])
			}
		}
		s.Permute12()
		for inst := range 8 {
			got := make([]byte, StateBytes)
			for b := range StateBytes {
				got[b] = s.getByte(inst, b)
			}
			if string(got) != string(wants[inst]) {
				t.Fatalf("permute8[%d] lane %d mismatch", i, inst)
			}
		}
	}
}

func TestSpongeVectorsState1(t *testing.T) {
	vectors := loadVectors(t)
	for i, tc := range vectors.Sponge {
		msg := mustHex(t, tc.Msg)
		want := mustHex(t, tc.Out)

		var s State1
		block := make([]byte, tc.Rate)
		pos := 0
		for len(msg) > 0 {
			w := min(tc.Rate-pos, len(msg))
			for j := range w {
				block[pos+j] ^= msg[j]
			}
			pos += w
			msg = msg[w:]
			if pos == tc.Rate {
				s.AbsorbStripe(tc.Rate, block)
				s.Permute12()
				clear(block)
				pos = 0
			}
		}

		block[pos] ^= tc.DS
		block[tc.Rate-1] ^= 0x80
		s.AbsorbStripe(tc.Rate, block)
		s.Permute12()

		got := make([]byte, tc.OutLen)
		outPos := 0
		stripe := make([]byte, tc.Rate)
		for outPos < len(got) {
			s.SqueezeStripe(tc.Rate, stripe)
			n := min(tc.Rate, len(got)-outPos)
			copy(got[outPos:outPos+n], stripe[:n])
			outPos += n
			if outPos < len(got) {
				s.Permute12()
			}
		}

		if string(got) != string(want) {
			t.Fatalf("sponge[%d] mismatch", i)
		}
	}
}

func TestOverwriteVectorsState1(t *testing.T) {
	vectors := loadVectors(t)
	for i, tc := range vectors.Overwrite {
		state := mustHex(t, tc.State)
		plain := mustHex(t, tc.Plain)
		wantCipher := mustHex(t, tc.Cipher)
		wantStateAfterEnc := mustHex(t, tc.StateAfterEncrypt)
		wantDecrypted := mustHex(t, tc.Decrypted)
		wantStateAfterDec := mustHex(t, tc.StateAfterDecrypt)

		sEnc := state1FromBytes(t, state)
		gotCipher := make([]byte, tc.Rate)
		sEnc.OverwriteEncryptStripe(tc.Rate, gotCipher, plain)
		if string(gotCipher) != string(wantCipher) {
			t.Fatalf("overwrite encrypt[%d] ciphertext mismatch", i)
		}
		if got := state1Bytes(&sEnc); string(got) != string(wantStateAfterEnc) {
			t.Fatalf("overwrite encrypt[%d] state mismatch", i)
		}

		sDec := state1FromBytes(t, state)
		gotPlain := make([]byte, tc.Rate)
		sDec.OverwriteDecryptStripe(tc.Rate, gotPlain, wantCipher)
		if string(gotPlain) != string(wantDecrypted) {
			t.Fatalf("overwrite decrypt[%d] plaintext mismatch", i)
		}
		if got := state1Bytes(&sDec); string(got) != string(wantStateAfterDec) {
			t.Fatalf("overwrite decrypt[%d] state mismatch", i)
		}
	}
}

func TestBackendSelectionSanity(t *testing.T) {
	if AvailableLanes < 1 {
		t.Fatalf("invalid available lanes: %d", AvailableLanes)
	}
	if forcedBackend != "" && backendName() != forcedBackend {
		t.Fatalf("forced backend mismatch: got %q want %q", backendName(), forcedBackend)
	}
}
