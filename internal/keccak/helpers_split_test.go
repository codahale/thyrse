package keccak

import (
	"encoding/binary"
	"fmt"
	"testing"
)

func testPattern(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte((i*37 + 13) & 0xFF)
	}
	return b
}

func TestAbsorbStripe2MatchesPacked(t *testing.T) {
	rates := []int{1, 7, 8, 9, 31, 32, 33, 64, 135, 136, 167, 168}
	for _, rate := range rates {
		t.Run(fmt.Sprintf("rate_%d", rate), func(t *testing.T) {
			in0 := testPattern(rate)
			in1 := testPattern(rate + 101)[:rate]
			packed := make([]byte, 2*rate)
			copy(packed[:rate], in0)
			copy(packed[rate:], in1)

			var a, b State2
			a.AbsorbStripe2(rate, in0, in1)
			b.AbsorbStripe(rate, packed)
			if a != b {
				t.Fatalf("state mismatch for rate=%d", rate)
			}
		})
	}
}

func TestAbsorbStripe4MatchesPacked(t *testing.T) {
	rates := []int{1, 7, 8, 9, 31, 32, 33, 64, 135, 136, 167, 168}
	for _, rate := range rates {
		t.Run(fmt.Sprintf("rate_%d", rate), func(t *testing.T) {
			in0 := testPattern(rate)
			in1 := testPattern(rate + 11)[:rate]
			in2 := testPattern(rate + 23)[:rate]
			in3 := testPattern(rate + 47)[:rate]
			packed := make([]byte, 4*rate)
			copy(packed[:rate], in0)
			copy(packed[rate:2*rate], in1)
			copy(packed[2*rate:3*rate], in2)
			copy(packed[3*rate:], in3)

			var a, b State4
			a.AbsorbStripe4(rate, in0, in1, in2, in3)
			b.AbsorbStripe(rate, packed)
			if a != b {
				t.Fatalf("state mismatch for rate=%d", rate)
			}
		})
	}
}

func TestAbsorbStripe8MatchesPacked(t *testing.T) {
	rates := []int{1, 7, 8, 9, 31, 32, 33, 64, 135, 136, 167, 168}
	for _, rate := range rates {
		t.Run(fmt.Sprintf("rate_%d", rate), func(t *testing.T) {
			in0 := testPattern(rate)
			in1 := testPattern(rate + 3)[:rate]
			in2 := testPattern(rate + 5)[:rate]
			in3 := testPattern(rate + 7)[:rate]
			in4 := testPattern(rate + 11)[:rate]
			in5 := testPattern(rate + 13)[:rate]
			in6 := testPattern(rate + 17)[:rate]
			in7 := testPattern(rate + 19)[:rate]
			packed := make([]byte, 8*rate)
			copy(packed[:rate], in0)
			copy(packed[rate:2*rate], in1)
			copy(packed[2*rate:3*rate], in2)
			copy(packed[3*rate:4*rate], in3)
			copy(packed[4*rate:5*rate], in4)
			copy(packed[5*rate:6*rate], in5)
			copy(packed[6*rate:7*rate], in6)
			copy(packed[7*rate:], in7)

			var a, b State8
			a.AbsorbStripe8(rate, in0, in1, in2, in3, in4, in5, in6, in7)
			b.AbsorbStripe(rate, packed)
			if a != b {
				t.Fatalf("state mismatch for rate=%d", rate)
			}
		})
	}
}

func TestAbsorbFinalStripe1MatchesConstructedBlock(t *testing.T) {
	rate := 168
	for _, rem := range []int{0, 1, 7, 8, 31, 32, 127, 167} {
		t.Run(fmt.Sprintf("rem_%d", rem), func(t *testing.T) {
			tail := testPattern(rem)
			var a, b State1
			a.AbsorbFinalStripe(rate, tail, 0x0B)

			block := make([]byte, rate)
			copy(block, tail)
			block[rem] ^= 0x0B
			block[rate-1] ^= 0x80
			b.AbsorbStripe(rate, block)
			if a != b {
				t.Fatalf("state mismatch")
			}
		})
	}
}

func TestAbsorbFinalStripe2MatchesConstructedBlock(t *testing.T) {
	rate := 168
	for _, rem := range []int{0, 1, 7, 8, 31, 32, 127, 167} {
		t.Run(fmt.Sprintf("rem_%d", rem), func(t *testing.T) {
			t0 := testPattern(rem)
			t1 := testPattern(rem + 9)[:rem]
			var a, b State2
			a.AbsorbFinalStripe2(rate, t0, t1, 0x0B)

			packed := make([]byte, 2*rate)
			copy(packed[:rem], t0)
			copy(packed[rate:rate+rem], t1)
			packed[rem] ^= 0x0B
			packed[rate+rem] ^= 0x0B
			packed[rate-1] ^= 0x80
			packed[2*rate-1] ^= 0x80
			b.AbsorbStripe(rate, packed)
			if a != b {
				t.Fatalf("state mismatch")
			}
		})
	}
}

func TestAbsorbFinalStripe4MatchesConstructedBlock(t *testing.T) {
	rate := 168
	for _, rem := range []int{0, 1, 7, 8, 31, 32, 127, 167} {
		t.Run(fmt.Sprintf("rem_%d", rem), func(t *testing.T) {
			t0 := testPattern(rem)
			t1 := testPattern(rem + 3)[:rem]
			t2 := testPattern(rem + 5)[:rem]
			t3 := testPattern(rem + 7)[:rem]
			var a, b State4
			a.AbsorbFinalStripe4(rate, t0, t1, t2, t3, 0x0B)

			packed := make([]byte, 4*rate)
			copy(packed[:rem], t0)
			copy(packed[rate:rate+rem], t1)
			copy(packed[2*rate:2*rate+rem], t2)
			copy(packed[3*rate:3*rate+rem], t3)
			for inst := 0; inst < 4; inst++ {
				packed[inst*rate+rem] ^= 0x0B
				packed[(inst+1)*rate-1] ^= 0x80
			}
			b.AbsorbStripe(rate, packed)
			if a != b {
				t.Fatalf("state mismatch")
			}
		})
	}
}

func TestAbsorbFinalStripe8MatchesConstructedBlock(t *testing.T) {
	rate := 168
	for _, rem := range []int{0, 1, 7, 8, 31, 32, 127, 167} {
		t.Run(fmt.Sprintf("rem_%d", rem), func(t *testing.T) {
			t0 := testPattern(rem)
			t1 := testPattern(rem + 3)[:rem]
			t2 := testPattern(rem + 5)[:rem]
			t3 := testPattern(rem + 7)[:rem]
			t4 := testPattern(rem + 11)[:rem]
			t5 := testPattern(rem + 13)[:rem]
			t6 := testPattern(rem + 17)[:rem]
			t7 := testPattern(rem + 19)[:rem]
			var a, b State8
			a.AbsorbFinalStripe8(rate, t0, t1, t2, t3, t4, t5, t6, t7, 0x0B)

			packed := make([]byte, 8*rate)
			copy(packed[:rem], t0)
			copy(packed[rate:rate+rem], t1)
			copy(packed[2*rate:2*rate+rem], t2)
			copy(packed[3*rate:3*rate+rem], t3)
			copy(packed[4*rate:4*rate+rem], t4)
			copy(packed[5*rate:5*rate+rem], t5)
			copy(packed[6*rate:6*rate+rem], t6)
			copy(packed[7*rate:7*rate+rem], t7)
			for inst := 0; inst < 8; inst++ {
				packed[inst*rate+rem] ^= 0x0B
				packed[(inst+1)*rate-1] ^= 0x80
			}
			b.AbsorbStripe(rate, packed)
			if a != b {
				t.Fatalf("state mismatch")
			}
		})
	}
}

func TestExtractLanesWordsMatchesSqueeze(t *testing.T) {
	lanes := 4
	rate := lanes * 8

	t.Run("state1", func(t *testing.T) {
		var s State1
		in := testPattern(rate)
		s.AbsorbStripe(rate, in)
		var got [4]uint64
		s.ExtractLanesWords(lanes, got[:])
		out := make([]byte, rate)
		s.SqueezeStripe(rate, out)
		for i := range lanes {
			want := binary.LittleEndian.Uint64(out[i*8 : (i+1)*8])
			if got[i] != want {
				t.Fatalf("lane %d mismatch", i)
			}
		}
	})

	t.Run("state2", func(t *testing.T) {
		var s State2
		in := testPattern(2 * rate)
		s.AbsorbStripe(rate, in)
		var got [8]uint64
		s.ExtractLanesWords(lanes, got[:])
		out := make([]byte, 2*rate)
		s.SqueezeStripe(rate, out)
		for inst := range 2 {
			for lane := range lanes {
				want := binary.LittleEndian.Uint64(out[inst*rate+lane*8 : inst*rate+(lane+1)*8])
				if got[inst*lanes+lane] != want {
					t.Fatalf("inst %d lane %d mismatch", inst, lane)
				}
			}
		}
	})

	t.Run("state4", func(t *testing.T) {
		var s State4
		in := testPattern(4 * rate)
		s.AbsorbStripe(rate, in)
		var got [16]uint64
		s.ExtractLanesWords(lanes, got[:])
		out := make([]byte, 4*rate)
		s.SqueezeStripe(rate, out)
		for inst := range 4 {
			for lane := range lanes {
				want := binary.LittleEndian.Uint64(out[inst*rate+lane*8 : inst*rate+(lane+1)*8])
				if got[inst*lanes+lane] != want {
					t.Fatalf("inst %d lane %d mismatch", inst, lane)
				}
			}
		}
	})

	t.Run("state8", func(t *testing.T) {
		var s State8
		in := testPattern(8 * rate)
		s.AbsorbStripe(rate, in)
		var got [32]uint64
		s.ExtractLanesWords(lanes, got[:])
		out := make([]byte, 8*rate)
		s.SqueezeStripe(rate, out)
		for inst := range 8 {
			for lane := range lanes {
				want := binary.LittleEndian.Uint64(out[inst*rate+lane*8 : inst*rate+(lane+1)*8])
				if got[inst*lanes+lane] != want {
					t.Fatalf("inst %d lane %d mismatch", inst, lane)
				}
			}
		}
	})
}
