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

func TestAbsorbWords4(t *testing.T) {
	var s State1
	s.AbsorbWords4(1, 2, 3, 4)
	if got := s.Lane(0); got != 1 {
		t.Fatalf("lane 0 = %d, want 1", got)
	}
	if got := s.Lane(1); got != 2 {
		t.Fatalf("lane 1 = %d, want 2", got)
	}
	if got := s.Lane(2); got != 3 {
		t.Fatalf("lane 2 = %d, want 3", got)
	}
	if got := s.Lane(3); got != 4 {
		t.Fatalf("lane 3 = %d, want 4", got)
	}
}

func TestFastLoopAbsorb168State1(t *testing.T) {
	in := testPattern(3*168 + 17)
	var a, b State1
	n := a.FastLoopAbsorb168(in)
	if n != 3*168 {
		t.Fatalf("consumed %d, want %d", n, 3*168)
	}
	for off := 0; off < n; off += 168 {
		b.Absorb168(in[off : off+168])
		b.Permute12()
	}
	if a != b {
		t.Fatalf("state mismatch after fast loop")
	}

	a.AbsorbFinal(in[n:], 0x0B)
	a.Permute12()
	b.AbsorbFinalStripe(168, in[n:], 0x0B)
	b.Permute12()
	if a != b {
		t.Fatalf("state mismatch after final absorb")
	}
}

func TestFastLoopAbsorb168State2(t *testing.T) {
	in0 := testPattern(2*168 + 17)
	in1 := testPattern(2*168 + 29)[:2*168+17]
	var a, b State2
	n := a.FastLoopAbsorb168(in0, in1)
	if n != 2*168 {
		t.Fatalf("consumed %d, want %d", n, 2*168)
	}
	for off := 0; off < n; off += 168 {
		b.AbsorbStripe2(168, in0[off:off+168], in1[off:off+168])
		b.Permute12()
	}
	if a != b {
		t.Fatalf("state mismatch after fast loop")
	}

	a.AbsorbFinal(in0[n:], in1[n:], 0x0B)
	a.Permute12()
	b.AbsorbFinalStripe2(168, in0[n:], in1[n:], 0x0B)
	b.Permute12()
	if a != b {
		t.Fatalf("state mismatch after final absorb")
	}
}

func TestFastLoopAbsorb168State4(t *testing.T) {
	in0 := testPattern(2*168 + 5)
	in1 := testPattern(2*168 + 7)[:2*168+5]
	in2 := testPattern(2*168 + 9)[:2*168+5]
	in3 := testPattern(2*168 + 11)[:2*168+5]
	var a, b State4
	n := a.FastLoopAbsorb168(in0, in1, in2, in3)
	if n != 2*168 {
		t.Fatalf("consumed %d, want %d", n, 2*168)
	}
	for off := 0; off < n; off += 168 {
		b.AbsorbStripe4(168, in0[off:off+168], in1[off:off+168], in2[off:off+168], in3[off:off+168])
		b.Permute12()
	}
	if a != b {
		t.Fatalf("state mismatch after fast loop")
	}

	a.AbsorbFinal(in0[n:], in1[n:], in2[n:], in3[n:], 0x0B)
	a.Permute12()
	b.AbsorbFinalStripe4(168, in0[n:], in1[n:], in2[n:], in3[n:], 0x0B)
	b.Permute12()
	if a != b {
		t.Fatalf("state mismatch after final absorb")
	}
}

func TestFastLoopAbsorb168State8(t *testing.T) {
	in0 := testPattern(2*168 + 3)
	in1 := testPattern(2*168 + 5)[:2*168+3]
	in2 := testPattern(2*168 + 7)[:2*168+3]
	in3 := testPattern(2*168 + 9)[:2*168+3]
	in4 := testPattern(2*168 + 11)[:2*168+3]
	in5 := testPattern(2*168 + 13)[:2*168+3]
	in6 := testPattern(2*168 + 15)[:2*168+3]
	in7 := testPattern(2*168 + 17)[:2*168+3]
	var a, b State8
	n := a.FastLoopAbsorb168(in0, in1, in2, in3, in4, in5, in6, in7)
	if n != 2*168 {
		t.Fatalf("consumed %d, want %d", n, 2*168)
	}
	for off := 0; off < n; off += 168 {
		b.AbsorbStripe8(
			168,
			in0[off:off+168],
			in1[off:off+168],
			in2[off:off+168],
			in3[off:off+168],
			in4[off:off+168],
			in5[off:off+168],
			in6[off:off+168],
			in7[off:off+168],
		)
		b.Permute12()
	}
	if a != b {
		t.Fatalf("state mismatch after fast loop")
	}

	a.AbsorbFinal(in0[n:], in1[n:], in2[n:], in3[n:], in4[n:], in5[n:], in6[n:], in7[n:], 0x0B)
	a.Permute12()
	b.AbsorbFinalStripe8(168, in0[n:], in1[n:], in2[n:], in3[n:], in4[n:], in5[n:], in6[n:], in7[n:], 0x0B)
	b.Permute12()
	if a != b {
		t.Fatalf("state mismatch after final absorb")
	}
}
