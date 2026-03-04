package keccak

import (
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
