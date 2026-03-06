package encoding

import (
	"bytes"
	"testing"
)

func TestLengthEncode(t *testing.T) {
	tests := []struct {
		x    uint64
		want []byte
	}{
		{0, []byte{0x00}},
		{1, []byte{0x01, 0x01}},
		{255, []byte{0xFF, 0x01}},
		{256, []byte{0x01, 0x00, 0x02}},
		{0x123456, []byte{0x12, 0x34, 0x56, 0x03}},
	}
	for _, tc := range tests {
		got := LengthEncode(tc.x)
		if !bytes.Equal(got, tc.want) {
			t.Errorf("LengthEncode(%d) = %x, want %x", tc.x, got, tc.want)
		}
	}
}
