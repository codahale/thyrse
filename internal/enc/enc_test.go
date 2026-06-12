package enc

import (
	"bytes"
	"fmt"
	"testing"
)

func TestRightEncode(t *testing.T) {
	tests := []struct {
		x    uint64
		want []byte
	}{
		{0, []byte{0x00, 0x01}},
		{1, []byte{0x01, 0x01}},
		{255, []byte{0xFF, 0x01}},
		{256, []byte{0x01, 0x00, 0x02}},
		{0x123456, []byte{0x12, 0x34, 0x56, 0x03}},
		{0xFFFFFFFFFFFFFFFF, []byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x08}},
	}
	for _, tt := range tests {
		t.Run(fmt.Sprintf("%d", tt.x), func(t *testing.T) {
			var buf [9]byte
			if got, want := RightEncode(buf[:0], tt.x), tt.want; !bytes.Equal(got, want) {
				t.Errorf("RightEncode(%d) = %x, want %x", tt.x, got, want)
			}
		})
	}

	t.Run("append", func(t *testing.T) {
		if got, want := RightEncode([]byte{0xAA}, 1), []byte{0xAA, 0x01, 0x01}; !bytes.Equal(got, want) {
			t.Errorf("RightEncode({0xAA}, 1) = %x, want %x", got, want)
		}
	})
}
