package enc

import (
	"bytes"
	"fmt"
	"testing"
)

func TestLeftEncode(t *testing.T) {
	tests := []struct {
		x    uint64
		want []byte
	}{
		{0, []byte{0x01, 0x00}},
		{1, []byte{0x01, 0x01}},
		{255, []byte{0x01, 0xFF}},
		{256, []byte{0x02, 0x01, 0x00}},
		{0x123456, []byte{0x03, 0x12, 0x34, 0x56}},
		{0xFFFFFFFFFFFFFFFF, []byte{0x08, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}},
	}
	for _, tt := range tests {
		t.Run(fmt.Sprintf("%d", tt.x), func(t *testing.T) {
			var buf [9]byte
			if got, want := LeftEncode(buf[:0], tt.x), tt.want; !bytes.Equal(got, want) {
				t.Errorf("LeftEncode(%d) = %x, want %x", tt.x, got, want)
			}
		})
	}
}

func TestEncodeString(t *testing.T) {
	tests := []struct {
		name string
		data []byte
		want []byte
	}{
		{"empty", nil, []byte{0x01, 0x00}},
		{"one byte", []byte{0xAB}, []byte{0x01, 0x08, 0xAB}},
		{"short", []byte("hello"), []byte{0x01, 0x28, 'h', 'e', 'l', 'l', 'o'}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf [64]byte
			if got, want := EncodeString(buf[:0], tt.data), tt.want; !bytes.Equal(got, want) {
				t.Errorf("EncodeString(%x) = %x, want %x", tt.data, got, want)
			}
		})
	}
}
