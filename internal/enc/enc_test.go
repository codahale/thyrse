package enc

import (
	"bytes"
	"fmt"
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
	for _, tt := range tests {
		t.Run(fmt.Sprintf("%d", tt.x), func(t *testing.T) {
			if got, want := LengthEncode(tt.x), tt.want; !bytes.Equal(got, want) {
				t.Errorf("LengthEncode(%d) = %x, want %x", tt.x, got, want)
			}
		})
	}
}

func TestLeftEncode(t *testing.T) {
	tests := []struct {
		x    uint64
		want []byte
	}{
		{0, []byte{0x01, 0x00}},
		{127, []byte{0x01, 0x7F}},
		{255, []byte{0x01, 0xFF}},
		{256, []byte{0x02, 0x01, 0x00}},
		{512, []byte{0x02, 0x02, 0x00}},
		{0x123456, []byte{0x03, 0x12, 0x34, 0x56}},
	}
	for _, tt := range tests {
		t.Run(fmt.Sprintf("%d", tt.x), func(t *testing.T) {
			if got := LeftEncode(tt.x); !bytes.Equal(got, tt.want) {
				t.Errorf("LeftEncode(%d) = %x, want %x", tt.x, got, tt.want)
			}
		})
	}
}

func TestEncodeString(t *testing.T) {
	tests := []struct {
		name string
		x    []byte
		want []byte
	}{
		{"empty", nil, []byte{0x01, 0x00}},
		{"1 byte", []byte{0xAB}, []byte{0x01, 0x08, 0xAB}},
		{"31 bytes", bytes.Repeat([]byte{0xFF}, 31), append([]byte{0x01, 0xF8}, bytes.Repeat([]byte{0xFF}, 31)...)},
		{"32 bytes", bytes.Repeat([]byte{0xFF}, 32), append([]byte{0x02, 0x01, 0x00}, bytes.Repeat([]byte{0xFF}, 32)...)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := EncodeString(tt.x); !bytes.Equal(got, tt.want) {
				t.Errorf("EncodeString(%x) = %x, want %x", tt.x, got, tt.want)
			}
		})
	}
}
