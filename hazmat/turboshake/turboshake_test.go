package turboshake

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"
)

// ptn generates the RFC 9861 test pattern: repeating 0x00..0xFA truncated to n bytes.
func ptn(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i % 251)
	}
	return b
}

// hexDecode decodes a space-separated hex string.
func hexDecode(s string) []byte {
	s = strings.ReplaceAll(s, " ", "")
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

// RFC 9861 Section 5 test vectors for TurboSHAKE128.
var testVectors = []struct {
	name   string
	msg    []byte
	ds     byte
	outLen int
	want   string // hex of expected output (or last 32 bytes for truncated vectors)
	last32 bool   // true if want contains only the last 32 bytes
}{
	{
		name:   "empty/D=1F/L=32",
		msg:    nil,
		ds:     0x1F,
		outLen: 32,
		want:   "1E 41 5F 1C 59 83 AF F2 16 92 17 27 7D 17 BB 53 8C D9 45 A3 97 DD EC 54 1F 1C E4 1A F2 C1 B7 4C",
	},
	{
		name:   "empty/D=1F/L=64",
		msg:    nil,
		ds:     0x1F,
		outLen: 64,
		want:   "1E 41 5F 1C 59 83 AF F2 16 92 17 27 7D 17 BB 53 8C D9 45 A3 97 DD EC 54 1F 1C E4 1A F2 C1 B7 4C 3E 8C CA E2 A4 DA E5 6C 84 A0 4C 23 85 C0 3C 15 E8 19 3B DF 58 73 73 63 32 16 91 C0 54 62 C8 DF",
	},
	{
		name:   "empty/D=1F/L=10032",
		msg:    nil,
		ds:     0x1F,
		outLen: 10032,
		want:   "A3 B9 B0 38 59 00 CE 76 1F 22 AE D5 48 E7 54 DA 10 A5 24 2D 62 E8 C6 58 E3 F3 A9 23 A7 55 56 07",
		last32: true,
	},
	{
		name:   "ptn(1)/D=1F/L=32",
		msg:    ptn(1),
		ds:     0x1F,
		outLen: 32,
		want:   "55 CE DD 6F 60 AF 7B B2 9A 40 42 AE 83 2E F3 F5 8D B7 29 9F 89 3E BB 92 47 24 7D 85 69 58 DA A9",
	},
	{
		name:   "ptn(17)/D=1F/L=32",
		msg:    ptn(17),
		ds:     0x1F,
		outLen: 32,
		want:   "9C 97 D0 36 A3 BA C8 19 DB 70 ED E0 CA 55 4E C6 E4 C2 A1 A4 FF BF D9 EC 26 9C A6 A1 11 16 12 33",
	},
	{
		name:   "ptn(289)/D=1F/L=32",
		msg:    ptn(289),
		ds:     0x1F,
		outLen: 32,
		want:   "96 C7 7C 27 9E 01 26 F7 FC 07 C9 B0 7F 5C DA E1 E0 BE 60 BD BE 10 62 00 40 E7 5D 72 23 A6 24 D2",
	},
	{
		name:   "ptn(4913)/D=1F/L=32",
		msg:    ptn(4913),
		ds:     0x1F,
		outLen: 32,
		want:   "D4 97 6E B5 6B CF 11 85 20 58 2B 70 9F 73 E1 D6 85 3E 00 1F DA F8 0E 1B 13 E0 D0 59 9D 5F B3 72",
	},
	{
		name:   "ptn(83521)/D=1F/L=32",
		msg:    ptn(83521),
		ds:     0x1F,
		outLen: 32,
		want:   "DA 67 C7 03 9E 98 BF 53 0C F7 A3 78 30 C6 66 4E 14 CB AB 7F 54 0F 58 40 3B 1B 82 95 13 18 EE 5C",
	},
	{
		name:   "ptn(1419857)/D=1F/L=32",
		msg:    ptn(1419857),
		ds:     0x1F,
		outLen: 32,
		want:   "B9 7A 90 6F BF 83 EF 7C 81 25 17 AB F3 B2 D0 AE A0 C4 F6 03 18 CE 11 CF 10 39 25 12 7F 59 EE CD",
	},
	// Skipping ptn(24137569) — too large for unit tests.
	{
		name:   "0xFF*3/D=01/L=32",
		msg:    []byte{0xFF, 0xFF, 0xFF},
		ds:     0x01,
		outLen: 32,
		want:   "BF 32 3F 94 04 94 E8 8E E1 C5 40 FE 66 0B E8 A0 C9 3F 43 D1 5E C0 06 99 84 62 FA 99 4E ED 5D AB",
	},
	{
		name:   "0xFF/D=06/L=32",
		msg:    []byte{0xFF},
		ds:     0x06,
		outLen: 32,
		want:   "8E C9 C6 64 65 ED 0D 4A 6C 35 D1 35 06 71 8D 68 7A 25 CB 05 C7 4C CA 1E 42 50 1A BD 83 87 4A 67",
	},
	{
		name:   "0xFF*3/D=07/L=32",
		msg:    []byte{0xFF, 0xFF, 0xFF},
		ds:     0x07,
		outLen: 32,
		want:   "B6 58 57 60 01 CA D9 B1 E5 F3 99 A9 F7 77 23 BB A0 54 58 04 2D 68 20 6F 72 52 68 2D BA 36 63 ED",
	},
	{
		name:   "0xFF*7/D=0B/L=32",
		msg:    []byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF},
		ds:     0x0B,
		outLen: 32,
		want:   "8D EE AA 1A EC 47 CC EE 56 9F 65 9C 21 DF A8 E1 12 DB 3C EE 37 B1 81 78 B2 AC D8 05 B7 99 CC 37",
	},
	{
		name:   "0xFF/D=30/L=32",
		msg:    []byte{0xFF},
		ds:     0x30,
		outLen: 32,
		want:   "55 31 22 E2 13 5E 36 3C 32 92 BE D2 C6 42 1F A2 32 BA B0 3D AA 07 C7 D6 63 66 03 28 65 06 32 5B",
	},
	{
		name:   "0xFF*3/D=7F/L=32",
		msg:    []byte{0xFF, 0xFF, 0xFF},
		ds:     0x7F,
		outLen: 32,
		want:   "16 27 4C C6 56 D4 4C EF D4 22 39 5D 0F 90 53 BD A6 D2 8E 12 2A BA 15 C7 65 E5 AD 0E 6E AF 26 F9",
	},
}

func TestSum(t *testing.T) {
	for _, tc := range testVectors {
		t.Run(tc.name, func(t *testing.T) {
			got := Sum(tc.msg, tc.ds, tc.outLen)
			want := hexDecode(tc.want)

			if tc.last32 {
				got = got[len(got)-32:]
			}

			if !bytes.Equal(got, want) {
				t.Errorf("got  %x\nwant %x", got, want)
			}
		})
	}
}

func TestHasher(t *testing.T) {
	for _, tc := range testVectors {
		t.Run(tc.name, func(t *testing.T) {
			h := New(tc.ds)
			_, _ = h.Write(tc.msg)
			got := make([]byte, tc.outLen)
			_, _ = h.Read(got)
			want := hexDecode(tc.want)

			if tc.last32 {
				got = got[len(got)-32:]
			}

			if !bytes.Equal(got, want) {
				t.Errorf("got  %x\nwant %x", got, want)
			}
		})
	}
}

func TestHasherIncremental(t *testing.T) {
	// Write in various chunk sizes and verify output matches Sum.
	for _, chunkSize := range []int{1, 7, 13, 64, 168, 169, 256} {
		msg := ptn(4913)
		h := New(0x1F)
		for i := 0; i < len(msg); i += chunkSize {
			end := min(i+chunkSize, len(msg))
			_, _ = h.Write(msg[i:end])
		}
		got := make([]byte, 32)
		_, _ = h.Read(got)
		want := Sum(msg, 0x1F, 32)
		if !bytes.Equal(got, want) {
			t.Errorf("chunkSize=%d: got %x, want %x", chunkSize, got, want)
		}
	}
}

func TestHasherIncrementalRead(t *testing.T) {
	// Read in various chunk sizes and verify output matches Sum.
	want := Sum(nil, 0x1F, 10032)

	for _, chunkSize := range []int{1, 7, 32, 168, 169, 500} {
		h := New(0x1F)
		var got []byte
		buf := make([]byte, chunkSize)
		for len(got) < 10032 {
			n := min(chunkSize, 10032-len(got))
			_, _ = h.Read(buf[:n])
			got = append(got, buf[:n]...)
		}
		if !bytes.Equal(got, want) {
			t.Errorf("chunkSize=%d: output mismatch", chunkSize)
		}
	}
}

func TestChain(t *testing.T) {
	msg := bytes.Repeat([]byte{0xDE, 0xCA, 0xFB, 0xAD}, 340)
	h1 := Sum(msg, 0x22, 16)
	h2 := Sum(msg, 0x23, 16)

	var h3, h4 [16]byte
	a := New(0x22)
	var b Hasher
	_, _ = a.Write(msg)
	Chain(&a, &b, 0x23)
	_, _ = a.Read(h3[:])
	_, _ = b.Read(h4[:])

	if got, want := h3[:], h1; !bytes.Equal(got, want) {
		t.Errorf("Chain(msg, 0x22) = %x, want = %x", got, want)
	}
	if got, want := h4[:], h2; !bytes.Equal(got, want) {
		t.Errorf("Chain(msg, 0x23) = %x, want = %x", got, want)
	}
}
