// Package enc implements encodings used by KangarooTwelve.
package enc

import "math/bits"

// MaxIntSize is the maximum number of bytes a 64-bit integer can be encoded to with either left_encode or right_encode.
const MaxIntSize = 9

// LeftEncode encodes value as left_encode(value) per NIST SP 800-185: a byte giving the length of the encoding,
// followed by the big-endian encoding with no leading zeros. The result is appended to b.
func LeftEncode(b []byte, value uint64) []byte {
	n := 8 - (bits.LeadingZeros64(value|1) / 8)
	value <<= (8 - n) * 8
	b = append(b, byte(n))
	for range n {
		b = append(b, byte(value>>56))
		value <<= 8
	}
	return b
}

// RightEncode encodes value as right_encode(value) per NIST SP 800-185: the big-endian encoding with no leading zeros,
// followed by a byte giving the length of the encoding. The result is appended to b.
func RightEncode(b []byte, value uint64) []byte {
	n := 8 - (bits.LeadingZeros64(value|1) / 8)
	value <<= (8 - n) * 8
	for range n {
		b = append(b, byte(value>>56))
		value <<= 8
	}
	b = append(b, byte(n))
	return b
}

// EncodeString encodes data as encode_string(data) per NIST SP 800-185: left_encode(len(data)*8) || data. The result is
// appended to b.
func EncodeString(b []byte, data []byte) []byte {
	b = LeftEncode(b, uint64(len(data))*8)
	return append(b, data...)
}
