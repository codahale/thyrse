// Package enc implements encodings used by KangarooTwelve.
package enc

import "math/bits"

// LeftEncode encodes value as left_encode(value) per NIST SP 800-185:
// a byte giving the length of the encoding, followed by the big-endian
// encoding with no leading zeros. The result is appended to b.
func LeftEncode(b []byte, value uint64) []byte {
	if value == 0 {
		return append(b, 1, 0)
	}

	n := 8 - bits.LeadingZeros64(value)/8
	b = append(b, byte(n))
	value <<= (8 - n) * 8
	for range n {
		b = append(b, byte(value>>56))
		value <<= 8
	}
	return b
}

// EncodeString encodes data as encode_string(data) per NIST SP 800-185:
// left_encode(len(data)*8) || data. The result is appended to b.
func EncodeString(b []byte, data []byte) []byte {
	b = LeftEncode(b, uint64(len(data))*8)
	return append(b, data...)
}

// LengthEncode encodes x as in KangarooTwelve (RFC 9861 Section 2.3.1):
// big-endian with no leading zeros, followed by a byte giving the length
// of the encoding. The result is appended to buf and returned as a slice.
func LengthEncode(b []byte, value uint64) []byte {
	if value == 0 {
		return append(b, 0x00)
	}

	n := 8 - (bits.LeadingZeros64(value|1) / 8)
	value <<= (8 - n) * 8
	for range n {
		b = append(b, byte(value>>56))
		value <<= 8
	}
	b = append(b, byte(n))
	return b
}
