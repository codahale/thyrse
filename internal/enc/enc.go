// Package enc implements the right_encode integer encoding from NIST SP 800-185.
package enc

import "math/bits"

// MaxIntSize is the maximum number of bytes a 64-bit integer can be encoded to with right_encode.
const MaxIntSize = 9

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
