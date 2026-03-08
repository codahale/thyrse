// Package enc implements encodings used by KangarooTwelve and NIST SP 800-185.
package enc

// LengthEncode encodes x as in KangarooTwelve (RFC 9861 Section 2.3.1):
// big-endian with no leading zeros, followed by a byte giving the length
// of the encoding.
func LengthEncode(x uint64) []byte {
	if x == 0 {
		return []byte{0x00}
	}

	n := 0
	for v := x; v > 0; v >>= 8 {
		n++
	}

	buf := make([]byte, n+1)
	for i := n - 1; i >= 0; i-- {
		buf[i] = byte(x)
		x >>= 8
	}
	buf[n] = byte(n)

	return buf
}

// LeftEncode encodes x as defined in NIST SP 800-185:
// byte count followed by big-endian value (at least one byte).
func LeftEncode(x uint64) []byte {
	if x == 0 {
		return []byte{1, 0}
	}
	n := 0
	for v := x; v > 0; v >>= 8 {
		n++
	}
	buf := make([]byte, n+1)
	buf[0] = byte(n)
	for i := n; i >= 1; i-- {
		buf[i] = byte(x)
		x >>= 8
	}
	return buf
}

// EncodeString encodes a byte string as defined in NIST SP 800-185:
// left_encode(len(x)*8) || x.
func EncodeString(x []byte) []byte {
	prefix := LeftEncode(uint64(len(x)) * 8)
	return append(prefix, x...)
}
