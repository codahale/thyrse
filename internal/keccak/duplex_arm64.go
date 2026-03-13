//go:build arm64 && !purego

package keccak

//go:noescape
func p1600x2Lane(a *[lanes][2]uint64)

func padPermute2(a, b *State1, ds byte) {
	pos := a.pos
	var buf [lanes][2]uint64
	for i := range lanes {
		buf[i][0] = a.a[i]
		buf[i][1] = b.a[i]
	}
	xorByteInWord(&buf[pos>>3][0], pos, ds)
	xorByteInWord(&buf[pos>>3][1], pos, ds)
	endLane := (Rate - 1) >> 3
	xorByteInWord(&buf[endLane][0], Rate-1, 0x80)
	xorByteInWord(&buf[endLane][1], Rate-1, 0x80)
	p1600x2Lane(&buf)
	for i := range lanes {
		a.a[i] = buf[i][0]
		b.a[i] = buf[i][1]
	}
}
