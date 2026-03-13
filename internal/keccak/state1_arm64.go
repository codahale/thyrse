//go:build arm64 && !purego

package keccak

import "unsafe"

//go:noescape
func p1600(a *State1)

func permute12x1Arch(s *State1) bool {
	p1600(s)
	return true
}

//go:noescape
func fastLoopAbsorb168x1(s *State1, in *byte, n int)

func fastLoopAbsorb168x1Arch(s *State1, in []byte) bool {
	fastLoopAbsorb168x1(s, unsafe.SliceData(in), len(in))
	return true
}

//go:noescape
func fastLoopEncrypt168x1(s *State1, src, dst *byte, n int)

//go:noescape
func fastLoopDecrypt168x1(s *State1, src, dst *byte, n int)

func fastLoopEncrypt168x1Arch(s *State1, src, dst []byte) bool {
	fastLoopEncrypt168x1(s, unsafe.SliceData(src), unsafe.SliceData(dst), len(src))
	return true
}

func fastLoopDecrypt168x1Arch(s *State1, src, dst []byte) bool {
	fastLoopDecrypt168x1(s, unsafe.SliceData(src), unsafe.SliceData(dst), len(src))
	return true
}

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
