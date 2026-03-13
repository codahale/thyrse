//go:build !arm64 || purego

package keccak

func padPermute2(a, b *State1, pos int, ds byte) {
	a.padPermute(pos, ds)
	b.padPermute(pos, ds)
}
