//go:build !arm64 || purego

package keccak

func padPermute2(a, b *State1, ds byte) {
	a.padPermute(a.pos, ds)
	b.padPermute(b.pos, ds)
}
