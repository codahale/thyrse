//go:build !arm64 || purego

package kt128

func padPermute2(a, b *sponge, ds byte) {
	a.padPermute(ds)
	b.padPermute(ds)
}
