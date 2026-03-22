//go:build arm64 && !purego

package tw128

//go:noescape
func p1600(a *duplex)

func permute12x1Arch(d *duplex) bool {
	p1600(d)
	return true
}
