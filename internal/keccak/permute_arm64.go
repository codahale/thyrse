//go:build arm64 && !purego

package keccak

import "github.com/klauspost/cpuid/v2"

//go:noescape
func p1600(a *State1)

//go:noescape
func p1600x2Lane(a *State2)

//go:noescape
func p1600x4Lane(a *State4)

//go:noescape
func p1600x8Lane(a *State8)

func permute12x2ARM64(s *State2) {
	p1600x2Lane(s)
}

func permute12x4ARM64(s *State4) {
	p1600x4Lane(s)
}

func permute12x8ARM64(s *State8) {
	p1600x8Lane(s)
}

func init() {
	if forcedBackend == "generic" {
		return
	}
	if !cpuid.CPU.Has(cpuid.SHA3) {
		return
	}
	selected.permute1 = p1600
	selected.permute2 = permute12x2ARM64
	selected.permute4 = permute12x4ARM64
	selected.permute8 = permute12x8ARM64
}
