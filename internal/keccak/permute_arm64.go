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

func permute12x1Arch(s *State1) bool {
	if !useArchPermute1 {
		return false
	}
	p1600(s)
	return true
}

func permute12x2Arch(s *State2) bool {
	if selectedP2 != permute2ARM64Lane {
		return false
	}
	p1600x2Lane(s)
	return true
}

func permute12x4Arch(s *State4) bool {
	if selectedP4 != permute4ARM64Lane {
		return false
	}
	p1600x4Lane(s)
	return true
}

func permute12x8Arch(s *State8) bool {
	if selectedP8 != permute8ARM64Lane {
		return false
	}
	p1600x8Lane(s)
	return true
}

func init() {
	if forcedBackend == "generic" {
		return
	}
	if !cpuid.CPU.Has(cpuid.SHA3) {
		return
	}
	useArchPermute1 = true
	selectedP2 = permute2ARM64Lane
	selectedP4 = permute4ARM64Lane
	selectedP8 = permute8ARM64Lane
}
