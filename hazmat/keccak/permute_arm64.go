//go:build arm64 && !purego

package keccak

import "github.com/klauspost/cpuid/v2"

//go:noescape
func p1600(a *State1)

//go:noescape
func p1600x2(a, b *State1)

//go:noescape
func p1600x2Lane(a *State2)

func permute12x2ARM64(s *State2) {
	p1600x2Lane(s)
}

func permute12x4ARM64(s *State4) {
	var t [4]State1
	for lane := range Lanes {
		t[0].a[lane] = s.a[lane][0]
		t[1].a[lane] = s.a[lane][1]
		t[2].a[lane] = s.a[lane][2]
		t[3].a[lane] = s.a[lane][3]
	}
	p1600x2(&t[0], &t[1])
	p1600x2(&t[2], &t[3])
	for lane := range Lanes {
		s.a[lane][0] = t[0].a[lane]
		s.a[lane][1] = t[1].a[lane]
		s.a[lane][2] = t[2].a[lane]
		s.a[lane][3] = t[3].a[lane]
	}
}

func permute12x8ARM64(s *State8) {
	var t [8]State1
	for lane := range Lanes {
		t[0].a[lane] = s.a[lane][0]
		t[1].a[lane] = s.a[lane][1]
		t[2].a[lane] = s.a[lane][2]
		t[3].a[lane] = s.a[lane][3]
		t[4].a[lane] = s.a[lane][4]
		t[5].a[lane] = s.a[lane][5]
		t[6].a[lane] = s.a[lane][6]
		t[7].a[lane] = s.a[lane][7]
	}
	p1600x2(&t[0], &t[1])
	p1600x2(&t[2], &t[3])
	p1600x2(&t[4], &t[5])
	p1600x2(&t[6], &t[7])
	for lane := range Lanes {
		s.a[lane][0] = t[0].a[lane]
		s.a[lane][1] = t[1].a[lane]
		s.a[lane][2] = t[2].a[lane]
		s.a[lane][3] = t[3].a[lane]
		s.a[lane][4] = t[4].a[lane]
		s.a[lane][5] = t[5].a[lane]
		s.a[lane][6] = t[6].a[lane]
		s.a[lane][7] = t[7].a[lane]
	}
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
