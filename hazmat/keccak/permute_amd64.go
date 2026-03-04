//go:build amd64 && !purego

package keccak

import "github.com/klauspost/cpuid/v2"

//go:noescape
func p1600(a *State1)

//go:noescape
func p1600x2SSE2(a, b *State1)

//go:noescape
func p1600x2Lane(a *State2)

//go:noescape
func p1600x2AVX512(a, b *State1)

//go:noescape
func p1600x4AVX2(a, b, c, d *State1)

//go:noescape
func p1600x4Lane(a *State4)

//go:noescape
func p1600x8Lane(a *State8)

//go:noescape
func p1600x4AVX512(a, b, c, d *State1)

func permute12x2AMD64(s *State2) {
	switch forcedBackend {
	case "amd64_avx512":
		var a, b State1
		for lane := range Lanes {
			a.a[lane] = s.a[lane][0]
			b.a[lane] = s.a[lane][1]
		}
		p1600x2AVX512(&a, &b)
		for lane := range Lanes {
			s.a[lane][0] = a.a[lane]
			s.a[lane][1] = b.a[lane]
		}
		return
	case "amd64_avx2", "amd64_sse2":
		p1600x2Lane(s)
		return
	}

	if cpuid.CPU.Has(cpuid.AVX512F) && cpuid.CPU.Has(cpuid.AVX512VL) {
		var a, b State1
		for lane := range Lanes {
			a.a[lane] = s.a[lane][0]
			b.a[lane] = s.a[lane][1]
		}
		p1600x2AVX512(&a, &b)
		for lane := range Lanes {
			s.a[lane][0] = a.a[lane]
			s.a[lane][1] = b.a[lane]
		}
		return
	}
	p1600x2Lane(s)
}

func permute12x4AMD64(s *State4) {
	switch forcedBackend {
	case "amd64_avx512":
		var t [4]State1
		for lane := range Lanes {
			t[0].a[lane] = s.a[lane][0]
			t[1].a[lane] = s.a[lane][1]
			t[2].a[lane] = s.a[lane][2]
			t[3].a[lane] = s.a[lane][3]
		}
		p1600x4AVX512(&t[0], &t[1], &t[2], &t[3])
		for lane := range Lanes {
			s.a[lane][0] = t[0].a[lane]
			s.a[lane][1] = t[1].a[lane]
			s.a[lane][2] = t[2].a[lane]
			s.a[lane][3] = t[3].a[lane]
		}
		return
	case "amd64_avx2", "amd64_sse2":
		p1600x4Lane(s)
		return
	}

	var t [4]State1
	for lane := range Lanes {
		t[0].a[lane] = s.a[lane][0]
		t[1].a[lane] = s.a[lane][1]
		t[2].a[lane] = s.a[lane][2]
		t[3].a[lane] = s.a[lane][3]
	}
	switch {
	case cpuid.CPU.Has(cpuid.AVX512F) && cpuid.CPU.Has(cpuid.AVX512VL):
		p1600x4AVX512(&t[0], &t[1], &t[2], &t[3])
	case cpuid.CPU.Has(cpuid.AVX2):
		p1600x4Lane(s)
		return
	default:
		p1600x2SSE2(&t[0], &t[1])
		p1600x2SSE2(&t[2], &t[3])
	}
	for lane := range Lanes {
		s.a[lane][0] = t[0].a[lane]
		s.a[lane][1] = t[1].a[lane]
		s.a[lane][2] = t[2].a[lane]
		s.a[lane][3] = t[3].a[lane]
	}
}

func permute12x8AMD64(s *State8) {
	if forcedBackend == "amd64_avx512" {
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
		p1600x4AVX512(&t[0], &t[1], &t[2], &t[3])
		p1600x4AVX512(&t[4], &t[5], &t[6], &t[7])
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
		return
	}
	if forcedBackend == "amd64_avx2" || forcedBackend == "amd64_sse2" {
		p1600x8Lane(s)
		return
	}

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
	switch {
	case cpuid.CPU.Has(cpuid.AVX512F) && cpuid.CPU.Has(cpuid.AVX512VL):
		p1600x4AVX512(&t[0], &t[1], &t[2], &t[3])
		p1600x4AVX512(&t[4], &t[5], &t[6], &t[7])
	case cpuid.CPU.Has(cpuid.AVX2):
		p1600x8Lane(s)
		return
	default:
		p1600x2SSE2(&t[0], &t[1])
		p1600x2SSE2(&t[2], &t[3])
		p1600x2SSE2(&t[4], &t[5])
		p1600x2SSE2(&t[6], &t[7])
	}
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
	if !cpuid.CPU.Has(cpuid.BMI1) || !cpuid.CPU.Has(cpuid.BMI2) {
		// Keep scalar fallback for x1 on older CPUs.
	} else {
		selected.permute1 = p1600
	}
	selected.permute2 = permute12x2AMD64
	selected.permute4 = permute12x4AMD64
	selected.permute8 = permute12x8AMD64
}
