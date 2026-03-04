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
func p1600x2LaneAVX512(a *State2)

//go:noescape
func p1600x4Lane(a *State4)

//go:noescape
func p1600x4LaneAVX512(a *State4)

//go:noescape
func p1600x8Lane(a *State8)

//go:noescape
func p1600x8AVX512State(a *State8)

func permute12x4SSE2FallbackAMD64(s *State4) {
	var t [4]State1
	for lane := range Lanes {
		t[0].a[lane] = s.a[lane][0]
		t[1].a[lane] = s.a[lane][1]
		t[2].a[lane] = s.a[lane][2]
		t[3].a[lane] = s.a[lane][3]
	}
	p1600x2SSE2(&t[0], &t[1])
	p1600x2SSE2(&t[2], &t[3])
	for lane := range Lanes {
		s.a[lane][0] = t[0].a[lane]
		s.a[lane][1] = t[1].a[lane]
		s.a[lane][2] = t[2].a[lane]
		s.a[lane][3] = t[3].a[lane]
	}
}

func permute12x8SSE2FallbackAMD64(s *State8) {
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
	p1600x2SSE2(&t[0], &t[1])
	p1600x2SSE2(&t[2], &t[3])
	p1600x2SSE2(&t[4], &t[5])
	p1600x2SSE2(&t[6], &t[7])
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

func choosePermute2ImplAMD64() permute2Impl {
	switch forcedBackend {
	case "amd64_avx512":
		return permute2AMD64AVX512
	case "amd64_avx2", "amd64_sse2":
		return permute2AMD64Lane
	default:
		if cpuid.CPU.Has(cpuid.AVX512F) && cpuid.CPU.Has(cpuid.AVX512VL) {
			return permute2AMD64AVX512
		}
		return permute2AMD64Lane
	}
}

func choosePermute4ImplAMD64() permute4Impl {
	switch forcedBackend {
	case "amd64_avx512":
		return permute4AMD64AVX512
	case "amd64_avx2", "amd64_sse2":
		return permute4AMD64Lane
	default:
		switch {
		case cpuid.CPU.Has(cpuid.AVX512F) && cpuid.CPU.Has(cpuid.AVX512VL):
			return permute4AMD64AVX512
		case cpuid.CPU.Has(cpuid.AVX2):
			return permute4AMD64Lane
		default:
			return permute4AMD64SSE2Fallback
		}
	}
}

func choosePermute8ImplAMD64() permute8Impl {
	switch forcedBackend {
	case "amd64_avx512":
		return permute8AMD64AVX512State
	case "amd64_avx2", "amd64_sse2":
		return permute8AMD64Lane
	default:
		switch {
		case cpuid.CPU.Has(cpuid.AVX512F) && cpuid.CPU.Has(cpuid.AVX512VL):
			return permute8AMD64AVX512State
		case cpuid.CPU.Has(cpuid.AVX2):
			return permute8AMD64Lane
		default:
			return permute8AMD64SSE2Fallback
		}
	}
}

func permute12x1Arch(s *State1) bool {
	if !useArchPermute1 {
		return false
	}
	p1600(s)
	return true
}

func permute12x2Arch(s *State2) bool {
	switch selectedP2 {
	case permute2AMD64Lane:
		p1600x2Lane(s)
		return true
	case permute2AMD64AVX512:
		p1600x2LaneAVX512(s)
		return true
	default:
		return false
	}
}

func permute12x4Arch(s *State4) bool {
	switch selectedP4 {
	case permute4AMD64Lane:
		p1600x4Lane(s)
		return true
	case permute4AMD64AVX512:
		p1600x4LaneAVX512(s)
		return true
	case permute4AMD64SSE2Fallback:
		permute12x4SSE2FallbackAMD64(s)
		return true
	default:
		return false
	}
}

func permute12x8Arch(s *State8) bool {
	switch selectedP8 {
	case permute8AMD64Lane:
		p1600x8Lane(s)
		return true
	case permute8AMD64AVX512State:
		p1600x8AVX512State(s)
		return true
	case permute8AMD64SSE2Fallback:
		permute12x8SSE2FallbackAMD64(s)
		return true
	default:
		return false
	}
}

func init() {
	if forcedBackend == "generic" {
		return
	}
	if cpuid.CPU.Has(cpuid.BMI1) && cpuid.CPU.Has(cpuid.BMI2) {
		useArchPermute1 = true
	}
	selectedP2 = choosePermute2ImplAMD64()
	selectedP4 = choosePermute4ImplAMD64()
	selectedP8 = choosePermute8ImplAMD64()
}
