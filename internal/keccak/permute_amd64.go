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

func permute2ImplAMD64() func(*State2) {
	switch forcedBackend {
	case "amd64_avx512":
		return p1600x2LaneAVX512
	case "amd64_avx2", "amd64_sse2":
		return p1600x2Lane
	default:
		if cpuid.CPU.Has(cpuid.AVX512F) && cpuid.CPU.Has(cpuid.AVX512VL) {
			return p1600x2LaneAVX512
		}
		return p1600x2Lane
	}
}

func permute4ImplAMD64() func(*State4) {
	switch forcedBackend {
	case "amd64_avx512":
		return p1600x4LaneAVX512
	case "amd64_avx2", "amd64_sse2":
		return p1600x4Lane
	default:
		switch {
		case cpuid.CPU.Has(cpuid.AVX512F) && cpuid.CPU.Has(cpuid.AVX512VL):
			return p1600x4LaneAVX512
		case cpuid.CPU.Has(cpuid.AVX2):
			return p1600x4Lane
		default:
			return permute12x4SSE2FallbackAMD64
		}
	}
}

func permute8ImplAMD64() func(*State8) {
	switch forcedBackend {
	case "amd64_avx512":
		return p1600x8AVX512State
	case "amd64_avx2", "amd64_sse2":
		return p1600x8Lane
	default:
		switch {
		case cpuid.CPU.Has(cpuid.AVX512F) && cpuid.CPU.Has(cpuid.AVX512VL):
			return p1600x8AVX512State
		case cpuid.CPU.Has(cpuid.AVX2):
			return p1600x8Lane
		default:
			return permute12x8SSE2FallbackAMD64
		}
	}
}

func permute12x2AMD64(s *State2) {
	permute2ImplAMD64()(s)
}

func permute12x4AMD64(s *State4) {
	permute4ImplAMD64()(s)
}

func permute12x8AMD64(s *State8) {
	permute8ImplAMD64()(s)
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
	selected.permute2 = permute2ImplAMD64()
	selected.permute4 = permute4ImplAMD64()
	selected.permute8 = permute8ImplAMD64()
}
