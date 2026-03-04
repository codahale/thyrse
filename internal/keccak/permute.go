package keccak

type backend uint8

const (
	backendGeneric backend = iota
	backendAMD64SSE2
	backendAMD64AVX2
	backendAMD64AVX512
	backendARM64SHA3
)

type permute2Impl uint8

const (
	permute2Generic permute2Impl = iota
	permute2AMD64Lane
	permute2AMD64AVX512
	permute2ARM64Lane
)

type permute4Impl uint8

const (
	permute4Generic permute4Impl = iota
	permute4AMD64Lane
	permute4AMD64AVX512
	permute4AMD64SSE2Fallback
	permute4ARM64Lane
)

type permute8Impl uint8

const (
	permute8Generic permute8Impl = iota
	permute8AMD64Lane
	permute8AMD64AVX512State
	permute8AMD64SSE2Fallback
	permute8ARM64Lane
)

var selectedBackend = selectBackend() //nolint:gochecknoglobals

// AvailableLanes is the preferred lane width for this CPU/backend selection.
var AvailableLanes = lanesForBackend(selectedBackend) //nolint:gochecknoglobals

var (
	useArchPermute1 = false           //nolint:gochecknoglobals
	selectedP2      = permute2Generic //nolint:gochecknoglobals
	selectedP4      = permute4Generic //nolint:gochecknoglobals
	selectedP8      = permute8Generic //nolint:gochecknoglobals
)

func lanesForBackend(b backend) int {
	switch b {
	case backendAMD64AVX512:
		return 8
	case backendAMD64AVX2:
		return 4
	case backendAMD64SSE2, backendARM64SHA3:
		return 2
	case backendGeneric:
		return 1
	default:
		panic("keccak: unknown backend")
	}
}

func selectBackend() backend {
	if forcedBackend != "" {
		return backendByName(forcedBackend)
	}
	if b, ok := archBackend(); ok {
		return b
	}
	return backendGeneric
}

func backendByName(name string) backend {
	switch name {
	case "amd64_avx512":
		return backendAMD64AVX512
	case "amd64_avx2":
		return backendAMD64AVX2
	case "amd64_sse2":
		return backendAMD64SSE2
	case "arm64_sha3":
		return backendARM64SHA3
	case "generic":
		return backendGeneric
	default:
		panic("keccak: unknown backend override")
	}
}

func backendName() string {
	switch selectedBackend {
	case backendAMD64AVX512:
		return "amd64_avx512"
	case backendAMD64AVX2:
		return "amd64_avx2"
	case backendAMD64SSE2:
		return "amd64_sse2"
	case backendARM64SHA3:
		return "arm64_sha3"
	case backendGeneric:
		return "generic"
	default:
		panic("keccak: unknown backend")
	}
}

func (s *State1) Permute12() {
	if permute12x1Arch(s) {
		return
	}
	permute12x1Generic(s)
}

func (s *State2) Permute12() {
	if permute12x2Arch(s) {
		return
	}
	permute12x2Generic(s)
}

func (s *State4) Permute12() {
	if permute12x4Arch(s) {
		return
	}
	permute12x4Generic(s)
}

func (s *State8) Permute12() {
	if permute12x8Arch(s) {
		return
	}
	permute12x8Generic(s)
}
