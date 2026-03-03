package keccak

type backend struct {
	name     string
	lanes    int
	permute1 func(*State1)
	permute2 func(*State2)
	permute4 func(*State4)
	permute8 func(*State8)
}

var selected = selectBackend() //nolint:gochecknoglobals

// AvailableLanes is the preferred lane width for this CPU/backend selection.
var AvailableLanes = selected.lanes //nolint:gochecknoglobals

func newGenericBackend() backend {
	return backend{
		name:     "generic",
		lanes:    1,
		permute1: permute12x1Generic,
		permute2: permute12x2Generic,
		permute4: permute12x4Generic,
		permute8: permute12x8Generic,
	}
}

func selectBackend() backend {
	if forcedBackend != "" {
		return backendByName(forcedBackend)
	}
	if b, ok := archBackend(); ok {
		return b
	}
	return newGenericBackend()
}

func backendByName(name string) backend {
	b := newGenericBackend()
	b.name = name

	switch name {
	case "amd64_avx512":
		b.lanes = 8
	case "amd64_avx2":
		b.lanes = 4
	case "amd64_sse2":
		b.lanes = 2
	case "arm64_sha3":
		b.lanes = 2
	case "generic":
		b.lanes = 1
	default:
		panic("keccak: unknown backend override")
	}

	return b
}

func backendName() string {
	return selected.name
}

func (s *State1) Permute12() { selected.permute1(s) }

func (s *State2) Permute12() { selected.permute2(s) }

func (s *State4) Permute12() { selected.permute4(s) }

func (s *State8) Permute12() { selected.permute8(s) }
