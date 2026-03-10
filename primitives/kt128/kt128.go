package kt128

import (
	"hash"

	"github.com/codahale/thyrse/internal/k12"
)

// kt128XOF wraps an internal KT128 to satisfy hash.XOF.
type kt128XOF struct {
	h      *k12.KT128
	custom []byte
}

// NewKT128 returns a new KT128 [hash.XOF] with empty customization.
func NewKT128() hash.XOF {
	return &kt128XOF{h: k12.New()}
}

// NewKT128Custom returns a new KT128 [hash.XOF] that finalizes with the given customization string.
func NewKT128Custom(s []byte) hash.XOF {
	return &kt128XOF{h: k12.New(), custom: s}
}

func (x *kt128XOF) Write(p []byte) (int, error) { return x.h.Write(p) }

func (x *kt128XOF) Read(p []byte) (int, error) {
	return x.h.ReadCustom(x.custom, p)
}

func (x *kt128XOF) Reset() { x.h.Reset() }

func (x *kt128XOF) BlockSize() int { return k12.BlockSize }
