package oprf

import (
	"crypto/rand"

	"github.com/codahale/thyrse"
	"github.com/gtank/ristretto255"
)

func computeCompositesFast(domain string, k *ristretto255.Scalar, b *ristretto255.Element, cM, dM []*ristretto255.Element) (m, z *ristretto255.Element) {
	if len(cM) != len(dM) {
		panic("oprf: mismatched element slice lengths")
	}
	m = ristretto255.NewIdentityElement()
	p := thyrse.New(domain)
	p.Mix("b", b.Bytes())
	for i := range cM {
		p.Mix("c", cM[i].Bytes())
		p.Mix("d", dM[i].Bytes())
		dI, _ := ristretto255.NewScalar().SetUniformBytes(p.Derive("scalar", nil, 64))
		m.Add(m, ristretto255.NewIdentityElement().ScalarMult(dI, cM[i]))
	}
	z = ristretto255.NewIdentityElement().ScalarMult(k, m)
	return m, z
}

func generateProof(domain string, k *ristretto255.Scalar, a, b *ristretto255.Element, cM, dM []*ristretto255.Element) (c, s *ristretto255.Scalar) {
	m, z := computeCompositesFast(domain, k, b, cM, dM)

	var x [64]byte
	if _, err := rand.Read(x[:]); err != nil {
		panic(err)
	}
	r, _ := ristretto255.NewScalar().SetUniformBytes(x[:])
	t2 := ristretto255.NewIdentityElement().ScalarMult(r, a)
	t3 := ristretto255.NewIdentityElement().ScalarMult(r, m)

	p := thyrse.New(domain)
	p.Mix("b", b.Bytes())
	p.Mix("m", m.Bytes())
	p.Mix("z", z.Bytes())
	p.Mix("t2", t2.Bytes())
	p.Mix("t3", t3.Bytes())
	c, _ = ristretto255.NewScalar().SetUniformBytes(p.Derive("challenge", nil, 64))
	s = ristretto255.NewScalar().Subtract(r, ristretto255.NewScalar().Multiply(c, k))
	return c, s
}

func computeComposites(domain string, b *ristretto255.Element, cM, dM []*ristretto255.Element) (m, z *ristretto255.Element) {
	if len(cM) != len(dM) {
		panic("oprf: mismatched element slice lengths")
	}
	m = ristretto255.NewIdentityElement()
	z = ristretto255.NewIdentityElement()
	p := thyrse.New(domain)
	p.Mix("b", b.Bytes())
	for i := range cM {
		p.Mix("c", cM[i].Bytes())
		p.Mix("d", dM[i].Bytes())
		dI, _ := ristretto255.NewScalar().SetUniformBytes(p.Derive("scalar", nil, 64))
		m.Add(m, ristretto255.NewIdentityElement().ScalarMult(dI, cM[i]))
		z.Add(z, ristretto255.NewIdentityElement().ScalarMult(dI, dM[i]))
	}
	return m, z
}

func verifyProof(domain string, a, b *ristretto255.Element, cM, dM []*ristretto255.Element, c, s *ristretto255.Scalar) bool {
	m, z := computeComposites(domain, b, cM, dM)
	t2 := ristretto255.NewIdentityElement().VarTimeMultiScalarMult([]*ristretto255.Scalar{s, c}, []*ristretto255.Element{a, b})
	t3 := ristretto255.NewIdentityElement().VarTimeMultiScalarMult([]*ristretto255.Scalar{s, c}, []*ristretto255.Element{m, z})
	p := thyrse.New(domain)
	p.Mix("b", b.Bytes())
	p.Mix("m", m.Bytes())
	p.Mix("z", z.Bytes())
	p.Mix("t2", t2.Bytes())
	p.Mix("t3", t3.Bytes())
	expectedC, _ := ristretto255.NewScalar().SetUniformBytes(p.Derive("challenge", nil, 64))
	return c.Equal(expectedC) == 1
}
