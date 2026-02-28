package keccak //nolint:testpackage // testing internals

import (
	"bytes"
	"crypto/sha3"
	"encoding/hex"
	"testing"
)

func TestP1600(t *testing.T) {
	var state [200]byte
	P1600(&state)

	if got, want := hex.EncodeToString(state[:]), "1786a7b938545e8e1ed059f2506acdd9351fa952c6e7b887c5e0e4cd67e09310455ad9f290ab33b0451adda8722fa7e09c2f6714aa8037c51d075100f547dd3ecc8a170c311da3b3a0aa5792a586b5799bf9b1b33d7c4abc93678ae66340876866250e2e33036c5cda30f0b90212aa9c9f7acf2b789a3b5f2379ae61e0c136e5ec873cb718b6e96dc28a9170f1d1be2ab724edda53bdab6a5ae12e2c6a41c1bfaf5209b936e0cfc6d76070dc17365045e47a9fc2b21156627a64302cdb7136d41ca02c22760dfdcf"; got != want {
		t.Errorf("P1600(0*200) = %s, want = %s", got, want)
	}
}

func TestF1600Generic(t *testing.T) {
	t.Run("12 rounds", func(t *testing.T) {
		var state [200]byte
		f1600Generic(&state, 12)

		if got, want := hex.EncodeToString(state[:]), "1786a7b938545e8e1ed059f2506acdd9351fa952c6e7b887c5e0e4cd67e09310455ad9f290ab33b0451adda8722fa7e09c2f6714aa8037c51d075100f547dd3ecc8a170c311da3b3a0aa5792a586b5799bf9b1b33d7c4abc93678ae66340876866250e2e33036c5cda30f0b90212aa9c9f7acf2b789a3b5f2379ae61e0c136e5ec873cb718b6e96dc28a9170f1d1be2ab724edda53bdab6a5ae12e2c6a41c1bfaf5209b936e0cfc6d76070dc17365045e47a9fc2b21156627a64302cdb7136d41ca02c22760dfdcf"; got != want {
			t.Errorf("P1600(0*200) = %s, want = %s", got, want)
		}
	})

	t.Run("24 rounds", func(t *testing.T) {
		var state [200]byte
		f1600Generic(&state, 24)

		if got, want := hex.EncodeToString(state[:]), "e7dde140798f25f18a47c033f9ccd584eea95aa61e2698d54d49806f304715bd57d05362054e288bd46f8e7f2da497ffc44746a4a0e5fe90762e19d60cda5b8c9c05191bf7a630ad64fc8fd0b75a933035d617233fa95aeb0321710d26e6a6a95f55cfdb167ca58126c84703cd31b8439f56a5111a2ff20161aed9215a63e505f270c98cf2febe641166c47b95703661cb0ed04f555a7cb8c832cf1c8ae83e8c14263aae22790c94e409c5a224f94118c26504e72635f5163ba1307fe944f67549a2ec5c7bfff1ea"; got != want {
			t.Errorf("F1600(0*200) = %s, want = %s", got, want)
		}
	})
}

func TestP1600x2(t *testing.T) {
	// Two zero states should both match the known P1600 test vector.
	var state1, state2 [200]byte
	P1600x2(&state1, &state2)

	want := "1786a7b938545e8e1ed059f2506acdd9351fa952c6e7b887c5e0e4cd67e09310455ad9f290ab33b0451adda8722fa7e09c2f6714aa8037c51d075100f547dd3ecc8a170c311da3b3a0aa5792a586b5799bf9b1b33d7c4abc93678ae66340876866250e2e33036c5cda30f0b90212aa9c9f7acf2b789a3b5f2379ae61e0c136e5ec873cb718b6e96dc28a9170f1d1be2ab724edda53bdab6a5ae12e2c6a41c1bfaf5209b936e0cfc6d76070dc17365045e47a9fc2b21156627a64302cdb7136d41ca02c22760dfdcf"
	if got := hex.EncodeToString(state1[:]); got != want {
		t.Errorf("P1600x2 state1(0*200) = %s, want = %s", got, want)
	}
	if got := hex.EncodeToString(state2[:]); got != want {
		t.Errorf("P1600x2 state2(0*200) = %s, want = %s", got, want)
	}

	// Two different states should each match sequential P1600 results.
	drbg := sha3.NewSHAKE128()
	_, _ = drbg.Write([]byte("P1600x2-test"))

	var a, b, aRef, bRef [200]byte
	_, _ = drbg.Read(a[:])
	_, _ = drbg.Read(b[:])
	copy(aRef[:], a[:])
	copy(bRef[:], b[:])

	P1600x2(&a, &b)
	f1600Generic(&aRef, 12)
	f1600Generic(&bRef, 12)

	if !bytes.Equal(a[:], aRef[:]) {
		t.Errorf("P1600x2 state1 mismatch: got %x, want %x", a, aRef)
	}
	if !bytes.Equal(b[:], bRef[:]) {
		t.Errorf("P1600x2 state2 mismatch: got %x, want %x", b, bRef)
	}
}

func FuzzP1600(f *testing.F) {
	drbg := sha3.NewSHAKE128()
	_, _ = drbg.Write([]byte("Keccak-p[1600,12]"))
	for range 10 {
		var state [200]byte
		_, _ = drbg.Read(state[:])
		f.Add(state[:])
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) != 200 {
			t.Skip()
		}

		var state1, state2 [200]byte
		copy(state1[:], data)
		copy(state2[:], data)

		P1600(&state1)            // Should use ASM
		f1600Generic(&state2, 12) // Reference

		if !bytes.Equal(state1[:], state2[:]) {
			t.Errorf("Keccak-p[1600,12](%x) = %x, want = %x", data, state1, state2)
		}
	})
}

func TestP1600x4(t *testing.T) {
	// Four zero states should all match the known P1600 test vector.
	var state1, state2, state3, state4 [200]byte
	P1600x4(&state1, &state2, &state3, &state4)

	want := "1786a7b938545e8e1ed059f2506acdd9351fa952c6e7b887c5e0e4cd67e09310455ad9f290ab33b0451adda8722fa7e09c2f6714aa8037c51d075100f547dd3ecc8a170c311da3b3a0aa5792a586b5799bf9b1b33d7c4abc93678ae66340876866250e2e33036c5cda30f0b90212aa9c9f7acf2b789a3b5f2379ae61e0c136e5ec873cb718b6e96dc28a9170f1d1be2ab724edda53bdab6a5ae12e2c6a41c1bfaf5209b936e0cfc6d76070dc17365045e47a9fc2b21156627a64302cdb7136d41ca02c22760dfdcf"
	if got := hex.EncodeToString(state1[:]); got != want {
		t.Errorf("P1600x4 state1(0*200) = %s, want = %s", got, want)
	}
	if got := hex.EncodeToString(state2[:]); got != want {
		t.Errorf("P1600x4 state2(0*200) = %s, want = %s", got, want)
	}
	if got := hex.EncodeToString(state3[:]); got != want {
		t.Errorf("P1600x4 state3(0*200) = %s, want = %s", got, want)
	}
	if got := hex.EncodeToString(state4[:]); got != want {
		t.Errorf("P1600x4 state4(0*200) = %s, want = %s", got, want)
	}

	// Four different states should each match sequential P1600 results.
	drbg := sha3.NewSHAKE128()
	_, _ = drbg.Write([]byte("P1600x4-test"))

	var a, b, c, d, aRef, bRef, cRef, dRef [200]byte
	_, _ = drbg.Read(a[:])
	_, _ = drbg.Read(b[:])
	_, _ = drbg.Read(c[:])
	_, _ = drbg.Read(d[:])
	copy(aRef[:], a[:])
	copy(bRef[:], b[:])
	copy(cRef[:], c[:])
	copy(dRef[:], d[:])

	P1600x4(&a, &b, &c, &d)
	f1600Generic(&aRef, 12)
	f1600Generic(&bRef, 12)
	f1600Generic(&cRef, 12)
	f1600Generic(&dRef, 12)

	if !bytes.Equal(a[:], aRef[:]) {
		t.Errorf("P1600x4 state1 mismatch: got %x, want %x", a, aRef)
	}
	if !bytes.Equal(b[:], bRef[:]) {
		t.Errorf("P1600x4 state2 mismatch: got %x, want %x", b, bRef)
	}
	if !bytes.Equal(c[:], cRef[:]) {
		t.Errorf("P1600x4 state3 mismatch: got %x, want %x", c, cRef)
	}
	if !bytes.Equal(d[:], dRef[:]) {
		t.Errorf("P1600x4 state4 mismatch: got %x, want %x", d, dRef)
	}
}

func FuzzP1600x2(f *testing.F) {
	drbg := sha3.NewSHAKE128()
	_, _ = drbg.Write([]byte("Keccak-p[1600,12]x2"))
	for range 10 {
		var seed [400]byte
		_, _ = drbg.Read(seed[:])
		f.Add(seed[:])
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) != 400 {
			t.Skip()
		}

		var s1, s2, ref1, ref2 [200]byte
		copy(s1[:], data[:200])
		copy(s2[:], data[200:])
		copy(ref1[:], s1[:])
		copy(ref2[:], s2[:])

		P1600x2(&s1, &s2)
		f1600Generic(&ref1, 12)
		f1600Generic(&ref2, 12)

		if !bytes.Equal(s1[:], ref1[:]) {
			t.Errorf("P1600x2 state1(%x) = %x, want = %x", data[:200], s1, ref1)
		}
		if !bytes.Equal(s2[:], ref2[:]) {
			t.Errorf("P1600x2 state2(%x) = %x, want = %x", data[200:], s2, ref2)
		}
	})
}

func FuzzP1600x4(f *testing.F) {
	drbg := sha3.NewSHAKE128()
	_, _ = drbg.Write([]byte("Keccak-p[1600,12]x4"))
	for range 10 {
		var seed [800]byte
		_, _ = drbg.Read(seed[:])
		f.Add(seed[:])
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) != 800 {
			t.Skip()
		}

		var s1, s2, s3, s4, ref1, ref2, ref3, ref4 [200]byte
		copy(s1[:], data[:200])
		copy(s2[:], data[200:400])
		copy(s3[:], data[400:600])
		copy(s4[:], data[600:])
		copy(ref1[:], s1[:])
		copy(ref2[:], s2[:])
		copy(ref3[:], s3[:])
		copy(ref4[:], s4[:])

		P1600x4(&s1, &s2, &s3, &s4)
		f1600Generic(&ref1, 12)
		f1600Generic(&ref2, 12)
		f1600Generic(&ref3, 12)
		f1600Generic(&ref4, 12)

		if !bytes.Equal(s1[:], ref1[:]) {
			t.Errorf("P1600x4 state1(%x) = %x, want = %x", data[:200], s1, ref1)
		}
		if !bytes.Equal(s2[:], ref2[:]) {
			t.Errorf("P1600x4 state2(%x) = %x, want = %x", data[200:400], s2, ref2)
		}
		if !bytes.Equal(s3[:], ref3[:]) {
			t.Errorf("P1600x4 state3(%x) = %x, want = %x", data[400:600], s3, ref3)
		}
		if !bytes.Equal(s4[:], ref4[:]) {
			t.Errorf("P1600x4 state4(%x) = %x, want = %x", data[600:], s4, ref4)
		}
	})
}

func BenchmarkP1600(b *testing.B) {
	b.Logf("Lanes = %d", Lanes)

	b.Run("Generic", func(b *testing.B) {
		var s0 [200]byte
		b.ReportAllocs()
		b.SetBytes(int64(len(s0)))
		for b.Loop() {
			f1600Generic(&s0, 12)
		}
	})

	b.Run("P1600", func(b *testing.B) {
		var s0 [200]byte
		b.ReportAllocs()
		b.SetBytes(int64(len(s0)))
		for b.Loop() {
			P1600(&s0)
		}
	})

	b.Run("P1600x2", func(b *testing.B) {
		var s0, s1 [200]byte
		b.ReportAllocs()
		b.SetBytes(int64(len(s0) + len(s1)))
		for b.Loop() {
			P1600x2(&s0, &s1)
		}
	})

	b.Run("P1600x4", func(b *testing.B) {
		var s0, s1, s2, s3 [200]byte
		b.ReportAllocs()
		b.SetBytes(int64(len(s0) + len(s1) + len(s2) + len(s3)))
		for b.Loop() {
			P1600x4(&s0, &s1, &s2, &s3)
		}
	})
}
