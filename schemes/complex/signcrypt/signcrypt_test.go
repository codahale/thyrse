package signcrypt_test

import (
	"bytes"
	"crypto/mlkem"
	"errors"
	"slices"
	"testing"

	"filippo.io/mldsa"
	"github.com/codahale/thyrse"
	"github.com/codahale/thyrse/internal/testdata"
	"github.com/codahale/thyrse/schemes/complex/signcrypt"
)

func TestOpen(t *testing.T) {
	keys := setup(t)
	ciphertext := signcrypt.Seal("signcrypt", keys.sender, keys.receiver.EncapsulationKey(), []byte("this is a message"))

	t.Run("valid", func(t *testing.T) {
		plaintext, err := signcrypt.Open("signcrypt", keys.receiver, keys.sender.PublicKey(), ciphertext)
		if err != nil {
			t.Fatal(err)
		}

		if got, want := plaintext, []byte("this is a message"); !bytes.Equal(got, want) {
			t.Errorf("Open() = %x, want %x", got, want)
		}
	})

	t.Run("empty message", func(t *testing.T) {
		ciphertext := signcrypt.Seal("signcrypt", keys.sender, keys.receiver.EncapsulationKey(), nil)
		if got, want := len(ciphertext), signcrypt.Overhead; got != want {
			t.Fatalf("len(Seal(nil)) = %d, want %d", got, want)
		}

		plaintext, err := signcrypt.Open("signcrypt", keys.receiver, keys.sender.PublicKey(), ciphertext)
		if err != nil {
			t.Fatal(err)
		}
		if len(plaintext) != 0 {
			t.Errorf("Open() = %x, want empty plaintext", plaintext)
		}
	})

	tests := map[string]struct {
		domain     string
		receiver   *mlkem.DecapsulationKey768
		sender     *mldsa.PublicKey
		ciphertext []byte
	}{
		"wrong domain": {
			domain:     "other",
			receiver:   keys.receiver,
			sender:     keys.sender.PublicKey(),
			ciphertext: ciphertext,
		},
		"wrong receiver": {
			domain:     "signcrypt",
			receiver:   keys.otherReceiver,
			sender:     keys.sender.PublicKey(),
			ciphertext: ciphertext,
		},
		"wrong sender": {
			domain:     "signcrypt",
			receiver:   keys.receiver,
			sender:     keys.otherSender.PublicKey(),
			ciphertext: ciphertext,
		},
		"modified ML-KEM ciphertext": {
			domain:     "signcrypt",
			receiver:   keys.receiver,
			sender:     keys.sender.PublicKey(),
			ciphertext: modified(ciphertext, 0),
		},
		"modified message": {
			domain:     "signcrypt",
			receiver:   keys.receiver,
			sender:     keys.sender.PublicKey(),
			ciphertext: modified(ciphertext, mlkem.CiphertextSize768+1),
		},
		"modified signature": {
			domain:     "signcrypt",
			receiver:   keys.receiver,
			sender:     keys.sender.PublicKey(),
			ciphertext: modified(ciphertext, len(ciphertext)-1),
		},
		"truncated": {
			domain:     "signcrypt",
			receiver:   keys.receiver,
			sender:     keys.sender.PublicKey(),
			ciphertext: ciphertext[:signcrypt.Overhead-1],
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			plaintext, err := signcrypt.Open(test.domain, test.receiver, test.sender, test.ciphertext)
			if !errors.Is(err, thyrse.ErrInvalidCiphertext) {
				t.Errorf("Open() = (%x, %v), want ErrInvalidCiphertext", plaintext, err)
			}
		})
	}
}

func TestRejectsWrongMLDSAParameters(t *testing.T) {
	keys := setup(t)
	drbg := testdata.New("thyrse signcrypt wrong parameters")
	wrongSender, err := mldsa.NewPrivateKey(mldsa.MLDSA65(), drbg.Data(mldsa.PrivateKeySize))
	if err != nil {
		t.Fatal(err)
	}

	t.Run("Seal", func(t *testing.T) {
		defer func() {
			if recover() == nil {
				t.Fatal("Seal() did not panic")
			}
		}()
		signcrypt.Seal("signcrypt", wrongSender, keys.receiver.EncapsulationKey(), nil)
	})

	t.Run("Open", func(t *testing.T) {
		ciphertext := signcrypt.Seal("signcrypt", keys.sender, keys.receiver.EncapsulationKey(), nil)
		plaintext, err := signcrypt.Open("signcrypt", keys.receiver, wrongSender.PublicKey(), ciphertext)
		if !errors.Is(err, thyrse.ErrInvalidCiphertext) {
			t.Errorf("Open() = (%x, %v), want ErrInvalidCiphertext", plaintext, err)
		}
	})
}

func BenchmarkSeal(b *testing.B) {
	keys := setup(b)
	message := []byte("this is a message")
	b.ReportAllocs()
	for b.Loop() {
		signcrypt.Seal("signcrypt", keys.sender, keys.receiver.EncapsulationKey(), message)
	}
}

func BenchmarkOpen(b *testing.B) {
	keys := setup(b)
	ciphertext := signcrypt.Seal("signcrypt", keys.sender, keys.receiver.EncapsulationKey(), []byte("this is a message"))

	b.ReportAllocs()
	for b.Loop() {
		_, _ = signcrypt.Open("signcrypt", keys.receiver, keys.sender.PublicKey(), ciphertext)
	}
}

func FuzzOpen(f *testing.F) {
	drbg := testdata.New("thyrse signcrypt fuzz")
	for range 10 {
		f.Add(drbg.Data(256))
	}

	keys := setup(f)
	ciphertext := signcrypt.Seal("signcrypt", keys.sender, keys.receiver.EncapsulationKey(), []byte("this is a message"))
	f.Add(modified(ciphertext, 0))
	f.Add(modified(ciphertext, mlkem.CiphertextSize768+1))
	f.Add(modified(ciphertext, len(ciphertext)-1))

	f.Fuzz(func(t *testing.T, modifiedCiphertext []byte) {
		if bytes.Equal(ciphertext, modifiedCiphertext) {
			t.Skip()
		}

		plaintext, err := signcrypt.Open("signcrypt", keys.receiver, keys.sender.PublicKey(), modifiedCiphertext)
		if !errors.Is(err, thyrse.ErrInvalidCiphertext) {
			t.Errorf("Open(ciphertext=%x) = (plaintext=%x, err=%v), want ErrInvalidCiphertext", modifiedCiphertext, plaintext, err)
		}
	})
}

type testKeys struct {
	sender        *mldsa.PrivateKey
	receiver      *mlkem.DecapsulationKey768
	otherSender   *mldsa.PrivateKey
	otherReceiver *mlkem.DecapsulationKey768
}

func setup(t testing.TB) testKeys {
	t.Helper()
	drbg := testdata.New("thyrse signcrypt")

	newSender := func() *mldsa.PrivateKey {
		key, err := mldsa.NewPrivateKey(mldsa.MLDSA44(), drbg.Data(mldsa.PrivateKeySize))
		if err != nil {
			t.Fatal(err)
		}
		return key
	}
	newReceiver := func() *mlkem.DecapsulationKey768 {
		key, err := mlkem.NewDecapsulationKey768(drbg.Data(mlkem.SeedSize))
		if err != nil {
			t.Fatal(err)
		}
		return key
	}

	return testKeys{
		sender:        newSender(),
		receiver:      newReceiver(),
		otherSender:   newSender(),
		otherReceiver: newReceiver(),
	}
}

func modified(ciphertext []byte, offset int) []byte {
	modified := slices.Clone(ciphertext)
	modified[offset] ^= 1
	return modified
}
