package frost_test

import (
	"bytes"
	"slices"
	"strings"
	"testing"

	"github.com/codahale/thyrse/internal/testdata"
	"github.com/codahale/thyrse/schemes/complex/frost"
	"github.com/codahale/thyrse/schemes/complex/sig"
	"github.com/gtank/ristretto255"
)

const (
	signDomain = "frost-test"
	kgDomain   = "frost-keygen"
)

func TestKeyGen(t *testing.T) {
	drbg := testdata.New("frost keygen")

	t.Run("valid 3-of-5", func(t *testing.T) {
		groupKey, signers, verifyingShares, err := frost.KeyGen(kgDomain, 5, 3, drbg.Data(64))
		if err != nil {
			t.Fatal(err)
		}

		if groupKey.Equal(ristretto255.NewIdentityElement()) == 1 {
			t.Error("group key is identity")
		}

		if got := len(signers); got != 5 {
			t.Errorf("got %d signers, want 5", got)
		}

		if got := len(verifyingShares); got != 5 {
			t.Errorf("got %d verifying shares, want 5", got)
		}

		for i, s := range signers {
			if got, want := s.Identifier(), uint16(i+1); got != want {
				t.Errorf("signer[%d].Identifier() = %d, want %d", i, got, want)
			}

			if s.GroupKey().Equal(groupKey) != 1 {
				t.Errorf("signer[%d].GroupKey() does not match group key", i)
			}

			if s.VerifyingShare().Equal(verifyingShares[i]) != 1 {
				t.Errorf("signer[%d].VerifyingShare() does not match verifying share", i)
			}
		}
	})

	t.Run("threshold too low", func(t *testing.T) {
		_, _, _, err := frost.KeyGen(kgDomain, 5, 1, drbg.Data(64))
		if err == nil {
			t.Error("expected error for threshold < 2")
		}
	})

	t.Run("threshold exceeds max signers", func(t *testing.T) {
		_, _, _, err := frost.KeyGen(kgDomain, 2, 3, drbg.Data(64))
		if err == nil {
			t.Error("expected error for threshold > maxSigners")
		}
	})

	t.Run("insufficient randomness", func(t *testing.T) {
		_, _, _, err := frost.KeyGen(kgDomain, 5, 3, drbg.Data(32))
		if err == nil {
			t.Error("expected error for insufficient randomness")
		}
	})
}

func TestSignAndVerify(t *testing.T) {
	drbg := testdata.New("frost sign")
	message := []byte("this is a test message")

	t.Run("3-of-5 threshold", func(t *testing.T) {
		groupKey, signers, _, err := frost.KeyGen(kgDomain, 5, 3, drbg.Data(64))
		if err != nil {
			t.Fatal(err)
		}

		// Select a threshold subset (signers 0, 2, 4 i.e. identifiers 1, 3, 5).
		subset := []int{0, 2, 4}

		// Round 1: Generate commitments.
		nonces := make([]frost.Nonce, len(subset))
		commitments := make([]frost.Commitment, len(subset))
		for i, idx := range subset {
			nonces[i], commitments[i] = signers[idx].Commit(drbg.Data(64))
		}

		// Round 2: Produce signature shares.
		shares := make([][]byte, len(subset))
		for i, idx := range subset {
			shares[i], err = signers[idx].Sign(signDomain, nonces[i], message, commitments)
			if err != nil {
				t.Fatalf("signer %d failed: %v", signers[idx].Identifier(), err)
			}

			if got := len(shares[i]); got != frost.ShareSize {
				t.Errorf("share size = %d, want %d", got, frost.ShareSize)
			}
		}

		// Aggregate.
		signature, err := frost.Aggregate(signDomain, groupKey, message, commitments, shares)
		if err != nil {
			t.Fatal(err)
		}

		if got := len(signature); got != frost.SignatureSize {
			t.Errorf("signature size = %d, want %d", got, frost.SignatureSize)
		}

		// Verify with frost.Verify.
		if !frost.Verify(signDomain, groupKey, message, signature) {
			t.Error("frost.Verify failed for valid signature")
		}
	})

	t.Run("2-of-3 threshold", func(t *testing.T) {
		groupKey, signers, _, err := frost.KeyGen(kgDomain, 3, 2, drbg.Data(64))
		if err != nil {
			t.Fatal(err)
		}

		subset := []int{0, 1}

		nonces := make([]frost.Nonce, len(subset))
		commitments := make([]frost.Commitment, len(subset))
		for i, idx := range subset {
			nonces[i], commitments[i] = signers[idx].Commit(drbg.Data(64))
		}

		shares := make([][]byte, len(subset))
		for i, idx := range subset {
			shares[i], err = signers[idx].Sign(signDomain, nonces[i], message, commitments)
			if err != nil {
				t.Fatal(err)
			}
		}

		signature, err := frost.Aggregate(signDomain, groupKey, message, commitments, shares)
		if err != nil {
			t.Fatal(err)
		}

		if !frost.Verify(signDomain, groupKey, message, signature) {
			t.Error("frost.Verify failed for valid 2-of-3 signature")
		}
	})

	t.Run("different subsets produce compatible signatures", func(t *testing.T) {
		groupKey, signers, _, err := frost.KeyGen(kgDomain, 5, 3, drbg.Data(64))
		if err != nil {
			t.Fatal(err)
		}

		// Sign with two different subsets to verify both produce valid signatures.
		for _, subset := range [][]int{{0, 1, 2}, {2, 3, 4}} {
			nonces := make([]frost.Nonce, len(subset))
			commitments := make([]frost.Commitment, len(subset))
			for i, idx := range subset {
				nonces[i], commitments[i] = signers[idx].Commit(drbg.Data(64))
			}

			shares := make([][]byte, len(subset))
			for i, idx := range subset {
				shares[i], err = signers[idx].Sign(signDomain, nonces[i], message, commitments)
				if err != nil {
					t.Fatal(err)
				}
			}

			signature, err := frost.Aggregate(signDomain, groupKey, message, commitments, shares)
			if err != nil {
				t.Fatal(err)
			}

			if !frost.Verify(signDomain, groupKey, message, signature) {
				t.Errorf("verification failed for subset %v", subset)
			}
		}
	})
}

func TestSigVerifyCompatibility(t *testing.T) {
	drbg := testdata.New("frost sig compat")
	message := []byte("cross-verify message")

	groupKey, signers, _, err := frost.KeyGen(kgDomain, 5, 3, drbg.Data(64))
	if err != nil {
		t.Fatal(err)
	}

	// Generate a FROST signature.
	nonces := make([]frost.Nonce, 3)
	commitments := make([]frost.Commitment, 3)
	for i := range 3 {
		nonces[i], commitments[i] = signers[i].Commit(drbg.Data(64))
	}

	shares := make([][]byte, 3)
	for i := range 3 {
		shares[i], err = signers[i].Sign(signDomain, nonces[i], message, commitments)
		if err != nil {
			t.Fatal(err)
		}
	}

	signature, err := frost.Aggregate(signDomain, groupKey, message, commitments, shares)
	if err != nil {
		t.Fatal(err)
	}

	// Verify with sig.Verify — FROST signatures should be compatible Schnorr signatures.
	valid, err := sig.Verify(signDomain, groupKey, signature, strings.NewReader(string(message)))
	if err != nil {
		t.Fatal(err)
	}
	if !valid {
		t.Error("sig.Verify failed for FROST signature — challenge derivation mismatch")
	}
}

func TestVerifyShare(t *testing.T) {
	drbg := testdata.New("frost verify share")
	message := []byte("share verification message")

	groupKey, signers, verifyingShares, err := frost.KeyGen(kgDomain, 5, 3, drbg.Data(64))
	if err != nil {
		t.Fatal(err)
	}

	subset := []int{0, 2, 4}

	nonces := make([]frost.Nonce, len(subset))
	commitments := make([]frost.Commitment, len(subset))
	for i, idx := range subset {
		nonces[i], commitments[i] = signers[idx].Commit(drbg.Data(64))
	}

	shares := make([][]byte, len(subset))
	for i, idx := range subset {
		shares[i], err = signers[idx].Sign(signDomain, nonces[i], message, commitments)
		if err != nil {
			t.Fatal(err)
		}
	}

	t.Run("valid shares", func(t *testing.T) {
		for i, idx := range subset {
			id := signers[idx].Identifier()
			valid := frost.VerifyShare(signDomain, verifyingShares[idx], groupKey, id, message, commitments, shares[i])
			if !valid {
				t.Errorf("share from signer %d should be valid", id)
			}
		}
	})

	t.Run("corrupted share", func(t *testing.T) {
		bad := slices.Clone(shares[0])
		bad[0] ^= 0xff
		id := signers[subset[0]].Identifier()
		valid := frost.VerifyShare(signDomain, verifyingShares[subset[0]], groupKey, id, message, commitments, bad)
		if valid {
			t.Error("corrupted share should not verify")
		}
	})

	t.Run("wrong verifying share", func(t *testing.T) {
		id := signers[subset[0]].Identifier()
		// Use signer 1's verifying share for signer 0's share.
		valid := frost.VerifyShare(signDomain, verifyingShares[subset[1]], groupKey, id, message, commitments, shares[0])
		if valid {
			t.Error("share with wrong verifying share should not verify")
		}
	})
}

func TestVerifyInvalid(t *testing.T) {
	drbg := testdata.New("frost verify invalid")
	message := []byte("verification test message")

	groupKey, signers, _, err := frost.KeyGen(kgDomain, 5, 3, drbg.Data(64))
	if err != nil {
		t.Fatal(err)
	}

	nonces := make([]frost.Nonce, 3)
	commitments := make([]frost.Commitment, 3)
	for i := range 3 {
		nonces[i], commitments[i] = signers[i].Commit(drbg.Data(64))
	}

	shares := make([][]byte, 3)
	for i := range 3 {
		shares[i], err = signers[i].Sign(signDomain, nonces[i], message, commitments)
		if err != nil {
			t.Fatal(err)
		}
	}

	signature, err := frost.Aggregate(signDomain, groupKey, message, commitments, shares)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("wrong message", func(t *testing.T) {
		if frost.Verify(signDomain, groupKey, []byte("wrong message"), signature) {
			t.Error("should not verify with wrong message")
		}
	})

	t.Run("wrong domain", func(t *testing.T) {
		if frost.Verify("wrong-domain", groupKey, message, signature) {
			t.Error("should not verify with wrong domain")
		}
	})

	t.Run("wrong group key", func(t *testing.T) {
		otherGroupKey, _, _, _ := frost.KeyGen(kgDomain, 3, 2, drbg.Data(64))
		if frost.Verify(signDomain, otherGroupKey, message, signature) {
			t.Error("should not verify with wrong group key")
		}
	})

	t.Run("corrupted R", func(t *testing.T) {
		bad := slices.Clone(signature)
		bad[0] ^= 0xff
		if frost.Verify(signDomain, groupKey, message, bad) {
			t.Error("should not verify with corrupted R")
		}
	})

	t.Run("corrupted s", func(t *testing.T) {
		bad := slices.Clone(signature)
		bad[34] ^= 0xff
		if frost.Verify(signDomain, groupKey, message, bad) {
			t.Error("should not verify with corrupted s")
		}
	})

	t.Run("short signature", func(t *testing.T) {
		if frost.Verify(signDomain, groupKey, message, signature[:frost.SignatureSize-1]) {
			t.Error("should not verify short signature")
		}
	})

	t.Run("long signature", func(t *testing.T) {
		if frost.Verify(signDomain, groupKey, message, append(signature, 0)) {
			t.Error("should not verify long signature")
		}
	})

	t.Run("non-canonical s", func(t *testing.T) {
		bad := slices.Clone(signature)
		for i := 32; i < 64; i++ {
			bad[i] = 0xff
		}
		if frost.Verify(signDomain, groupKey, message, bad) {
			t.Error("should not verify non-canonical s")
		}
	})
}

func TestSignErrors(t *testing.T) {
	drbg := testdata.New("frost sign errors")
	message := []byte("error test")

	_, signers, _, err := frost.KeyGen(kgDomain, 5, 3, drbg.Data(64))
	if err != nil {
		t.Fatal(err)
	}

	nonces := make([]frost.Nonce, 3)
	commitments := make([]frost.Commitment, 3)
	for i := range 3 {
		nonces[i], commitments[i] = signers[i].Commit(drbg.Data(64))
	}

	t.Run("signer not in commitments", func(t *testing.T) {
		// Signer 4 (index 3) is not in commitments for signers 1,2,3.
		_, err := signers[3].Sign(signDomain, nonces[0], message, commitments)
		if err == nil {
			t.Error("expected error for missing signer")
		}
	})

	t.Run("duplicate identifiers", func(t *testing.T) {
		dupes := []frost.Commitment{commitments[0], commitments[0], commitments[1]}
		_, err := signers[0].Sign(signDomain, nonces[0], message, dupes)
		if err == nil {
			t.Error("expected error for duplicate identifiers")
		}
	})
}

func TestAggregateErrors(t *testing.T) {
	drbg := testdata.New("frost aggregate errors")

	groupKey, _, _, err := frost.KeyGen(kgDomain, 5, 3, drbg.Data(64))
	if err != nil {
		t.Fatal(err)
	}

	t.Run("mismatched lengths", func(t *testing.T) {
		commitments := []frost.Commitment{{Identifier: 1, Hiding: make([]byte, 32), Binding: make([]byte, 32)}}
		_, err := frost.Aggregate(signDomain, groupKey, []byte("msg"), commitments, [][]byte{})
		if err == nil {
			t.Error("expected error for mismatched lengths")
		}
	})

	t.Run("invalid share bytes", func(t *testing.T) {
		commitments := []frost.Commitment{{Identifier: 1, Hiding: make([]byte, 32), Binding: make([]byte, 32)}}
		badShare := bytes.Repeat([]byte{0xff}, 32)
		_, err := frost.Aggregate(signDomain, groupKey, []byte("msg"), commitments, [][]byte{badShare})
		if err == nil {
			t.Error("expected error for invalid share encoding")
		}
	})
}

func TestDeterministicKeyGen(t *testing.T) {
	seed := testdata.New("frost deterministic").Data(64)

	groupKey1, signers1, vs1, err := frost.KeyGen(kgDomain, 5, 3, seed)
	if err != nil {
		t.Fatal(err)
	}

	groupKey2, signers2, vs2, err := frost.KeyGen(kgDomain, 5, 3, seed)
	if err != nil {
		t.Fatal(err)
	}

	if groupKey1.Equal(groupKey2) != 1 {
		t.Error("group keys differ for same seed")
	}

	for i := range signers1 {
		if signers1[i].VerifyingShare().Equal(signers2[i].VerifyingShare()) != 1 {
			t.Errorf("verifying share %d differs for same seed", i)
		}

		if vs1[i].Equal(vs2[i]) != 1 {
			t.Errorf("verifying share (returned) %d differs for same seed", i)
		}
	}
}

func FuzzVerify(f *testing.F) {
	drbg := testdata.New("frost fuzz verify")
	_, signers, _, _ := frost.KeyGen(kgDomain, 3, 2, drbg.Data(64))

	for range 10 {
		f.Add(drbg.Data(frost.SignatureSize), drbg.Data(32))
	}

	f.Fuzz(func(t *testing.T, signature, message []byte) {
		valid := frost.Verify(signDomain, signers[0].GroupKey(), message, signature)
		if valid {
			t.Errorf("Verify(signature=%x, message=%x) = true, want = false", signature, message)
		}
	})
}
