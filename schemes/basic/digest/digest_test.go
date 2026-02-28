package digest_test

import (
	"bytes"
	"testing"

	"github.com/codahale/thyrse/hazmat/kt128"
	"github.com/codahale/thyrse/schemes/basic/digest"
)

func TestDigest_Size(t *testing.T) {
	t.Run("unkeyed", func(t *testing.T) {
		h := digest.New("test")
		if got, want := h.Size(), digest.UnkeyedSize; got != want {
			t.Errorf("Size() = %d, want %d", got, want)
		}
	})

	t.Run("keyed", func(t *testing.T) {
		h := digest.NewKeyed("test", []byte("key"))
		if got, want := h.Size(), digest.KeyedSize; got != want {
			t.Errorf("Size() = %d, want %d", got, want)
		}
	})
}

func TestDigest_BlockSize(t *testing.T) {
	h := digest.New("test")
	if got, want := h.BlockSize(), kt128.BlockSize; got != want {
		t.Errorf("BlockSize() = %d, want %d", got, want)
	}
}

func TestDigest_Sum(t *testing.T) {
	h := digest.New("com.example.test")
	input := []byte("Hello, world!")
	h.Write(input)

	sum := h.Sum(nil)
	if got, want := len(sum), 32; got != want {
		t.Errorf("len(Sum()) = %d, want %d", got, want)
	}

	// Verify idempotency of Sum (it shouldn't reset the state)
	// Although our implementation reconstructs the state, so it naturally is idempotent w.r.t the buffer.
	sum2 := h.Sum(nil)
	if got, want := sum2, sum; !bytes.Equal(got, want) {
		t.Errorf("Sum() = %x, want %x", got, want)
	}

	// Verify appending works
	h.Write(input) // "Hello, world!Hello, world!"
	sum3 := h.Sum(nil)
	if bytes.Equal(sum, sum3) {
		t.Error("Sum() should change after Write()")
	}
}

func TestDigest_Reset(t *testing.T) {
	h := digest.New("com.example.test")
	h.Write([]byte("data"))
	sum1 := h.Sum(nil)

	h.Reset()
	sumEmpty := h.Sum(nil)

	if bytes.Equal(sum1, sumEmpty) {
		t.Error("Reset() didn't clear the buffer")
	}

	h.Write([]byte("data"))
	sum2 := h.Sum(nil)

	if !bytes.Equal(sum1, sum2) {
		t.Errorf("Sum() after Reset+Write = %x, want %x", sum2, sum1)
	}
}
