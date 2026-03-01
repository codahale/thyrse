package oae2_test

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"

	"github.com/codahale/thyrse"
	"github.com/codahale/thyrse/internal/testdata"
	"github.com/codahale/thyrse/schemes/basic/oae2"
)

func TestNewReader(t *testing.T) {
	t.Run("invalid block size", func(t *testing.T) {
		defer func() {
			if r := recover(); r == nil {
				t.Errorf("expected panic for blockSize=0")
			}
		}()
		oae2.NewReader(thyrse.New("test"), nil, 0)
	})

	t.Run("multiple blocks", func(t *testing.T) {
		pWriter := thyrse.New("test")
		pReader := pWriter.Clone()

		var buf bytes.Buffer
		blockSize := 64

		w := oae2.NewWriter(pWriter, &buf, blockSize)

		input := []byte(strings.Repeat("this is a test of the oae2 stream.", 10))

		// Write data
		n, err := w.Write(input)
		if err != nil {
			t.Fatalf("unexpected error during write: %v", err)
		}
		if n != len(input) {
			t.Fatalf("wrote %d bytes, expected %d", n, len(input))
		}

		// Close writer
		err = w.Close()
		if err != nil {
			t.Fatalf("unexpected error during close: %v", err)
		}

		// Read data
		r := oae2.NewReader(pReader, &buf, blockSize)
		output, err := io.ReadAll(r)
		if err != nil {
			t.Fatalf("unexpected error during read: %v", err)
		}

		if !bytes.Equal(input, output) {
			t.Fatalf("expected output %q, got %q", input, output)
		}
	})

	t.Run("empty stream", func(t *testing.T) {
		pWriter := thyrse.New("test")
		pReader := pWriter.Clone()

		var buf bytes.Buffer
		blockSize := 64

		w := oae2.NewWriter(pWriter, &buf, blockSize)

		// Close writer
		err := w.Close()
		if err != nil {
			t.Fatalf("unexpected error during close: %v", err)
		}

		// Read data
		r := oae2.NewReader(pReader, &buf, blockSize)
		output, err := io.ReadAll(r)
		if err != nil {
			t.Fatalf("unexpected error during read: %v", err)
		}

		if len(output) != 0 {
			t.Fatalf("expected empty output, got %q", output)
		}
	})

	t.Run("exact block size", func(t *testing.T) {
		pWriter := thyrse.New("test")
		pReader := pWriter.Clone()

		var buf bytes.Buffer
		blockSize := 64

		w := oae2.NewWriter(pWriter, &buf, blockSize)

		input := bytes.Repeat([]byte("A"), blockSize)

		// Write data
		n, err := w.Write(input)
		if err != nil {
			t.Fatalf("unexpected error during write: %v", err)
		}
		if n != len(input) {
			t.Fatalf("wrote %d bytes, expected %d", n, len(input))
		}

		// Close writer
		err = w.Close()
		if err != nil {
			t.Fatalf("unexpected error during close: %v", err)
		}

		// Read data
		r := oae2.NewReader(pReader, &buf, blockSize)
		output, err := io.ReadAll(r)
		if err != nil {
			t.Fatalf("unexpected error during read: %v", err)
		}

		if !bytes.Equal(input, output) {
			t.Fatalf("expected output %q, got %q", input, output)
		}
	})

	t.Run("modified stream", func(t *testing.T) {
		pWriter := thyrse.New("test")
		pReader := pWriter.Clone()

		var buf bytes.Buffer
		blockSize := 64

		w := oae2.NewWriter(pWriter, &buf, blockSize)
		input := bytes.Repeat([]byte("A"), blockSize*2)
		_, _ = w.Write(input)
		_ = w.Close()

		data := buf.Bytes()
		data[0] ^= 1 // Corrupt the first byte

		r := oae2.NewReader(pReader, bytes.NewReader(data), blockSize)
		_, err := io.ReadAll(r)
		if !errors.Is(err, thyrse.ErrInvalidCiphertext) {
			t.Fatalf("expected ErrInvalidCiphertext, got %v", err)
		}
	})

	t.Run("reordered blocks", func(t *testing.T) {
		pWriter := thyrse.New("test")
		pReader := pWriter.Clone()

		var buf bytes.Buffer
		blockSize := 64

		w := oae2.NewWriter(pWriter, &buf, blockSize)
		input := bytes.Repeat([]byte("A"), blockSize*3)
		_, _ = w.Write(input)
		_ = w.Close()

		data := buf.Bytes()
		blockLen := blockSize + thyrse.TagSize

		// Swap block 0 and block 1
		block0 := make([]byte, blockLen)
		copy(block0, data[:blockLen])

		block1 := make([]byte, blockLen)
		copy(block1, data[blockLen:blockLen*2])

		copy(data[:blockLen], block1)
		copy(data[blockLen:blockLen*2], block0)

		r := oae2.NewReader(pReader, bytes.NewReader(data), blockSize)
		_, err := io.ReadAll(r)
		if !errors.Is(err, thyrse.ErrInvalidCiphertext) {
			t.Fatalf("expected ErrInvalidCiphertext, got %v", err)
		}
	})

	t.Run("truncated stream missing bytes", func(t *testing.T) {
		pWriter := thyrse.New("test")
		pReader := pWriter.Clone()

		var buf bytes.Buffer
		blockSize := 64

		w := oae2.NewWriter(pWriter, &buf, blockSize)
		input := bytes.Repeat([]byte("A"), blockSize*3)
		_, _ = w.Write(input)
		_ = w.Close()

		data := buf.Bytes()
		data = data[:len(data)-10] // Truncate last 10 bytes

		r := oae2.NewReader(pReader, bytes.NewReader(data), blockSize)
		_, err := io.ReadAll(r)
		if !errors.Is(err, thyrse.ErrInvalidCiphertext) {
			t.Fatalf("expected thyrse.ErrInvalidCiphertext, got %v", err)
		}
	})

	t.Run("truncated stream dropped final block", func(t *testing.T) {
		pWriter := thyrse.New("test")
		pReader := pWriter.Clone()

		var buf bytes.Buffer
		blockSize := 64

		w := oae2.NewWriter(pWriter, &buf, blockSize)
		input := bytes.Repeat([]byte("A"), blockSize*3)
		_, _ = w.Write(input)
		_ = w.Close()

		data := buf.Bytes()
		blockLen := blockSize + thyrse.TagSize
		// Drop the last block entirely
		data = data[:len(data)-blockLen]

		r := oae2.NewReader(pReader, bytes.NewReader(data), blockSize)
		_, err := io.ReadAll(r)
		if !errors.Is(err, thyrse.ErrInvalidCiphertext) {
			t.Fatalf("expected ErrInvalidCiphertext, got %v", err)
		}
	})
}

func TestWriter_Write(t *testing.T) {
	t.Run("underlying writer error", func(t *testing.T) {
		ew := &testdata.ErrWriter{Err: errors.New("write failed")}
		w := oae2.NewWriter(thyrse.New("example"), ew, 64)

		// Write enough to trigger a flush (>= blockSize).
		_, err := w.Write(bytes.Repeat([]byte("A"), 64))
		if !errors.Is(err, ew.Err) {
			t.Errorf("expected %v, got %v", ew.Err, err)
		}
	})
}

func TestWriter_Close(t *testing.T) {
	t.Run("idempotent close", func(t *testing.T) {
		var buf bytes.Buffer
		w := oae2.NewWriter(thyrse.New("example"), &buf, 64)
		if _, err := w.Write([]byte("hello")); err != nil {
			t.Fatal(err)
		}
		if err := w.Close(); err != nil {
			t.Fatal(err)
		}
		if err := w.Close(); err != nil {
			t.Errorf("expected nil on second close, got %v", err)
		}
	})
}

func TestReader_Read(t *testing.T) {
	t.Run("empty read", func(t *testing.T) {
		r := oae2.NewReader(thyrse.New("example"), bytes.NewReader(nil), 64)
		n, err := r.Read(nil)
		if n != 0 || err != nil {
			t.Errorf("expected 0, nil; got %d, %v", n, err)
		}
	})

	t.Run("underlying reader error", func(t *testing.T) {
		er := &testdata.ErrReader{Err: errors.New("read failed")}
		r := oae2.NewReader(thyrse.New("example"), er, 64)

		_, err := r.Read(make([]byte, 100))
		if !errors.Is(err, er.Err) {
			t.Errorf("expected %v, got %v", er.Err, err)
		}
	})
}

func TestNewWriter(t *testing.T) {
	t.Run("invalid block size", func(t *testing.T) {
		defer func() {
			if r := recover(); r == nil {
				t.Errorf("expected panic for blockSize=0")
			}
		}()
		oae2.NewWriter(thyrse.New("test"), nil, 0)
	})
}

func Example() {
	encrypt := func(key, plaintext []byte) []byte {
		// Initialize a protocol with a domain string.
		p := thyrse.New("com.example.oae2")

		// Mix the key into the protocol.
		p.Mix("key", key)

		// Create a buffer to hold the ciphertext.
		ciphertext := bytes.NewBuffer(nil)

		// Create an OAE2 streaming authenticated encryption writer with a 64-byte block size.
		w := oae2.NewWriter(p, ciphertext, 64)

		// Write the plaintext to the writer.
		if _, err := w.Write(plaintext); err != nil {
			panic(err)
		}

		// Close the writer to flush the final block.
		if err := w.Close(); err != nil {
			panic(err)
		}

		return ciphertext.Bytes()
	}

	decrypt := func(key, ciphertext []byte) ([]byte, error) {
		// Initialize a protocol with a domain string.
		p := thyrse.New("com.example.oae2")

		// Mix the key into the protocol.
		p.Mix("key", key)

		// Create an OAE2 streaming authenticated encryption reader with a 64-byte block size.
		r := oae2.NewReader(p, bytes.NewReader(ciphertext), 64)

		// Read the plaintext from the reader.
		plaintext, err := io.ReadAll(r)
		if err != nil {
			return nil, err
		}

		return plaintext, nil
	}

	key := []byte("my-secret-key")
	plaintext := []byte("hello world")

	ciphertext := encrypt(key, plaintext)
	fmt.Printf("ciphertext = %x\n", ciphertext)

	plaintext, err := decrypt(key, ciphertext)
	if err != nil {
		panic(err)
	}
	fmt.Printf("plaintext  = %s\n", plaintext)

	// Output:
	// ciphertext = 56df9a58321769a21951e24fb1fe5c01cdc61c005d3d0aea0b5464ee1e0947922bee24c66f895f831bb83acbaa3cae359734933b9fae903ce93d1cff4425a847fddbb9ae7d86f872440354d5b7e93853280c7e2e4ebfa44904ce05aecd89e4af
	// plaintext  = hello world
}

var lengths = []struct {
	name string
	n    int
}{
	{"16B", 16},
	{"32B", 32},
	{"64B", 64},
	{"128B", 128},
	{"256B", 256},
	{"1KiB", 1024},
	{"16KiB", 16 * 1024},
	{"1MiB", 1024 * 1024},
}

func BenchmarkWriter(b *testing.B) {
	p := thyrse.New("example")
	p.Mix("key", []byte("it's a key"))

	for _, length := range lengths {
		b.Run(length.name, func(b *testing.B) {
			plaintext := make([]byte, length.n)

			b.SetBytes(int64(length.n))
			b.ReportAllocs()
			for b.Loop() {
				w := oae2.NewWriter(p.Clone(), io.Discard, 64)
				r := bytes.NewReader(plaintext)
				if _, err := io.Copy(w, r); err != nil {
					b.Fatal(err)
				}
				if err := w.Close(); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkReader(b *testing.B) {
	p := thyrse.New("example")
	p.Mix("key", []byte("it's a key"))

	for _, length := range lengths {
		b.Run(length.name, func(b *testing.B) {
			plaintext := make([]byte, length.n)
			ciphertext := bytes.NewBuffer(make([]byte, 0, length.n))
			w := oae2.NewWriter(p.Clone(), ciphertext, 64)
			r := bytes.NewReader(plaintext)
			if _, err := io.Copy(w, r); err != nil {
				b.Fatal(err)
			}
			if err := w.Close(); err != nil {
				b.Fatal(err)
			}

			b.SetBytes(int64(length.n))
			b.ReportAllocs()

			for b.Loop() {
				r := oae2.NewReader(p.Clone(), bytes.NewReader(ciphertext.Bytes()), 64)
				if _, err := io.Copy(io.Discard, r); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func FuzzReader(f *testing.F) {
	drbg := testdata.New("thyrse oae2 fuzz")
	for range 10 {
		f.Add(drbg.Data(1024))
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		r := oae2.NewReader(thyrse.New("fuzz"), bytes.NewReader(data), 64)
		v, err := io.ReadAll(r)
		if err == nil {
			t.Errorf("ReadAll(data=%x) = plaintext=%x, want = err", data, v)
		}
	})
}
