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
				t.Fatal("NewReader() did not panic")
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

		n, err := w.Write(input)
		if err != nil {
			t.Fatal(err)
		}
		if got, want := n, len(input); got != want {
			t.Fatalf("Write() = %d, want %d", got, want)
		}

		if err := w.Close(); err != nil {
			t.Fatal(err)
		}

		r := oae2.NewReader(pReader, &buf, blockSize)
		output, err := io.ReadAll(r)
		if err != nil {
			t.Fatal(err)
		}

		if got, want := output, input; !bytes.Equal(got, want) {
			t.Fatalf("ReadAll() = %q, want %q", got, want)
		}
	})

	t.Run("empty stream", func(t *testing.T) {
		pWriter := thyrse.New("test")
		pReader := pWriter.Clone()

		var buf bytes.Buffer
		blockSize := 64

		w := oae2.NewWriter(pWriter, &buf, blockSize)
		if err := w.Close(); err != nil {
			t.Fatal(err)
		}

		r := oae2.NewReader(pReader, &buf, blockSize)
		output, err := io.ReadAll(r)
		if err != nil {
			t.Fatal(err)
		}

		if got, want := len(output), 0; got != want {
			t.Fatalf("ReadAll() len = %d, want %d", got, want)
		}
	})

	t.Run("exact block size", func(t *testing.T) {
		pWriter := thyrse.New("test")
		pReader := pWriter.Clone()

		var buf bytes.Buffer
		blockSize := 64

		w := oae2.NewWriter(pWriter, &buf, blockSize)

		input := bytes.Repeat([]byte("A"), blockSize)

		n, err := w.Write(input)
		if err != nil {
			t.Fatal(err)
		}
		if got, want := n, len(input); got != want {
			t.Fatalf("Write() = %d, want %d", got, want)
		}

		if err := w.Close(); err != nil {
			t.Fatal(err)
		}

		r := oae2.NewReader(pReader, &buf, blockSize)
		output, err := io.ReadAll(r)
		if err != nil {
			t.Fatal(err)
		}

		if got, want := output, input; !bytes.Equal(got, want) {
			t.Fatalf("ReadAll() = %q, want %q", got, want)
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
		if got, want := err, thyrse.ErrInvalidCiphertext; !errors.Is(got, want) {
			t.Fatalf("ReadAll() err = %v, want %v", got, want)
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
		if got, want := err, thyrse.ErrInvalidCiphertext; !errors.Is(got, want) {
			t.Fatalf("ReadAll() err = %v, want %v", got, want)
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
		if got, want := err, thyrse.ErrInvalidCiphertext; !errors.Is(got, want) {
			t.Fatalf("ReadAll() err = %v, want %v", got, want)
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
		if got, want := err, thyrse.ErrInvalidCiphertext; !errors.Is(got, want) {
			t.Fatalf("ReadAll() err = %v, want %v", got, want)
		}
	})
}

func TestWriter_Write(t *testing.T) {
	t.Run("underlying writer error", func(t *testing.T) {
		ew := &testdata.ErrWriter{Err: errors.New("write failed")}
		w := oae2.NewWriter(thyrse.New("example"), ew, 64)

		// Write enough to trigger a flush (>= blockSize).
		_, err := w.Write(bytes.Repeat([]byte("A"), 64))
		if got, want := err, ew.Err; !errors.Is(got, want) {
			t.Errorf("Write() err = %v, want %v", got, want)
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
			t.Errorf("Close() err = %v, want nil", err)
		}
	})
}

func TestReader_Read(t *testing.T) {
	t.Run("empty read", func(t *testing.T) {
		r := oae2.NewReader(thyrse.New("example"), bytes.NewReader(nil), 64)
		n, err := r.Read(nil)
		if got, want := n, 0; got != want {
			t.Errorf("Read() = %d, want %d", got, want)
		}
		if err != nil {
			t.Errorf("Read() err = %v, want nil", err)
		}
	})

	t.Run("underlying reader error", func(t *testing.T) {
		er := &testdata.ErrReader{Err: errors.New("read failed")}
		r := oae2.NewReader(thyrse.New("example"), er, 64)

		_, err := r.Read(make([]byte, 100))
		if got, want := err, er.Err; !errors.Is(got, want) {
			t.Errorf("Read() err = %v, want %v", got, want)
		}
	})
}

func TestNewWriter(t *testing.T) {
	t.Run("invalid block size", func(t *testing.T) {
		defer func() {
			if r := recover(); r == nil {
				t.Fatal("NewWriter() did not panic")
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
	// ciphertext = b09d6f80750d7db2f6b73b2947f993c9c57df65d86d06aa4c1a26540d7166574bc0493ea4ee0048c523f92e6980cbc5ab7f0540774ff7029cce5f571285d51d0b9c88833f1a4f87947dc00ed502d7107d8f44ed0f60c1397aafb79571bd6e0bb
	// plaintext  = hello world
}

func BenchmarkWriter(b *testing.B) {
	p := thyrse.New("example")
	p.Mix("key", []byte("it's a key"))

	for _, size := range testdata.Sizes {
		b.Run(size.Name, func(b *testing.B) {
			plaintext := make([]byte, size.N)

			b.SetBytes(int64(size.N))
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

	for _, size := range testdata.Sizes {
		b.Run(size.Name, func(b *testing.B) {
			plaintext := make([]byte, size.N)
			ciphertext := bytes.NewBuffer(make([]byte, 0, size.N))
			w := oae2.NewWriter(p.Clone(), ciphertext, 64)
			r := bytes.NewReader(plaintext)
			if _, err := io.Copy(w, r); err != nil {
				b.Fatal(err)
			}
			if err := w.Close(); err != nil {
				b.Fatal(err)
			}

			b.SetBytes(int64(size.N))
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
			t.Errorf("ReadAll(data=%x) = plaintext=%x, want error", data, v)
		}
	})
}
