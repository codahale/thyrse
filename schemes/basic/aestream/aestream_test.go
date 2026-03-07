package aestream_test

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"testing"

	"github.com/codahale/thyrse"
	"github.com/codahale/thyrse/internal/testdata"
	"github.com/codahale/thyrse/schemes/basic/aestream"
)

func TestNewWriter(t *testing.T) {
	t.Run("round trip", func(t *testing.T) {
		p1 := thyrse.New("example")
		p1.Mix("key", []byte("it's a key"))
		buf := bytes.NewBuffer(nil)
		w := aestream.NewWriter(p1, buf)
		if _, err := w.Write([]byte("here's one message; ")); err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write([]byte("and another")); err != nil {
			t.Fatal(err)
		}
		if err := w.Close(); err != nil {
			t.Fatal(err)
		}

		p2 := thyrse.New("example")
		p2.Mix("key", []byte("it's a key"))
		r := aestream.NewReader(p2, bytes.NewReader(buf.Bytes()))
		b, err := io.ReadAll(r)
		if err != nil {
			t.Fatal(err)
		}

		if got, want := b, []byte("here's one message; and another"); !bytes.Equal(got, want) {
			t.Errorf("io.ReadAll() = %x, want = %x", got, want)
		}
	})

	t.Run("io.Copy", func(t *testing.T) {
		p1 := thyrse.New("example")
		p1.Mix("key", []byte("it's a key"))
		buf := bytes.NewBuffer(nil)
		w := aestream.NewWriter(p1, buf)
		message := make([]byte, 2345)
		n, err := io.CopyBuffer(w, bytes.NewReader(message), make([]byte, 100))
		if err != nil {
			t.Fatal(err)
		}
		if got, want := n, int64(len(message)); got != want {
			t.Errorf("Copy(aestream, buf) = %d bytes, want = %d", got, want)
		}
		err = w.Close()
		if err != nil {
			t.Fatal(err)
		}

		p2 := thyrse.New("example")
		p2.Mix("key", []byte("it's a key"))
		r := aestream.NewReader(p2, bytes.NewReader(buf.Bytes()))
		b, err := io.ReadAll(r)
		if err != nil {
			t.Fatal(err)
		}

		if got, want := b, message; !bytes.Equal(got, want) {
			t.Errorf("io.ReadAll() = %x, want = %x", got, want)
		}
	})

	t.Run("empty write", func(t *testing.T) {
		p1 := thyrse.New("example")
		p1.Mix("key", []byte("it's a key"))
		buf := bytes.NewBuffer(nil)
		w := aestream.NewWriter(p1, buf)

		if _, err := w.Write([]byte("first")); err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write([]byte{}); err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write([]byte("second")); err != nil {
			t.Fatal(err)
		}
		if err := w.Close(); err != nil {
			t.Fatal(err)
		}

		p2 := thyrse.New("example")
		p2.Mix("key", []byte("it's a key"))
		r := aestream.NewReader(p2, bytes.NewReader(buf.Bytes()))
		b, err := io.ReadAll(r)
		if err != nil {
			t.Fatal(err)
		}

		if got, want := string(b), "firstsecond"; got != want {
			t.Errorf("got %q, want %q", got, want)
		}
	})
}

func TestWriter_Write(t *testing.T) {
	t.Run("underlying writer error", func(t *testing.T) {
		ew := &testdata.ErrWriter{Err: errors.New("write failed")}
		w := aestream.NewWriter(thyrse.New("example"), ew)

		_, err := w.Write([]byte("hello"))
		if got, want := err, ew.Err; !errors.Is(got, want) {
			t.Errorf("Write() err = %v, want %v", got, want)
		}
	})
}

func TestNewReader(t *testing.T) {
	t.Run("truncation", func(t *testing.T) {
		p1 := thyrse.New("example")
		p1.Mix("key", []byte("it's a key"))
		buf := bytes.NewBuffer(nil)
		w := aestream.NewWriter(p1, buf)
		if _, err := w.Write([]byte("message")); err != nil {
			t.Fatal(err)
		}
		// Do not close w, so no terminal block is written.

		p2 := thyrse.New("example")
		p2.Mix("key", []byte("it's a key"))
		r := aestream.NewReader(p2, bytes.NewReader(buf.Bytes()))
		_, err := io.ReadAll(r)
		if err == nil {
			t.Error("ReadAll() err = nil, want error")
		}
	})

	t.Run("partial header", func(t *testing.T) {
		p1 := thyrse.New("example")
		p1.Mix("key", []byte("it's a key"))
		buf := bytes.NewBuffer(nil)
		w := aestream.NewWriter(p1, buf)
		if _, err := w.Write([]byte("message")); err != nil {
			t.Fatal(err)
		}
		_ = w.Close()

		data := buf.Bytes()
		truncated := data[:len(data)-2]

		p2 := thyrse.New("example")
		p2.Mix("key", []byte("it's a key"))
		r := aestream.NewReader(p2, bytes.NewReader(truncated))
		_, err := io.ReadAll(r)
		if err == nil {
			t.Error("ReadAll() err = nil, want error")
		} else if got, want := err, thyrse.ErrInvalidCiphertext; !errors.Is(got, want) {
			t.Errorf("ReadAll() err = %v, want %v", got, want)
		}
	})
}

func TestReader_Read(t *testing.T) {
	t.Run("empty read", func(t *testing.T) {
		r := aestream.NewReader(thyrse.New("example"), bytes.NewReader(nil))
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
		r := aestream.NewReader(thyrse.New("example"), er)

		_, err := r.Read(make([]byte, 100))
		if got, want := err, er.Err; !errors.Is(got, want) {
			t.Errorf("Read() err = %v, want %v", got, want)
		}
	})

	t.Run("empty stream", func(t *testing.T) {
		r := aestream.NewReader(thyrse.New("example"), bytes.NewReader(nil))
		_, err := r.Read(make([]byte, 100))
		if got, want := err, thyrse.ErrInvalidCiphertext; !errors.Is(got, want) {
			t.Errorf("Read() err = %v, want %v", got, want)
		}
	})

	t.Run("invalid header tag", func(t *testing.T) {
		buf := bytes.NewBuffer(nil)
		w := aestream.NewWriter(thyrse.New("example"), buf)
		_, _ = w.Write([]byte("message"))
		_ = w.Close()

		data := buf.Bytes()
		data[5] ^= 1 // tamper with header tag

		r := aestream.NewReader(thyrse.New("example"), bytes.NewReader(data))
		_, err := io.ReadAll(r)
		if got, want := err, thyrse.ErrInvalidCiphertext; !errors.Is(got, want) {
			t.Errorf("Read() err = %v, want %v", got, want)
		}
	})

	t.Run("invalid block tag", func(t *testing.T) {
		buf := bytes.NewBuffer(nil)
		w := aestream.NewWriter(thyrse.New("example"), buf)
		_, _ = w.Write([]byte("message"))
		_ = w.Close()

		data := buf.Bytes()
		data[len(data)-1] ^= 1 // tamper with block tag

		r := aestream.NewReader(thyrse.New("example"), bytes.NewReader(data))
		_, err := io.ReadAll(r)
		if got, want := err, thyrse.ErrInvalidCiphertext; !errors.Is(got, want) {
			t.Errorf("Read() err = %v, want %v", got, want)
		}
	})
}

func BenchmarkNewWriter(b *testing.B) {
	for _, size := range testdata.Sizes {
		b.Run(size.Name, func(b *testing.B) {
			b.SetBytes(int64(size.N))
			b.ReportAllocs()

			p1 := thyrse.New("example")
			p1.Mix("key", []byte("it's a key"))
			w := aestream.NewWriter(p1, io.Discard)
			buf := make([]byte, size.N)

			for b.Loop() {
				if _, err := w.Write(buf); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkNewReader(b *testing.B) {
	// This is really only useful for compensating for the inability to remove setup costs from BenchmarkReader.
	for _, size := range testdata.Sizes {
		b.Run(size.Name, func(b *testing.B) {
			b.ReportAllocs()

			p1 := thyrse.New("example")
			p1.Mix("key", []byte("it's a key"))
			ciphertext := bytes.NewBuffer(make([]byte, 0, size.N))
			w := aestream.NewWriter(p1, ciphertext)
			buf := make([]byte, size.N)
			_, _ = w.Write(buf)
			_ = w.Close()

			p2 := thyrse.New("example")
			p2.Mix("key", []byte("it's a key"))

			for b.Loop() {
				p3 := p2.Clone()
				aestream.NewReader(p3, bytes.NewReader(ciphertext.Bytes()))
			}
		})
	}
}

func BenchmarkNewReader_Read(b *testing.B) {
	for _, size := range testdata.Sizes {
		b.Run(size.Name, func(b *testing.B) {
			b.SetBytes(int64(size.N))
			b.ReportAllocs()

			p1 := thyrse.New("example")
			p1.Mix("key", []byte("it's a key"))
			ciphertext := bytes.NewBuffer(make([]byte, 0, size.N))
			w := aestream.NewWriter(p1, ciphertext)
			buf := make([]byte, size.N)
			_, _ = w.Write(buf)
			_ = w.Close()

			p2 := thyrse.New("example")
			p2.Mix("key", []byte("it's a key"))

			for b.Loop() {
				p3 := p2.Clone()
				r := aestream.NewReader(p3, bytes.NewReader(ciphertext.Bytes()))
				if _, err := io.CopyBuffer(io.Discard, r, buf); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func Example() {
	encrypt := func(key, plaintext []byte) []byte {
		// Initialize a protocol with a domain string.
		p := thyrse.New("com.example.aestream")

		// Mix the key into the protocol.
		p.Mix("key", key)

		// Create a buffer to hold the ciphertext.
		ciphertext := bytes.NewBuffer(nil)

		// Create a streaming authenticated encryption writer.
		w := aestream.NewWriter(p, ciphertext)

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
		p := thyrse.New("com.example.aestream")

		// Mix the key into the protocol.
		p.Mix("key", key)

		// Create a streaming authenticated encryption reader.
		r := aestream.NewReader(p, bytes.NewReader(ciphertext))

		// Read the plaintext from the reader.
		plaintext, err := io.ReadAll(r)
		if err != nil {
			return nil, err
		}

		// Finally, return the plaintext.
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
	// ciphertext = dca9a867b30cebc09e48845ad7251792880ff07c4ee0ca93c684db2a2280a3a0ceee3b55ac009dff2978ba70e7479f4700dce503294d16df40152bda2bd488dadfe7fd424a0776d9c90cd48ad190f8
	// plaintext  = hello world
}

func FuzzReader(f *testing.F) {
	drbg := testdata.New("thyrse aestream fuzz")
	for range 10 {
		f.Add(drbg.Data(1024))
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		r := aestream.NewReader(thyrse.New("fuzz"), bytes.NewReader(data))
		v, err := io.ReadAll(r)
		if err == nil {
			t.Errorf("ReadAll(data=%x) = plaintext=%x, want = err", data, v)
		}
	})
}
