package aestream_test

import (
	"bytes"
	"encoding/binary"
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
		w := aestream.NewWriter(p1, buf, 0)
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
		r := aestream.NewReader(p2, bytes.NewReader(buf.Bytes()), 0)
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
		w := aestream.NewWriter(p1, buf, 0)
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
		r := aestream.NewReader(p2, bytes.NewReader(buf.Bytes()), 0)
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
		w := aestream.NewWriter(p1, buf, 0)

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
		r := aestream.NewReader(p2, bytes.NewReader(buf.Bytes()), 0)
		b, err := io.ReadAll(r)
		if err != nil {
			t.Fatal(err)
		}

		if got, want := string(b), "firstsecond"; got != want {
			t.Errorf("got %q, want %q", got, want)
		}
	})

	t.Run("32-bit block length", func(t *testing.T) {
		message := make([]byte, 1<<16+1)
		p1 := thyrse.New("example")
		p1.Mix("key", []byte("it's a key"))
		buf := bytes.NewBuffer(nil)
		w := aestream.NewWriter(p1, buf, 0)
		if _, err := w.Write(message); err != nil {
			t.Fatal(err)
		}
		if err := w.Close(); err != nil {
			t.Fatal(err)
		}

		p2 := thyrse.New("example")
		p2.Mix("key", []byte("it's a key"))
		header, err := p2.Open("header", nil, buf.Bytes()[:4+thyrse.TagSize])
		if err != nil {
			t.Fatal(err)
		}
		if got, want := binary.BigEndian.Uint32(header), uint32(len(message)); got != want {
			t.Errorf("block length = %d, want %d", got, want)
		}
	})

	t.Run("maximum block size", func(t *testing.T) {
		message := []byte("0123456789")
		p1 := thyrse.New("example")
		p1.Mix("key", []byte("it's a key"))
		buf := bytes.NewBuffer(nil)
		w := aestream.NewWriter(p1, buf, 4)
		if _, err := w.Write(message); err != nil {
			t.Fatal(err)
		}
		if err := w.Close(); err != nil {
			t.Fatal(err)
		}

		const frameOverhead = 4 + 2*thyrse.TagSize
		if got, want := buf.Len(), len(message)+4*frameOverhead; got != want {
			t.Fatalf("ciphertext length = %d, want %d", got, want)
		}

		p2 := thyrse.New("example")
		p2.Mix("key", []byte("it's a key"))
		plaintext, err := io.ReadAll(aestream.NewReader(p2, bytes.NewReader(buf.Bytes()), 4))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(plaintext, message) {
			t.Errorf("ReadAll() = %x, want %x", plaintext, message)
		}
	})
}

func TestWriter_Write(t *testing.T) {
	t.Run("underlying writer error", func(t *testing.T) {
		ew := &testdata.ErrWriter{Err: errors.New("write failed")}
		w := aestream.NewWriter(thyrse.New("example"), ew, 0)

		_, err := w.Write([]byte("hello"))
		if got, want := err, ew.Err; !errors.Is(got, want) {
			t.Errorf("Write() err = %v, want %v", got, want)
		}
		if _, err := w.Write([]byte("again")); !errors.Is(err, ew.Err) {
			t.Errorf("subsequent Write() err = %v, want %v", err, ew.Err)
		}
		if err := w.Close(); !errors.Is(err, ew.Err) {
			t.Errorf("Close() err = %v, want %v", err, ew.Err)
		}
	})

	t.Run("short write", func(t *testing.T) {
		w := aestream.NewWriter(thyrse.New("example"), &testdata.ShortWriter{}, 0)
		n, err := w.Write([]byte("hello"))
		if !errors.Is(err, io.ErrShortWrite) {
			t.Errorf("Write() err = %v, want ErrShortWrite", err)
		}
		if n != 0 {
			t.Errorf("Write() n = %d, want 0", n)
		}
		if _, err := w.Write([]byte("again")); !errors.Is(err, io.ErrShortWrite) {
			t.Errorf("subsequent Write() err = %v, want ErrShortWrite", err)
		}
		if err := w.Close(); !errors.Is(err, io.ErrShortWrite) {
			t.Errorf("Close() err = %v, want ErrShortWrite", err)
		}
	})

	t.Run("short close", func(t *testing.T) {
		w := aestream.NewWriter(thyrse.New("example"), &testdata.ShortWriter{}, 0)
		if err := w.Close(); !errors.Is(err, io.ErrShortWrite) {
			t.Errorf("Close() err = %v, want ErrShortWrite", err)
		}
		if err := w.Close(); !errors.Is(err, io.ErrShortWrite) {
			t.Errorf("second Close() err = %v, want ErrShortWrite", err)
		}
	})

	t.Run("write after close", func(t *testing.T) {
		w := aestream.NewWriter(thyrse.New("example"), io.Discard, 0)
		if err := w.Close(); err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write([]byte("message")); !errors.Is(err, io.ErrClosedPipe) {
			t.Errorf("Write() err = %v, want ErrClosedPipe", err)
		}
	})
}

func TestNewReader(t *testing.T) {
	t.Run("truncation", func(t *testing.T) {
		p1 := thyrse.New("example")
		p1.Mix("key", []byte("it's a key"))
		buf := bytes.NewBuffer(nil)
		w := aestream.NewWriter(p1, buf, 0)
		if _, err := w.Write([]byte("message")); err != nil {
			t.Fatal(err)
		}
		// Do not close w, so no terminal block is written.

		p2 := thyrse.New("example")
		p2.Mix("key", []byte("it's a key"))
		r := aestream.NewReader(p2, bytes.NewReader(buf.Bytes()), 0)
		_, err := io.ReadAll(r)
		if err == nil {
			t.Error("ReadAll() err = nil, want error")
		}
	})

	t.Run("partial header", func(t *testing.T) {
		p1 := thyrse.New("example")
		p1.Mix("key", []byte("it's a key"))
		buf := bytes.NewBuffer(nil)
		w := aestream.NewWriter(p1, buf, 0)
		if _, err := w.Write([]byte("message")); err != nil {
			t.Fatal(err)
		}
		_ = w.Close()

		const sealedHeaderSize = 4 + thyrse.TagSize
		firstFrameSize := sealedHeaderSize + len("message") + thyrse.TagSize
		truncated := buf.Bytes()[:firstFrameSize+sealedHeaderSize-2]

		p2 := thyrse.New("example")
		p2.Mix("key", []byte("it's a key"))
		r := aestream.NewReader(p2, bytes.NewReader(truncated), 0)
		_, err := io.ReadAll(r)
		if err == nil {
			t.Error("ReadAll() err = nil, want error")
		} else if got, want := err, thyrse.ErrInvalidCiphertext; !errors.Is(got, want) {
			t.Errorf("ReadAll() err = %v, want %v", got, want)
		}
	})

	t.Run("maximum block size", func(t *testing.T) {
		p1 := thyrse.New("example")
		p1.Mix("key", []byte("it's a key"))
		buf := bytes.NewBuffer(nil)
		w := aestream.NewWriter(p1, buf, 5)
		if _, err := w.Write([]byte("12345")); err != nil {
			t.Fatal(err)
		}
		if err := w.Close(); err != nil {
			t.Fatal(err)
		}

		ciphertext := bytes.NewReader(buf.Bytes())
		p2 := thyrse.New("example")
		p2.Mix("key", []byte("it's a key"))
		r := aestream.NewReader(p2, ciphertext, 4)
		_, err := r.Read(make([]byte, 1))
		if !errors.Is(err, thyrse.ErrInvalidCiphertext) {
			t.Errorf("Read() err = %v, want %v", err, thyrse.ErrInvalidCiphertext)
		}
		if got, want := ciphertext.Len(), buf.Len()-(4+thyrse.TagSize); got != want {
			t.Errorf("ciphertext bytes remaining = %d, want %d", got, want)
		}
		if _, err := r.Read(make([]byte, 1)); !errors.Is(err, thyrse.ErrInvalidCiphertext) {
			t.Errorf("subsequent Read() err = %v, want %v", err, thyrse.ErrInvalidCiphertext)
		}
	})
}

func TestReader_Read(t *testing.T) {
	t.Run("empty read", func(t *testing.T) {
		r := aestream.NewReader(thyrse.New("example"), bytes.NewReader(nil), 0)
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
		r := aestream.NewReader(thyrse.New("example"), er, 0)

		_, err := r.Read(make([]byte, 100))
		if got, want := err, er.Err; !errors.Is(got, want) {
			t.Errorf("Read() err = %v, want %v", got, want)
		}
		if _, err := r.Read(make([]byte, 100)); !errors.Is(err, er.Err) {
			t.Errorf("subsequent Read() err = %v, want %v", err, er.Err)
		}
	})

	t.Run("empty stream", func(t *testing.T) {
		r := aestream.NewReader(thyrse.New("example"), bytes.NewReader(nil), 0)
		_, err := r.Read(make([]byte, 100))
		if got, want := err, thyrse.ErrInvalidCiphertext; !errors.Is(got, want) {
			t.Errorf("Read() err = %v, want %v", got, want)
		}
	})

	t.Run("invalid header tag", func(t *testing.T) {
		buf := bytes.NewBuffer(nil)
		w := aestream.NewWriter(thyrse.New("example"), buf, 0)
		_, _ = w.Write([]byte("message"))
		_ = w.Close()

		data := buf.Bytes()
		data[5] ^= 1 // tamper with header tag

		r := aestream.NewReader(thyrse.New("example"), bytes.NewReader(data), 0)
		_, err := io.ReadAll(r)
		if got, want := err, thyrse.ErrInvalidCiphertext; !errors.Is(got, want) {
			t.Errorf("Read() err = %v, want %v", got, want)
		}
		if _, err := r.Read(make([]byte, 1)); !errors.Is(err, thyrse.ErrInvalidCiphertext) {
			t.Errorf("subsequent Read() err = %v, want %v", err, thyrse.ErrInvalidCiphertext)
		}
	})

	t.Run("invalid block tag", func(t *testing.T) {
		buf := bytes.NewBuffer(nil)
		w := aestream.NewWriter(thyrse.New("example"), buf, 0)
		_, _ = w.Write([]byte("message"))
		_ = w.Close()

		data := buf.Bytes()
		data[len(data)-1] ^= 1 // tamper with block tag

		r := aestream.NewReader(thyrse.New("example"), bytes.NewReader(data), 0)
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
			w := aestream.NewWriter(p1, io.Discard, 0)
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
			w := aestream.NewWriter(p1, ciphertext, 0)
			buf := make([]byte, size.N)
			_, _ = w.Write(buf)
			_ = w.Close()

			p2 := thyrse.New("example")
			p2.Mix("key", []byte("it's a key"))

			for b.Loop() {
				p3 := p2.Clone()
				aestream.NewReader(p3, bytes.NewReader(ciphertext.Bytes()), 0)
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
			w := aestream.NewWriter(p1, ciphertext, 0)
			buf := make([]byte, size.N)
			_, _ = w.Write(buf)
			_ = w.Close()

			p2 := thyrse.New("example")
			p2.Mix("key", []byte("it's a key"))

			for b.Loop() {
				p3 := p2.Clone()
				r := aestream.NewReader(p3, bytes.NewReader(ciphertext.Bytes()), 0)
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
		w := aestream.NewWriter(p, ciphertext, 0)

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
		r := aestream.NewReader(p, bytes.NewReader(ciphertext), 0)

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
	// ciphertext = 2a4c7d43006f1c1daa54a2dfff5c3670dbb907ddaebc3f46b7ef7a6058e2a44b7f81689a24a23dc975f4e328499795cf4761f7e07f52612cf281143dacfa90acb4048175e988c1e2e17c065c8f4d33e3b30ec5a5b4f62a23b5a0168f36eb372156a3a54b384b619986372871b4e78cc8309a85628e137764145dfaf68b0f3f74817f7372252a5ed9961b7a510cd10a24005b05
	// plaintext  = hello world
}

func FuzzReader(f *testing.F) {
	drbg := testdata.New("thyrse aestream fuzz")
	for range 10 {
		f.Add(drbg.Data(1024))
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		r := aestream.NewReader(thyrse.New("fuzz"), bytes.NewReader(data), 0)
		v, err := io.ReadAll(r)
		if err == nil {
			t.Errorf("ReadAll(data=%x) = plaintext=%x, want = err", data, v)
		}
	})
}
