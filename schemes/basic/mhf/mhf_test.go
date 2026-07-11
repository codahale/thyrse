package mhf_test

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/codahale/thyrse/schemes/basic/mhf"
)

func ExampleHash() {
	domain := "example passwords"
	password := []byte("C'est moi, le Mario")
	salt := []byte("a yellow submarine")
	hash := mhf.Hash(domain, 1024, 3, 32, salt, password, nil, 32)
	fmt.Printf("hash = %x\n", hash)
	// Output:
	// hash = 269bd2393a3607763f453a52d7799d7f82a331e527dc7d47de7de9d2a4e54e14
}

func TestHash(t *testing.T) {
	domain := "example passwords"
	spaceCost, timeCost, blockSize := 16, 2, 32
	password := []byte("C'est moi, le Mario")
	salt := []byte("a yellow submarine")
	outputSize := 32
	hash := mhf.Hash(domain, spaceCost, timeCost, blockSize, salt, password, nil, outputSize)

	tests := map[string]struct {
		domain                         string
		spaceCost, timeCost, blockSize int
		salt, password                 []byte
		outputSize                     int
	}{
		"domain":      {"example crosswords", spaceCost, timeCost, blockSize, salt, password, outputSize},
		"space cost":  {domain, spaceCost + 1, timeCost, blockSize, salt, password, outputSize},
		"time cost":   {domain, spaceCost, timeCost + 1, blockSize, salt, password, outputSize},
		"block size":  {domain, spaceCost, timeCost, blockSize + 1, salt, password, outputSize},
		"salt":        {domain, spaceCost, timeCost, blockSize, []byte("okay"), password, outputSize},
		"password":    {domain, spaceCost, timeCost, blockSize, salt, []byte("It is I, Mario"), outputSize},
		"output size": {domain, spaceCost, timeCost, blockSize, salt, password, outputSize + 1},
	}

	if got := mhf.Hash(domain, spaceCost, timeCost, blockSize, salt, password, nil, outputSize); !bytes.Equal(got, hash) {
		t.Fatalf("Hash() = %x, want %x", got, hash)
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			got := mhf.Hash(tt.domain, tt.spaceCost, tt.timeCost, tt.blockSize, tt.salt, tt.password, nil, tt.outputSize)
			if bytes.Equal(got, hash) {
				t.Fatalf("Hash() = %x, want a different hash", got)
			}
		})
	}
}

func TestHashAppends(t *testing.T) {
	prefix := []byte("prefix")
	got := mhf.Hash("test", 8, 1, 32, []byte("salt"), []byte("password"), prefix, 48)
	if !bytes.Equal(got[:len(prefix)], prefix) {
		t.Fatalf("Hash() prefix = %q, want %q", got[:len(prefix)], prefix)
	}
	if got, want := len(got), len(prefix)+48; got != want {
		t.Fatalf("len(Hash()) = %d, want %d", got, want)
	}
}

func TestHashBlockSizeBounds(t *testing.T) {
	for _, blockSize := range []int{mhf.MinBlockSize, mhf.MaxBlockSize} {
		t.Run(fmt.Sprint(blockSize), func(t *testing.T) {
			got := mhf.Hash("test", 2, 1, blockSize, nil, nil, nil, 32)
			if got, want := len(got), 32; got != want {
				t.Fatalf("len(Hash()) = %d, want %d", got, want)
			}
		})
	}
}

func TestHashInvalidParameters(t *testing.T) {
	tests := map[string]struct {
		spaceCost, timeCost, blockSize, outputSize int
	}{
		"space cost":      {0, 1, 32, 32},
		"time cost":       {1, 0, 32, 32},
		"small block":     {1, 1, mhf.MinBlockSize - 1, 32},
		"large block":     {1, 1, mhf.MaxBlockSize + 1, 32},
		"output size":     {1, 1, 32, 0},
		"buffer overflow": {int(^uint(0) >> 1), 1, 32, 32},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			defer func() {
				if recover() == nil {
					t.Fatal("Hash() did not panic")
				}
			}()
			mhf.Hash("test", tt.spaceCost, tt.timeCost, tt.blockSize, nil, nil, nil, tt.outputSize)
		})
	}
}

func FuzzHash(f *testing.F) {
	f.Add("test.domain", uint8(4), uint8(2), uint8(32), []byte("salt"), []byte("password"), uint8(32))
	f.Add("", uint8(2), uint8(1), uint8(64), []byte(""), []byte(""), uint8(16))

	f.Fuzz(func(t *testing.T, domain string, space, rounds, blockBytes uint8, salt, password []byte, outputBytes uint8) {
		spaceCost := int(space%16) + 1
		timeCost := int(rounds%3) + 1
		blockSize := int(blockBytes)%(mhf.MaxBlockSize-mhf.MinBlockSize+1) + mhf.MinBlockSize
		outputSize := int(outputBytes%64) + 1

		hash := mhf.Hash(domain, spaceCost, timeCost, blockSize, salt, password, nil, outputSize)
		if got, want := len(hash), outputSize; got != want {
			t.Fatalf("len(Hash()) = %d, want %d", got, want)
		}

		hash2 := mhf.Hash(domain, spaceCost, timeCost, blockSize, salt, password, nil, outputSize)
		if !bytes.Equal(hash, hash2) {
			t.Fatal("Hash() is not deterministic")
		}
	})
}
