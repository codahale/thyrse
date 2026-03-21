package tw128

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/codahale/thyrse/internal/testdata"
)

func testKey() []byte {
	key := make([]byte, KeySize)
	for i := range key {
		key[i] = byte(i)
	}
	return key
}

func testNonce() []byte {
	nonce := make([]byte, NonceSize)
	for i := range nonce {
		nonce[i] = byte(i)
	}
	return nonce
}

func seq(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i % 256)
	}
	return b
}

func pattern(length int, start byte) []byte {
	b := make([]byte, length)
	for i := range b {
		b[i] = start + byte(i)
	}
	return b
}

// encrypt is a convenience helper for tests: single-call encrypt via streaming API.
func encrypt(key, nonce, ad, pt []byte) ([]byte, [TagSize]byte) {
	ct := make([]byte, len(pt))
	e := NewEncryptor(key, nonce, ad)
	e.XORKeyStream(ct, pt)
	return ct, e.Finalize()
}

// decrypt is a convenience helper for tests: single-call decrypt via streaming API.
func decrypt(key, nonce, ad, ct []byte) ([]byte, [TagSize]byte) {
	pt := make([]byte, len(ct))
	d := NewDecryptor(key, nonce, ad)
	d.XORKeyStream(pt, ct)
	return pt, d.Finalize()
}

type vector struct {
	name          string
	keyHex        string
	nonceHex      string
	adHex         string
	ptLen         int
	ptStart       byte
	ctTagHex      string // full ct||tag if short enough
	ctPrefix32Hex string // first 32 bytes if long
	tagHex        string
}

var vectors = []vector{
	{
		name: "empty", keyHex: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
		nonceHex: "101112131415161718191a1b1c1d1e1f", adHex: "", ptLen: 0, ptStart: 0x00,
		ctTagHex: "95c08d34f5589310605e7b81ad7c7bd6be4f9c6a8772d39c760163e5dbd47345",
		tagHex:   "95c08d34f5589310605e7b81ad7c7bd6be4f9c6a8772d39c760163e5dbd47345",
	},
	{
		name: "short_ad_short_pt", keyHex: "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f",
		nonceHex: "303132333435363738393a3b3c3d3e3f", adHex: "40414243444546", ptLen: 15, ptStart: 0x50,
		ctTagHex: "700bdff95b7af4d9d413eb1cce5f9b92a4c3e6ce77b1d68031a06113a286dfd5c2a24c3aa083635db08f73b420b9c6",
		tagHex:   "92a4c3e6ce77b1d68031a06113a286dfd5c2a24c3aa083635db08f73b420b9c6",
	},
	{
		name: "rate_minus_1", keyHex: "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f",
		nonceHex: "707172737475767778797a7b7c7d7e7f", adHex: "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0", ptLen: 167, ptStart: 0x90,
		ctPrefix32Hex: "8a7f4b7897fda18eae32f97b692199506e8e7f03edecc70a8b2ae342b16bcbf4",
		tagHex:        "8a65226e6082a2e3deaf9860dbea6ec6a6b226078965af4f48c8b14537392082",
	},
	{
		name: "rate_exact", keyHex: "a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf",
		nonceHex: "b0b1b2b3b4b5b6b7b8b9babbbcbdbebf", adHex: "c0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1", ptLen: 168, ptStart: 0xD0,
		ctPrefix32Hex: "d227adcbc1d8fab6f21564d1fdaada9dfd50ae7ad16e1642a6cbcc183b57ca31",
		tagHex:        "1c21fe9547e183981dc7fba1138afa3783125ff3caed32c3288f42ae6cd16dbd",
	},
	{
		name: "rate_plus_1", keyHex: "e0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
		nonceHex: "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff", adHex: "1112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f30313233", ptLen: 169, ptStart: 0x22,
		ctPrefix32Hex: "d7e48784c1c086f950d77ac16f509c838f1bdb830b8983d30755e0dd9a6b78ee",
		tagHex:        "f256c9e77a89d15211c0775673b5e3ce831cbb2cd5dcae90626e7786dceea5bf",
	},
	{
		name: "two_rate_blocks", keyHex: "333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152",
		nonceHex: "55565758595a5b5c5d5e5f6061626364", adHex: "7778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6", ptLen: 336, ptStart: 0x99,
		ctPrefix32Hex: "666c94514523a371b09416b3c1bd245a21c4634224f64102fecf14744ff1be2d",
		tagHex:        "395eeaada5fadd558f7aa75fedc7e81d95830cc5da1770015afc8b311cb0f58a",
	},
	{
		name: "chunk_minus_1", keyHex: "12131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f3031",
		nonceHex: "232425262728292a2b2c2d2e2f303132", adHex: "3435363738393a3b3c3d3e3f404142434445464748494a", ptLen: ChunkSize - 1, ptStart: 0x45,
		ctPrefix32Hex: "a7a80b98bcf2de881b3790b1ee8faec2e8bfe64eb8019e104aeba948e71016dc",
		tagHex:        "470a7d135b14aee07aeea4c0fe5439253e8fbe4cd11b255581e636329bbb07c8",
	},
	{
		name: "chunk_exact", keyHex: "565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475",
		nonceHex: "6768696a6b6c6d6e6f70717273747576", adHex: "78797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f", ptLen: ChunkSize, ptStart: 0x89,
		ctPrefix32Hex: "a6ab031c7743458600486fdc91ba5a861f7e51fae09e77fc34175b7092810990",
		tagHex:        "51581f19b7108bf6cdc7fb380694575874b23b8a86615d04d97824f5569f9748",
	},
	{
		name: "chunk_plus_1", keyHex: "9a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9",
		nonceHex: "abacadaeafb0b1b2b3b4b5b6b7b8b9ba", adHex: "bcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4", ptLen: ChunkSize + 1, ptStart: 0xCD,
		ctPrefix32Hex: "42f168dd16946abaab76a6029b26188941fee1ec9ced461bd60ad1a39cae460a",
		tagHex:        "0d87c57795916997b8e00440e6480404efe60d4f3c0ad262fdc1891e55b539bd",
	},
	{
		name: "two_chunks_exact", keyHex: "2122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40",
		nonceHex: "434445464748494a4b4c4d4e4f505152", adHex: "65666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e", ptLen: ChunkSize * 2, ptStart: 0x87,
		ctPrefix32Hex: "66da66b1f25f9efdbcf0e86c061f4971f8cb18fe7e78681122a9d557747ccff4",
		tagHex:        "9dd20ddb99d830f90bcccc2c358f10efad4f81793d1b22b67b6d35fefacb4c3c",
	},
	{
		name: "two_chunks_plus_1", keyHex: "a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0",
		nonceHex: "c3c4c5c6c7c8c9cacbcccdcecfd0d1d2", adHex: "e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff", ptLen: ChunkSize*2 + 1, ptStart: 0x07,
		ctPrefix32Hex: "2d9a2024d6ea1bb1c472c08d865873c26bf033a177666469d52a36c21da039e8",
		tagHex:        "4de9f871cdfcab9eb6e9e8ea0a0ad2b70b742ce8c1647d2aa354282695592d83",
	},
}

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

func TestVectors(t *testing.T) {
	for _, v := range vectors {
		t.Run(v.name, func(t *testing.T) {
			key := mustHex(v.keyHex)
			nonce := mustHex(v.nonceHex)
			ad := mustHex(v.adHex)
			pt := pattern(v.ptLen, v.ptStart)

			ct, tag := encrypt(key, nonce, ad, pt)

			// Check tag.
			expectedTag := mustHex(v.tagHex)
			if !bytes.Equal(tag[:], expectedTag) {
				t.Fatalf("tag mismatch:\n  got  %x\n  want %x", tag[:], expectedTag)
			}

			// Check ct prefix or full ct||tag.
			if v.ctTagHex != "" {
				expectedCTTag := mustHex(v.ctTagHex)
				gotCTTag := append(ct, tag[:]...)
				if !bytes.Equal(gotCTTag, expectedCTTag) {
					t.Fatalf("ct||tag mismatch:\n  got  %x\n  want %x", gotCTTag, expectedCTTag)
				}
			}
			if v.ctPrefix32Hex != "" {
				expectedPrefix := mustHex(v.ctPrefix32Hex)
				if !bytes.Equal(ct[:32], expectedPrefix) {
					t.Fatalf("ct prefix mismatch:\n  got  %x\n  want %x", ct[:32], expectedPrefix)
				}
			}

			// Round-trip: decrypt and verify.
			pt2, tag2 := decrypt(key, nonce, ad, ct)
			if !bytes.Equal(pt2, pt) {
				t.Fatal("round-trip plaintext mismatch")
			}
			if subtle.ConstantTimeCompare(tag[:], tag2[:]) != 1 {
				t.Fatal("round-trip tag mismatch")
			}
		})
	}
}

func TestRoundTrip(t *testing.T) {
	key := testKey()
	nonce := testNonce()

	sizes := []struct {
		name string
		size int
	}{
		{"empty", 0},
		{"1 byte", 1},
		{"167 bytes", 167},
		{"168 bytes (1 rate block)", 168},
		{"169 bytes", 169},
		{"335 bytes", 335},
		{"336 bytes (2 rate blocks)", 336},
		{fmt.Sprintf("%d bytes (chunk-1)", ChunkSize-1), ChunkSize - 1},
		{fmt.Sprintf("%d bytes (1 chunk)", ChunkSize), ChunkSize},
		{fmt.Sprintf("%d bytes", ChunkSize+1), ChunkSize + 1},
		{fmt.Sprintf("%d bytes (2 chunks)", ChunkSize*2), ChunkSize * 2},
		{fmt.Sprintf("%d bytes", ChunkSize*2+1), ChunkSize*2 + 1},
		{fmt.Sprintf("%d bytes (3 chunks)", ChunkSize*3), ChunkSize * 3},
		{fmt.Sprintf("%d bytes", ChunkSize*3+999), ChunkSize*3 + 999},
	}

	for _, sz := range sizes {
		t.Run(sz.name, func(t *testing.T) {
			pt := seq(sz.size)
			ad := seq(sz.size % 41)

			ct, tag := encrypt(key, nonce, ad, pt)

			if len(ct) != len(pt) {
				t.Fatalf("ciphertext length: got %d, want %d", len(ct), len(pt))
			}

			pt2, tag2 := decrypt(key, nonce, ad, ct)
			if !bytes.Equal(pt2, pt) {
				t.Fatalf("plaintext mismatch at size %d", sz.size)
			}
			if subtle.ConstantTimeCompare(tag[:], tag2[:]) != 1 {
				t.Fatalf("tag mismatch at size %d", sz.size)
			}
		})
	}
}

func TestInPlace(t *testing.T) {
	key := testKey()
	nonce := testNonce()

	for _, size := range []int{0, 1, 168, ChunkSize, ChunkSize + 1, ChunkSize * 2} {
		pt := seq(size)
		buf := make([]byte, size)
		copy(buf, pt)

		e := NewEncryptor(key, nonce, nil)
		e.XORKeyStream(buf, buf) // in-place
		tag := e.Finalize()

		d := NewDecryptor(key, nonce, nil)
		d.XORKeyStream(buf, buf) // in-place
		tag2 := d.Finalize()

		if !bytes.Equal(buf, pt) {
			t.Fatalf("in-place round-trip failed at size %d", size)
		}
		if subtle.ConstantTimeCompare(tag[:], tag2[:]) != 1 {
			t.Fatalf("in-place tag mismatch at size %d", size)
		}
	}
}

func TestIncrementalWrite(t *testing.T) {
	key := testKey()
	nonce := testNonce()
	ad := []byte("test ad")
	pt := seq(ChunkSize*2 + 500)

	// Single-call reference.
	refCT, refTag := encrypt(key, nonce, ad, pt)

	// Multi-call with various write sizes.
	for _, writeSize := range []int{1, 7, 100, 168, 169, ChunkSize - 1, ChunkSize, ChunkSize + 1} {
		t.Run(fmt.Sprintf("%d", writeSize), func(t *testing.T) {
			ct := make([]byte, len(pt))
			e := NewEncryptor(key, nonce, ad)
			off := 0
			for off < len(pt) {
				n := min(writeSize, len(pt)-off)
				e.XORKeyStream(ct[off:off+n], pt[off:off+n])
				off += n
			}
			tag := e.Finalize()

			if !bytes.Equal(ct, refCT) {
				t.Fatalf("incremental ct mismatch (writeSize=%d)", writeSize)
			}
			if tag != refTag {
				t.Fatalf("incremental tag mismatch (writeSize=%d)", writeSize)
			}
		})
	}
}

func TestWrongAD(t *testing.T) {
	key := testKey()
	nonce := testNonce()
	pt := []byte("hello")
	ad := []byte("correct")

	ct, tag := encrypt(key, nonce, ad, pt)

	_, tag2 := decrypt(key, nonce, []byte("wrong"), ct)
	if subtle.ConstantTimeCompare(tag[:], tag2[:]) == 1 {
		t.Fatal("wrong AD should produce different tag")
	}
}

func TestTamperedCiphertext(t *testing.T) {
	key := testKey()
	nonce := testNonce()
	pt := seq(1000)

	ct, tag := encrypt(key, nonce, nil, pt)
	tampered := make([]byte, len(ct))
	copy(tampered, ct)
	tampered[0] ^= 1

	_, tag2 := decrypt(key, nonce, nil, tampered)
	if subtle.ConstantTimeCompare(tag[:], tag2[:]) == 1 {
		t.Fatal("tampered ciphertext should produce different tag")
	}
}

func TestNilNonce(t *testing.T) {
	key := testKey()
	pt := seq(14)

	// nil nonce should behave the same as all-zero nonce.
	ct1, tag1 := encrypt(key, nil, nil, pt)
	ct2, tag2 := encrypt(key, make([]byte, NonceSize), nil, pt)

	if !bytes.Equal(ct1, ct2) {
		t.Fatal("nil nonce and zero nonce should produce same ciphertext")
	}
	if tag1 != tag2 {
		t.Fatal("nil nonce and zero nonce should produce same tag")
	}

}

func BenchmarkEncrypt(b *testing.B) {
	key := testKey()
	nonce := testNonce()

	for _, size := range []int{64, 1024, ChunkSize, ChunkSize * 8} {
		b.Run(fmt.Sprintf("%dB", size), func(b *testing.B) {
			pt := make([]byte, size)
			ct := make([]byte, size)
			b.SetBytes(int64(size))
			b.ResetTimer()
			for range b.N {
				e := NewEncryptor(key, nonce, nil)
				e.XORKeyStream(ct, pt)
				e.Finalize()
			}
		})
	}
}

func BenchmarkEncryptor(b *testing.B) {
	key := testKey()
	for _, size := range testdata.Sizes {
		pt := make([]byte, size.N)
		output := make([]byte, size.N)
		b.Run(size.Name, func(b *testing.B) {
			b.SetBytes(int64(size.N))
			b.ReportAllocs()
			for b.Loop() {
				e := NewEncryptor(key, nil, nil)
				e.XORKeyStream(output, pt)
				e.Finalize()
			}
		})
	}
}

func BenchmarkAESGCM(b *testing.B) {
	key := testKey()
	for _, size := range testdata.Sizes {
		nonce := make([]byte, 12)
		pt := make([]byte, size.N)
		output := make([]byte, size.N+16)
		b.Run(size.Name, func(b *testing.B) {
			b.SetBytes(int64(size.N))
			b.ReportAllocs()
			for b.Loop() {
				block, _ := aes.NewCipher(key[:])
				gcm, _ := cipher.NewGCM(block)
				gcm.Seal(output[:0], nonce, pt, nil)
			}
		})
	}
}

func BenchmarkDecryptor(b *testing.B) {
	key := testKey()
	for _, size := range testdata.Sizes {
		pt := make([]byte, size.N)
		ct, _ := encrypt(key, nil, nil, pt)
		output := make([]byte, size.N)
		b.Run(size.Name, func(b *testing.B) {
			b.SetBytes(int64(size.N))
			b.ReportAllocs()
			for b.Loop() {
				d := NewDecryptor(key, nil, nil)
				d.XORKeyStream(output, ct)
				d.Finalize()
			}
		})
	}
}
