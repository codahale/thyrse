package aead_test

import (
	"fmt"

	"github.com/codahale/thyrse/schemes/basic/aead"
)

func Example() {
	key := []byte("a very secret key, 32 bytes long")
	nonce := []byte("a 16-byte nonce!")
	ad := []byte("some additional data")
	plaintext := []byte("hello world")

	// Create a new AEAD instance with a 16-byte nonce.
	c := aead.New("com.example.aead", key, 16)

	// Seal the plaintext.
	ciphertext := c.Seal(nil, nonce, plaintext, ad)
	fmt.Printf("ciphertext = %x\n", ciphertext)

	// Open the ciphertext.
	decrypted, err := c.Open(nil, nonce, ciphertext, ad)
	if err != nil {
		panic(err)
	}
	fmt.Printf("plaintext  = %s\n", decrypted)

	// Output:
	// ciphertext = 09483fd090081b2be673e0f6e7d3ba8e3cdedada5717d2d883a7adea18716832744548a2c78faeadcf90f8
	// plaintext  = hello world
}
