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
	// ciphertext = c8a79b0f77d3fe3eb397f3b4e18d40c8cd77835c6fade594bdbf2e10d9094c3a21e8c8d4eaa10fdd3c4f04
	// plaintext  = hello world
}
