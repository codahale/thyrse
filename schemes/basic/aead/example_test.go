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
	// ciphertext = 9af1348178477e04f5f13527e28a46c03316cc327c088691d31349844d65ef7be72ab6d76da89753b8b37e
	// plaintext  = hello world
}
