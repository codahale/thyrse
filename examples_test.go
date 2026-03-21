package thyrse_test

import (
	"crypto/ecdh"
	"encoding/hex"
	"fmt"

	"github.com/codahale/thyrse"
)

func Example() {
	protocol := thyrse.New("com.example.kat")
	protocol.Mix("first", []byte("one"))
	protocol.Mix("second", []byte("two"))

	third := protocol.Derive("third", nil, 8)
	fmt.Printf("Derive('third', 8) = %x\n", third)

	plaintext := []byte("this is an example")
	ciphertext := protocol.Mask("fourth", nil, plaintext)
	fmt.Printf("Mask('fourth', '%s') = %x\n", plaintext, ciphertext)

	ciphertext = protocol.Seal("fifth", nil, []byte("this is an example"))
	fmt.Printf("Seal('fifth', '%s') = %x\n", plaintext, ciphertext)

	protocol.Ratchet("sixth")

	sixth := protocol.Derive("seventh", nil, 8)
	fmt.Printf("Derive('seventh', 8) = %x\n", sixth)

	// Output:
	// Derive('third', 8) = e9af288f79a69df3
	// Mask('fourth', 'this is an example') = 2d31bdcc6edd9241983aa0823ee147fd9afb
	// Seal('fifth', 'this is an example') = eb77f8247978608e5fa7bd862cb769ab4bc00935f3e129d8ce06d6d3aa065e5d2eafa5931adff73e5d2b3185bb95a4cc3e7a
	// Derive('seventh', 8) = 33b887899926c00f
}

func ExampleProtocol_mac() {
	mac := func(key, message []byte) []byte {
		// Initialize a protocol with a domain string.
		mac := thyrse.New("com.example.mac")

		// Mix the key into the protocol.
		mac.Mix("key", key)

		// Mix the message into the protocol.
		mac.Mix("message", message)

		// Derive 16 bytes of output.
		// Note: The output length is encoded into the derivation, so changing the length will change the output.
		tag := mac.Derive("tag", nil, 16)

		return tag
	}

	key := []byte("my-secret-key")
	message := []byte("hello world")
	tag := mac(key, message)
	fmt.Printf("tag = %x\n", tag)

	// Output:
	// tag = 6a8aae111bf9cb08238be181ec73fbf9
}

func ExampleProtocol_stream() {
	encrypt := func(key, nonce, plaintext []byte) []byte {
		// Initialize a protocol with a domain string.
		stream := thyrse.New("com.example.stream")

		// Mix the key and nonce into the protocol.
		stream.Mix("key", key)
		stream.Mix("nonce", nonce)

		// Encrypt the plaintext without any authenticity.
		return stream.Mask("message", nil, plaintext)
	}

	decrypt := func(key, nonce, ciphertext []byte) []byte {
		// Initialize a protocol with a domain string.
		stream := thyrse.New("com.example.stream")

		// Mix the key and nonce into the protocol.
		stream.Mix("key", key)
		stream.Mix("nonce", nonce)

		// Decrypt the ciphertext.
		return stream.Unmask("message", nil, ciphertext)
	}

	key := []byte("my-secret-key")
	nonce := []byte("actually random")
	plaintext := []byte("hello world")

	ciphertext := encrypt(key, nonce, plaintext)
	fmt.Printf("ciphertext = %x\n", ciphertext)

	plaintext = decrypt(key, nonce, ciphertext)
	fmt.Printf("plaintext  = %s\n", plaintext)

	// Output:
	// ciphertext = 1b71afc466b2fbba28a96e
	// plaintext  = hello world
}

func ExampleProtocol_aead() {
	encrypt := func(key, nonce, ad, plaintext []byte) []byte {
		// Initialize a protocol with a domain string.
		aead := thyrse.New("com.example.aead")

		// Mix the key and nonce into the protocol.
		aead.Mix("key", key)
		aead.Mix("nonce", nonce)

		// Mix the authenticated data into the protocol.
		aead.Mix("ad", ad)

		// Seal the plaintext.
		return aead.Seal("message", nil, plaintext)
	}

	decrypt := func(key, nonce, ad, ciphertext []byte) ([]byte, error) {
		// Initialize a protocol with a domain string.
		aead := thyrse.New("com.example.aead")

		// Mix the key and nonce into the protocol.
		aead.Mix("key", key)
		aead.Mix("nonce", nonce)

		// Mix the authenticated data into the protocol.
		aead.Mix("ad", ad)

		// Open the ciphertext.
		return aead.Open("message", nil, ciphertext)
	}

	key := []byte("my-secret-key")
	nonce := []byte("actually random")
	ad := []byte("some authenticated data")
	plaintext := []byte("hello world")

	ciphertext := encrypt(key, nonce, ad, plaintext)
	fmt.Printf("ciphertext = %x\n", ciphertext)

	plaintext, err := decrypt(key, nonce, ad, ciphertext)
	if err != nil {
		panic(err)
	}
	fmt.Printf("plaintext  = %s\n", plaintext)

	// Output:
	// ciphertext = 196b81b2a6f611503a1c2efdfc53247ce8a02ef3decd26be324467a3bba7d1aab8cce56c6c5844bff7d921
	// plaintext  = hello world
}

func ExampleProtocol_hpke() {
	encrypt := func(receiver *ecdh.PublicKey, plaintext []byte) []byte {
		// This should be randomly generated, but it would make the test always fail.
		ephemeralPrivBuf, _ := hex.DecodeString("a0b9a9ea71d45df9a8c7cf7da798c4394342993b21f24c7bb3612e573e8a58df")
		ephemeral, _ := ecdh.X25519().NewPrivateKey(ephemeralPrivBuf)

		// Initialize a protocol with a domain string.
		hpke := thyrse.New("com.example.hpke")

		// Mix the receiver's public key and the ephemeral public key into the protocol.
		hpke.Mix("receiver", receiver.Bytes())
		hpke.Mix("ephemeral", ephemeral.PublicKey().Bytes())

		// Mix the ECDH shared secret into the protocol.
		ss, err := ephemeral.ECDH(receiver)
		if err != nil {
			panic(err)
		}
		hpke.Mix("ecdh", ss)

		// Seal the plaintext and append it to the ephemeral public key.
		return hpke.Seal("message", ephemeral.PublicKey().Bytes(), plaintext)
	}

	decrypt := func(receiver *ecdh.PrivateKey, ciphertext []byte) ([]byte, error) {
		ephemeral, err := ecdh.X25519().NewPublicKey(ciphertext[:32])
		if err != nil {
			panic(err)
		}

		hpke := thyrse.New("com.example.hpke")
		hpke.Mix("receiver", receiver.PublicKey().Bytes())
		hpke.Mix("ephemeral", ephemeral.Bytes())
		ss, err := receiver.ECDH(ephemeral)
		if err != nil {
			panic(err)
		}
		hpke.Mix("ecdh", ss)
		return hpke.Open("message", nil, ciphertext[32:])
	}

	receiverPrivBuf, _ := hex.DecodeString("c3a9b89b9a9a15da3c7a7e8ce9c96a828744abf52c0239f4180b0948fa3b1c74")
	receiver, _ := ecdh.X25519().NewPrivateKey(receiverPrivBuf)

	message := []byte("hello world")
	ciphertext := encrypt(receiver.PublicKey(), message)
	fmt.Printf("ciphertext = %x\n", ciphertext)

	plaintext, err := decrypt(receiver, ciphertext)
	if err != nil {
		panic(err)
	}
	fmt.Printf("plaintext  = %s\n", plaintext)

	// Output:
	// ciphertext = 672e904ba78b50b56f896d4b9c2f8018aecfd34038523a6faa4e82e37be4281f9027ff4a302ec34e467273773f52597ffc7384becf557a3fe32466c85a3762a6296199d6e5bf71cfd5c575
	// plaintext  = hello world
}
