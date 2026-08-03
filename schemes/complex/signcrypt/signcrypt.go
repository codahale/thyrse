// Package signcrypt implements an integrated signcryption scheme using ML-KEM-768, ML-DSA-44, and Thyrse.
package signcrypt

import (
	"crypto/mlkem"

	"filippo.io/mldsa"
	"github.com/codahale/thyrse"
)

const (
	commitmentSize = 32

	// Overhead is the length, in bytes, of the additional data added to a plaintext to produce a signcrypted ciphertext.
	Overhead = mlkem.CiphertextSize768 + mldsa.MLDSA44SignatureSize
)

// Seal encrypts and signs the message to protect its confidentiality and authenticity. Only the owner of the
// receiver's private key can decrypt it, and only the owner of the sender's private key could have sent it.
//
// Panics if sender is not an ML-DSA-44 key or signing fails.
func Seal(
	domain string,
	sender *mldsa.PrivateKey,
	receiver *mlkem.EncapsulationKey768,
	message []byte,
) []byte {
	if sender.PublicKey().Parameters() != mldsa.MLDSA44() {
		panic("signcrypt: sender is not an ML-DSA-44 key")
	}

	sharedSecret, kemCiphertext := receiver.Encapsulate()
	p := newProtocol(domain, receiver, sender.PublicKey(), kemCiphertext, sharedSecret)

	ciphertext := p.Mask("message", kemCiphertext, message)
	commitment := p.Derive("commitment", nil, commitmentSize)
	signature, err := sender.Sign(nil, commitment, nil)
	if err != nil {
		panic(err)
	}

	ciphertext = p.Mask("signature", ciphertext, signature)
	return ciphertext
}

// Open decrypts and verifies a ciphertext produced by Seal. Returns either the confidential, authentic plaintext or
// thyrse.ErrInvalidCiphertext.
func Open(
	domain string,
	receiver *mlkem.DecapsulationKey768,
	sender *mldsa.PublicKey,
	ciphertext []byte,
) ([]byte, error) {
	if len(ciphertext) < Overhead || sender.Parameters() != mldsa.MLDSA44() {
		return nil, thyrse.ErrInvalidCiphertext
	}

	kemCiphertext := ciphertext[:mlkem.CiphertextSize768]
	sharedSecret, err := receiver.Decapsulate(kemCiphertext)
	if err != nil {
		return nil, thyrse.ErrInvalidCiphertext
	}

	p := newProtocol(domain, receiver.EncapsulationKey(), sender, kemCiphertext, sharedSecret)

	signatureOffset := len(ciphertext) - mldsa.MLDSA44SignatureSize
	plaintext := p.Unmask("message", nil, ciphertext[mlkem.CiphertextSize768:signatureOffset])
	commitment := p.Derive("commitment", nil, commitmentSize)
	signature := p.Unmask("signature", nil, ciphertext[signatureOffset:])
	err = mldsa.Verify(sender, commitment, signature, nil)
	if err != nil {
		return nil, thyrse.ErrInvalidCiphertext
	}

	return plaintext, nil
}

func newProtocol(
	domain string,
	receiver *mlkem.EncapsulationKey768,
	sender *mldsa.PublicKey,
	kemCiphertext, sharedSecret []byte,
) *thyrse.Protocol {
	p := thyrse.New(domain)
	p.Mix("receiver ml-kem", receiver.Bytes())
	p.Mix("sender ml-dsa", sender.Bytes())
	p.Mix("ml-kem ciphertext", kemCiphertext)
	p.Mix("ml-kem shared secret", sharedSecret)
	return p
}
