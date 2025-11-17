package cryptohelpers

import (
	"crypto/rand"
	"errors"

	"golang.org/x/crypto/nacl/box"
)

// EncryptBundle encrypts a signed bundle using NaCl box (Curve25519 + XSalsa20-Poly1305).
//
// The function automatically generates a new ephemeral key pair and a 24-byte nonce.
// The output format is:
//
//	[24 bytes nonce] | [32 bytes ephemeralPub] | [ciphertext]
//
// The function returns the encrypted blob or panics on failure.
func EncryptBundle(bundle []byte, recipientPub *[32]byte) []byte {
	ephemeralPub, ephemeralPriv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}

	var nonce [24]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		panic(err)
	}

	ciphertext := box.Seal(ephemeralPub[:], bundle, &nonce, recipientPub, ephemeralPriv)

	// Append nonce before ciphertext for easy parsing.
	output := append(nonce[:], ciphertext...)
	return output
}

// DecryptBundle decrypts a blob produced by EncryptBundle.
//
// The blob must contain:
//   - 24 bytes: nonce
//   - 32 bytes: ephemeral sender public key
//   - remaining bytes: ciphertext
//
// The function returns the decrypted plaintext or an error on failure.
func DecryptBundle(blob []byte, recipientPriv *[32]byte) ([]byte, error) {
	if len(blob) < 24+32 {
		return nil, errors.New("encrypted blob too small")
	}

	var nonce [24]byte
	var ephemeralPub [32]byte

	copy(nonce[:], blob[:24])
	copy(ephemeralPub[:], blob[24:56])

	ciphertext := blob[56:]

	plaintext, ok := box.Open(nil, ciphertext, &nonce, &ephemeralPub, recipientPriv)
	if !ok {
		return nil, errors.New("decryption failed")
	}
	return plaintext, nil
}
