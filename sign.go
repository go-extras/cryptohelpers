package cryptohelpers

import (
	"crypto/ed25519"
	"errors"
)

// SignPayload creates an Ed25519 signature for the provided payload.
//
// The function returns a 64-byte signature. It panics if the private key is invalid.
// No hashing is required because Ed25519 operates on the message directly.
func SignPayload(priv ed25519.PrivateKey, payload []byte) []byte {
	return ed25519.Sign(priv, payload)
}

// VerifyPayload checks whether the given Ed25519 signature is valid for a payload.
//
// It returns true for a valid signature and false otherwise. The function does not panic.
// This method is intended for validating the authenticity of decrypted configuration data.
func VerifyPayload(pub ed25519.PublicKey, payload, signature []byte) bool {
	if len(signature) != ed25519.SignatureSize {
		return false
	}
	return ed25519.Verify(pub, payload, signature)
}

// SplitBundle separates a payload+signature bundle into its components.
//
// The bundle must contain at least one Ed25519 signature (64 bytes) appended to the payload.
// The function returns payload, signature, or an error if the bundle is malformed.
func SplitBundle(bundle []byte) (payload, signature []byte, err error) {
	if len(bundle) < ed25519.SignatureSize {
		return nil, nil, errors.New("bundle too small to contain signature")
	}

	payload = bundle[:len(bundle)-ed25519.SignatureSize]
	signature = bundle[len(bundle)-ed25519.SignatureSize:]
	return payload, signature, nil
}
