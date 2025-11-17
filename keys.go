// Package cryptohelpers provides utilities for loading and handling cryptographic keys
// used for Ed25519 signing and Curve25519 encryption in the ppatcher system.
package cryptohelpers

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"os"
)

// LoadEd25519Private loads an Ed25519 private key from a base64-encoded file.
//
// The file must contain exactly one base64 string representing a 64-byte Ed25519 private key.
// The function returns an ed25519.PrivateKey or panics on any failure.
func LoadEd25519Private(path string) ed25519.PrivateKey {
	data, err := os.ReadFile(path)
	if err != nil {
		panic(err)
	}
	raw, err := base64.StdEncoding.DecodeString(string(data))
	if err != nil {
		panic(err)
	}
	return ed25519.PrivateKey(raw)
}

// LoadEd25519Public loads an Ed25519 public key from a base64-encoded file.
//
// The file must contain exactly one base64 string representing a 32-byte Ed25519 public key.
// The function returns an ed25519.PublicKey or panics on any failure.
func LoadEd25519Public(path string) ed25519.PublicKey {
	data, err := os.ReadFile(path)
	if err != nil {
		panic(err)
	}
	raw, err := base64.StdEncoding.DecodeString(string(data))
	if err != nil {
		panic(err)
	}
	return ed25519.PublicKey(raw)
}

// LoadCurve25519Private loads a Curve25519 (X25519) private key from a base64-encoded file.
//
// The resulting key must be exactly 32 bytes long. The function returns a pointer to an array
// suitable for use with nacl/box operations, or panics if the key is invalid or cannot be loaded.
func LoadCurve25519Private(path string) *[32]byte {
	data, err := os.ReadFile(path)
	if err != nil {
		panic(err)
	}
	raw, err := base64.StdEncoding.DecodeString(string(data))
	if err != nil {
		panic(err)
	}
	if len(raw) != 32 {
		panic(errors.New("invalid Curve25519 private key length"))
	}
	var out [32]byte
	copy(out[:], raw)
	return &out
}

// LoadCurve25519Public loads a Curve25519 (X25519) public key from a base64-encoded file.
//
// The resulting key must be exactly 32 bytes long. The function returns a pointer to an array
// suitable for nacl/box encryption, or panics if the key is invalid or cannot be loaded.
func LoadCurve25519Public(path string) *[32]byte {
	data, err := os.ReadFile(path)
	if err != nil {
		panic(err)
	}
	raw, err := base64.StdEncoding.DecodeString(string(data))
	if err != nil {
		panic(err)
	}
	if len(raw) != 32 {
		panic(errors.New("invalid Curve25519 public key length"))
	}
	var out [32]byte
	copy(out[:], raw)
	return &out
}
