# cryptohelpers

Cryptographic utilities for Ed25519 signing and Curve25519 encryption in Go

[![CI](https://github.com/go-extras/cryptohelpers/actions/workflows/ci.yml/badge.svg?branch=master)](https://github.com/go-extras/cryptohelpers/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/go-extras/cryptohelpers.svg)](https://pkg.go.dev/github.com/go-extras/cryptohelpers)
[![Go Report Card](https://goreportcard.com/report/github.com/go-extras/cryptohelpers)](https://goreportcard.com/report/github.com/go-extras/cryptohelpers)
[![Go Version](https://img.shields.io/badge/go-%3E%3D1.25-00ADD8?logo=go)](https://go.dev/dl/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## Overview

`cryptohelpers` is a lightweight, focused library providing essential cryptographic operations for Go applications. It offers:

- **Ed25519 digital signatures** for authentication and integrity verification
- **Curve25519 encryption** (NaCl box) for secure data transmission
- **Key management utilities** for loading base64-encoded keys from files
- **Bundle operations** for combining payloads with signatures

The library is designed for developers who need reliable, easy-to-use cryptographic primitives without the complexity of managing low-level crypto APIs directly.

**Target audience:** Backend developers, security engineers, and application architects building secure systems that require message signing, verification, and encryption.

## Features

- ✅ **Ed25519 signing and verification** with deterministic signatures
- ✅ **NaCl box encryption/decryption** (Curve25519 + XSalsa20-Poly1305)
- ✅ **Key loading utilities** for Ed25519 and Curve25519 keys from base64-encoded files
- ✅ **Bundle operations** to combine and split payload+signature bundles
- ✅ **Zero dependencies** beyond Go standard library and `golang.org/x/crypto`
- ✅ **Well-tested** with comprehensive test coverage
- ✅ **Simple API** designed for ease of use and safety

## Requirements

- Go 1.25+ (tested on 1.25.x)

## Installation

Add the library to your Go module:

```bash
go get github.com/go-extras/cryptohelpers@latest
```

## Quick Start

### Signing and Verifying Messages

```go
package main

import (
    "crypto/ed25519"
    "crypto/rand"
    "fmt"
    
    "github.com/go-extras/cryptohelpers"
)

func main() {
    // Generate a key pair
    pub, priv, _ := ed25519.GenerateKey(rand.Reader)
    
    // Sign a message
    message := []byte("Hello, World!")
    signature := cryptohelpers.SignPayload(priv, message)
    
    // Verify the signature
    valid := cryptohelpers.VerifyPayload(pub, message, signature)
    fmt.Printf("Signature valid: %v\n", valid) // Output: Signature valid: true
}
```

### Encrypting and Decrypting Data

```go
package main

import (
    "crypto/rand"
    "fmt"
    
    "github.com/go-extras/cryptohelpers"
    "golang.org/x/crypto/nacl/box"
)

func main() {
    // Generate recipient key pair
    recipientPub, recipientPriv, _ := box.GenerateKey(rand.Reader)
    
    // Encrypt data
    data := []byte("Secret message")
    encrypted := cryptohelpers.EncryptBundle(data, recipientPub)
    
    // Decrypt data
    decrypted, err := cryptohelpers.DecryptBundle(encrypted, recipientPriv)
    if err != nil {
        panic(err)
    }
    
    fmt.Printf("Decrypted: %s\n", decrypted) // Output: Decrypted: Secret message
}
```

### Loading Keys from Files

```go
package main

import (
    "github.com/go-extras/cryptohelpers"
)

func main() {
    // Load Ed25519 keys
    privKey := cryptohelpers.LoadEd25519Private("path/to/ed25519_private.key")
    pubKey := cryptohelpers.LoadEd25519Public("path/to/ed25519_public.key")
    
    // Load Curve25519 keys
    encPrivKey := cryptohelpers.LoadCurve25519Private("path/to/curve25519_private.key")
    encPubKey := cryptohelpers.LoadCurve25519Public("path/to/curve25519_public.key")
    
    // Use the keys...
}
```

### Working with Bundles

```go
package main

import (
    "crypto/ed25519"
    "crypto/rand"
    "fmt"
    
    "github.com/go-extras/cryptohelpers"
)

func main() {
    pub, priv, _ := ed25519.GenerateKey(rand.Reader)
    
    // Create a signed bundle
    payload := []byte("Important data")
    signature := cryptohelpers.SignPayload(priv, payload)
    bundle := append(payload, signature...)
    
    // Split the bundle
    extractedPayload, extractedSignature, err := cryptohelpers.SplitBundle(bundle)
    if err != nil {
        panic(err)
    }
    
    // Verify the extracted signature
    valid := cryptohelpers.VerifyPayload(pub, extractedPayload, extractedSignature)
    fmt.Printf("Bundle signature valid: %v\n", valid) // Output: Bundle signature valid: true
}
```

## API Documentation

Full API documentation is available at [pkg.go.dev/github.com/go-extras/cryptohelpers](https://pkg.go.dev/github.com/go-extras/cryptohelpers).

### Core Functions

#### Signing Operations

- **`SignPayload(priv ed25519.PrivateKey, payload []byte) []byte`**  
  Creates an Ed25519 signature (64 bytes) for the provided payload.

- **`VerifyPayload(pub ed25519.PublicKey, payload, signature []byte) bool`**  
  Verifies an Ed25519 signature. Returns `true` if valid, `false` otherwise.

- **`SplitBundle(bundle []byte) (payload, signature []byte, err error)`**  
  Separates a payload+signature bundle into its components.

#### Encryption Operations

- **`EncryptBundle(bundle []byte, recipientPub *[32]byte) []byte`**  
  Encrypts data using NaCl box (Curve25519 + XSalsa20-Poly1305).  
  Output format: `[24 bytes nonce] | [32 bytes ephemeralPub] | [ciphertext]`

- **`DecryptBundle(blob []byte, recipientPriv *[32]byte) ([]byte, error)`**  
  Decrypts a blob produced by `EncryptBundle`.

#### Key Loading

- **`LoadEd25519Private(path string) ed25519.PrivateKey`**  
  Loads an Ed25519 private key from a base64-encoded file. Panics on failure.

- **`LoadEd25519Public(path string) ed25519.PublicKey`**  
  Loads an Ed25519 public key from a base64-encoded file. Panics on failure.

- **`LoadCurve25519Private(path string) *[32]byte`**  
  Loads a Curve25519 private key from a base64-encoded file. Panics on failure.

- **`LoadCurve25519Public(path string) *[32]byte`**  
  Loads a Curve25519 public key from a base64-encoded file. Panics on failure.

## Use Cases

- **Secure configuration management**: Sign and encrypt configuration files
- **API authentication**: Sign requests with Ed25519 for tamper-proof authentication
- **Encrypted data storage**: Encrypt sensitive data before storing
- **Secure messaging**: Sign and encrypt messages between services
- **Key distribution**: Load and manage cryptographic keys from files

## Security Considerations

- **Ed25519 signatures are deterministic**: The same message and key always produce the same signature
- **Key storage**: Store private keys securely with appropriate file permissions (e.g., `0600`)
- **Ephemeral keys**: `EncryptBundle` generates a new ephemeral key pair for each encryption
- **No key derivation**: This library does not provide password-based key derivation; use appropriate KDF functions if needed
- **Panic on key loading errors**: Key loading functions panic on failure; handle appropriately in production code

## Testing

Run the test suite:

```bash
# Run all tests
go test ./...

# Run tests with race detection
go test -race ./...

# Run tests with coverage
go test -cover ./...
```

## Contributing

Contributions are welcome! Please:

- Open issues for bugs, feature requests, or questions
- Submit pull requests with clear descriptions and tests
- Follow the existing code style and conventions
- Ensure all tests pass and maintain test coverage

## License

MIT © 2025 Denis Voytyuk — see [LICENSE](LICENSE) for details.

## Acknowledgments

This library builds upon:

- Go's standard `crypto/ed25519` package
- The `golang.org/x/crypto/nacl/box` package for NaCl box encryption

