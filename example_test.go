package cryptohelpers_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"

	"github.com/go-extras/cryptohelpers"
	"golang.org/x/crypto/nacl/box"
)

// ExampleSignPayload demonstrates how to sign a message using Ed25519.
func ExampleSignPayload() {
	// Generate a key pair
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}

	// Sign a message
	message := []byte("Hello, World!")
	signature := cryptohelpers.SignPayload(priv, message)

	// Verify the signature
	valid := cryptohelpers.VerifyPayload(pub, message, signature)
	fmt.Printf("Signature valid: %v\n", valid)
	fmt.Printf("Signature length: %d bytes\n", len(signature))

	// Output:
	// Signature valid: true
	// Signature length: 64 bytes
}

// ExampleVerifyPayload demonstrates how to verify an Ed25519 signature.
func ExampleVerifyPayload() {
	// Generate a key pair
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}

	message := []byte("Important message")
	signature := cryptohelpers.SignPayload(priv, message)

	// Verify with correct data
	valid := cryptohelpers.VerifyPayload(pub, message, signature)
	fmt.Printf("Valid signature: %v\n", valid)

	// Verify with tampered data
	tamperedMessage := []byte("Tampered message")
	valid = cryptohelpers.VerifyPayload(pub, tamperedMessage, signature)
	fmt.Printf("Tampered message valid: %v\n", valid)

	// Output:
	// Valid signature: true
	// Tampered message valid: false
}

// ExampleSplitBundle demonstrates how to split a payload+signature bundle.
func ExampleSplitBundle() {
	// Generate a key pair
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}

	// Create a signed bundle
	payload := []byte("Important data")
	signature := cryptohelpers.SignPayload(priv, payload)
	bundle := append(payload, signature...)

	fmt.Printf("Bundle size: %d bytes\n", len(bundle))

	// Split the bundle
	extractedPayload, extractedSignature, err := cryptohelpers.SplitBundle(bundle)
	if err != nil {
		panic(err)
	}

	fmt.Printf("Payload: %s\n", extractedPayload)
	fmt.Printf("Signature length: %d bytes\n", len(extractedSignature))

	// Verify the extracted signature
	valid := cryptohelpers.VerifyPayload(pub, extractedPayload, extractedSignature)
	fmt.Printf("Signature valid: %v\n", valid)

	// Output:
	// Bundle size: 78 bytes
	// Payload: Important data
	// Signature length: 64 bytes
	// Signature valid: true
}

// ExampleEncryptBundle demonstrates how to encrypt data using NaCl box.
func ExampleEncryptBundle() {
	// Generate recipient key pair
	recipientPub, recipientPriv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}

	// Encrypt data
	data := []byte("Secret message")
	encrypted := cryptohelpers.EncryptBundle(data, recipientPub)

	fmt.Printf("Original data: %s\n", data)
	fmt.Printf("Encrypted size: %d bytes\n", len(encrypted))

	// Decrypt data
	decrypted, err := cryptohelpers.DecryptBundle(encrypted, recipientPriv)
	if err != nil {
		panic(err)
	}

	fmt.Printf("Decrypted data: %s\n", decrypted)

	// Output:
	// Original data: Secret message
	// Encrypted size: 86 bytes
	// Decrypted data: Secret message
}

// ExampleDecryptBundle demonstrates how to decrypt data encrypted with EncryptBundle.
func ExampleDecryptBundle() {
	// Generate recipient key pair
	recipientPub, recipientPriv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}

	// Encrypt some data
	originalData := []byte("Confidential information")
	encrypted := cryptohelpers.EncryptBundle(originalData, recipientPub)

	// Decrypt the data
	decrypted, err := cryptohelpers.DecryptBundle(encrypted, recipientPriv)
	if err != nil {
		panic(err)
	}

	fmt.Printf("Decrypted: %s\n", decrypted)
	fmt.Printf("Match: %v\n", string(decrypted) == string(originalData))

	// Output:
	// Decrypted: Confidential information
	// Match: true
}

// ExampleLoadEd25519Private demonstrates how to load an Ed25519 private key from a file.
func ExampleLoadEd25519Private() {
	// Generate a key pair
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}

	// Create a temporary file
	tempDir, err := os.MkdirTemp("", "cryptohelpers-example")
	if err != nil {
		panic(err)
	}
	defer os.RemoveAll(tempDir)

	keyPath := filepath.Join(tempDir, "ed25519_private.key")

	// Save the key in base64 format
	encoded := base64.StdEncoding.EncodeToString(priv)
	err = os.WriteFile(keyPath, []byte(encoded), 0600)
	if err != nil {
		panic(err)
	}

	// Load the key
	loadedKey := cryptohelpers.LoadEd25519Private(keyPath)

	fmt.Printf("Key loaded successfully\n")
	fmt.Printf("Key length: %d bytes\n", len(loadedKey))

	// Output:
	// Key loaded successfully
	// Key length: 64 bytes
}

// ExampleLoadEd25519Public demonstrates how to load an Ed25519 public key from a file.
func ExampleLoadEd25519Public() {
	// Generate a key pair
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}

	// Create a temporary file
	tempDir, err := os.MkdirTemp("", "cryptohelpers-example")
	if err != nil {
		panic(err)
	}
	defer os.RemoveAll(tempDir)

	keyPath := filepath.Join(tempDir, "ed25519_public.key")

	// Save the key in base64 format
	encoded := base64.StdEncoding.EncodeToString(pub)
	err = os.WriteFile(keyPath, []byte(encoded), 0600)
	if err != nil {
		panic(err)
	}

	// Load the key
	loadedKey := cryptohelpers.LoadEd25519Public(keyPath)

	fmt.Printf("Public key loaded successfully\n")
	fmt.Printf("Key length: %d bytes\n", len(loadedKey))

	// Output:
	// Public key loaded successfully
	// Key length: 32 bytes
}

// ExampleLoadCurve25519Private demonstrates how to load a Curve25519 private key from a file.
func ExampleLoadCurve25519Private() {
	// Generate a key pair
	_, priv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}

	// Create a temporary file
	tempDir, err := os.MkdirTemp("", "cryptohelpers-example")
	if err != nil {
		panic(err)
	}
	defer os.RemoveAll(tempDir)

	keyPath := filepath.Join(tempDir, "curve25519_private.key")

	// Save the key in base64 format
	encoded := base64.StdEncoding.EncodeToString(priv[:])
	err = os.WriteFile(keyPath, []byte(encoded), 0600)
	if err != nil {
		panic(err)
	}

	// Load the key
	loadedKey := cryptohelpers.LoadCurve25519Private(keyPath)

	fmt.Printf("Curve25519 private key loaded successfully\n")
	fmt.Printf("Key length: %d bytes\n", len(loadedKey))

	// Output:
	// Curve25519 private key loaded successfully
	// Key length: 32 bytes
}

// ExampleLoadCurve25519Public demonstrates how to load a Curve25519 public key from a file.
func ExampleLoadCurve25519Public() {
	// Generate a key pair
	pub, _, err := box.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}

	// Create a temporary file
	tempDir, err := os.MkdirTemp("", "cryptohelpers-example")
	if err != nil {
		panic(err)
	}
	defer os.RemoveAll(tempDir)

	keyPath := filepath.Join(tempDir, "curve25519_public.key")

	// Save the key in base64 format
	encoded := base64.StdEncoding.EncodeToString(pub[:])
	err = os.WriteFile(keyPath, []byte(encoded), 0600)
	if err != nil {
		panic(err)
	}

	// Load the key
	loadedKey := cryptohelpers.LoadCurve25519Public(keyPath)

	fmt.Printf("Curve25519 public key loaded successfully\n")
	fmt.Printf("Key length: %d bytes\n", len(loadedKey))

	// Output:
	// Curve25519 public key loaded successfully
	// Key length: 32 bytes
}

// Example demonstrates a complete workflow: sign, encrypt, decrypt, and verify.
func Example() {
	// Generate Ed25519 keys for signing
	signPub, signPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}

	// Generate Curve25519 keys for encryption
	encPub, encPriv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}

	// Original message
	message := []byte("Secure message")

	// Step 1: Sign the message
	signature := cryptohelpers.SignPayload(signPriv, message)
	fmt.Printf("1. Message signed (%d bytes)\n", len(signature))

	// Step 2: Create a bundle (message + signature)
	bundle := append(message, signature...)
	fmt.Printf("2. Bundle created (%d bytes)\n", len(bundle))

	// Step 3: Encrypt the bundle
	encrypted := cryptohelpers.EncryptBundle(bundle, encPub)
	fmt.Printf("3. Bundle encrypted (%d bytes)\n", len(encrypted))

	// Step 4: Decrypt the bundle
	decrypted, err := cryptohelpers.DecryptBundle(encrypted, encPriv)
	if err != nil {
		panic(err)
	}
	fmt.Printf("4. Bundle decrypted (%d bytes)\n", len(decrypted))

	// Step 5: Split the bundle
	extractedMessage, extractedSignature, err := cryptohelpers.SplitBundle(decrypted)
	if err != nil {
		panic(err)
	}
	fmt.Printf("5. Bundle split (message: %d bytes, signature: %d bytes)\n",
		len(extractedMessage), len(extractedSignature))

	// Step 6: Verify the signature
	valid := cryptohelpers.VerifyPayload(signPub, extractedMessage, extractedSignature)
	fmt.Printf("6. Signature verified: %v\n", valid)
	fmt.Printf("7. Message: %s\n", extractedMessage)

	// Output:
	// 1. Message signed (64 bytes)
	// 2. Bundle created (78 bytes)
	// 3. Bundle encrypted (150 bytes)
	// 4. Bundle decrypted (78 bytes)
	// 5. Bundle split (message: 14 bytes, signature: 64 bytes)
	// 6. Signature verified: true
	// 7. Message: Secure message
}

