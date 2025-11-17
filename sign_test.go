package cryptohelpers_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	qt "github.com/frankban/quicktest"

	"github.com/go-extras/cryptohelpers"
)

func TestSignPayload_Success(t *testing.T) {
	c := qt.New(t)

	// Generate a key pair
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	c.Assert(err, qt.IsNil)

	testData := []byte("Test message to sign")

	// Sign the payload
	signature := cryptohelpers.SignPayload(priv, testData)

	// Verify signature length
	c.Assert(len(signature), qt.Equals, ed25519.SignatureSize)
	c.Assert(len(signature), qt.Equals, 64)

	// Verify the signature is valid
	valid := cryptohelpers.VerifyPayload(pub, testData, signature)
	c.Assert(valid, qt.IsTrue)
}

func TestSignPayload_EmptyData(t *testing.T) {
	c := qt.New(t)

	// Generate a key pair
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	c.Assert(err, qt.IsNil)

	testData := make([]byte, 0)

	// Sign empty payload
	signature := cryptohelpers.SignPayload(priv, testData)

	// Verify signature length
	c.Assert(len(signature), qt.Equals, ed25519.SignatureSize)

	// Verify the signature is valid
	valid := cryptohelpers.VerifyPayload(pub, testData, signature)
	c.Assert(valid, qt.IsTrue)
}

func TestSignPayload_LargeData(t *testing.T) {
	c := qt.New(t)

	// Generate a key pair
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	c.Assert(err, qt.IsNil)

	// Create large payload (1MB)
	testData := make([]byte, 1024*1024)
	_, err = rand.Read(testData)
	c.Assert(err, qt.IsNil)

	// Sign the payload
	signature := cryptohelpers.SignPayload(priv, testData)

	// Verify signature length
	c.Assert(len(signature), qt.Equals, ed25519.SignatureSize)

	// Verify the signature is valid
	valid := cryptohelpers.VerifyPayload(pub, testData, signature)
	c.Assert(valid, qt.IsTrue)
}

func TestSignPayload_Deterministic(t *testing.T) {
	c := qt.New(t)

	// Generate a key pair
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	c.Assert(err, qt.IsNil)

	testData := []byte("Deterministic test")

	// Sign the same data multiple times
	signature1 := cryptohelpers.SignPayload(priv, testData)
	signature2 := cryptohelpers.SignPayload(priv, testData)
	signature3 := cryptohelpers.SignPayload(priv, testData)

	// Ed25519 signatures should be deterministic
	c.Assert(signature1, qt.DeepEquals, signature2)
	c.Assert(signature1, qt.DeepEquals, signature3)
}

func TestSignPayload_DifferentKeys(t *testing.T) {
	c := qt.New(t)

	// Generate two key pairs
	pub1, priv1, err := ed25519.GenerateKey(rand.Reader)
	c.Assert(err, qt.IsNil)

	pub2, priv2, err := ed25519.GenerateKey(rand.Reader)
	c.Assert(err, qt.IsNil)

	testData := []byte("Test message")

	// Sign with both keys
	signature1 := cryptohelpers.SignPayload(priv1, testData)
	signature2 := cryptohelpers.SignPayload(priv2, testData)

	// Signatures should be different
	c.Assert(signature1, qt.Not(qt.DeepEquals), signature2)

	// Each signature should verify with its corresponding public key
	c.Assert(cryptohelpers.VerifyPayload(pub1, testData, signature1), qt.IsTrue)
	c.Assert(cryptohelpers.VerifyPayload(pub2, testData, signature2), qt.IsTrue)

	// Cross-verification should fail
	c.Assert(cryptohelpers.VerifyPayload(pub1, testData, signature2), qt.IsFalse)
	c.Assert(cryptohelpers.VerifyPayload(pub2, testData, signature1), qt.IsFalse)
}

func TestVerifyPayload_Success(t *testing.T) {
	c := qt.New(t)

	// Generate a key pair
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	c.Assert(err, qt.IsNil)

	testData := []byte("Verify this message")

	// Sign the payload
	signature := cryptohelpers.SignPayload(priv, testData)

	// Verify should succeed
	valid := cryptohelpers.VerifyPayload(pub, testData, signature)
	c.Assert(valid, qt.IsTrue)
}

func TestVerifyPayload_InvalidSignature(t *testing.T) {
	c := qt.New(t)

	// Generate a key pair
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	c.Assert(err, qt.IsNil)

	testData := []byte("Test message")

	// Create an invalid signature (random bytes)
	invalidSignature := make([]byte, ed25519.SignatureSize)
	_, err = rand.Read(invalidSignature)
	c.Assert(err, qt.IsNil)

	// Verify should fail
	valid := cryptohelpers.VerifyPayload(pub, testData, invalidSignature)
	c.Assert(valid, qt.IsFalse)
}

func TestVerifyPayload_WrongSignatureSize(t *testing.T) {
	c := qt.New(t)

	// Generate a key pair
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	c.Assert(err, qt.IsNil)

	testData := []byte("Test message")

	testCases := []struct {
		name      string
		signature []byte
	}{
		{"empty", make([]byte, 0)},
		{"too short", make([]byte, 63)},
		{"too long", make([]byte, 65)},
		{"way too short", make([]byte, 32)},
		{"way too long", make([]byte, 128)},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			c := qt.New(t)
			valid := cryptohelpers.VerifyPayload(pub, testData, tc.signature)
			c.Assert(valid, qt.IsFalse)
		})
	}
}

func TestVerifyPayload_ModifiedPayload(t *testing.T) {
	c := qt.New(t)

	// Generate a key pair
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	c.Assert(err, qt.IsNil)

	originalData := []byte("Original message")
	modifiedData := []byte("Modified message")

	// Sign the original payload
	signature := cryptohelpers.SignPayload(priv, originalData)

	// Verify with original data should succeed
	valid := cryptohelpers.VerifyPayload(pub, originalData, signature)
	c.Assert(valid, qt.IsTrue)

	// Verify with modified data should fail
	valid = cryptohelpers.VerifyPayload(pub, modifiedData, signature)
	c.Assert(valid, qt.IsFalse)
}

func TestVerifyPayload_ModifiedSignature(t *testing.T) {
	c := qt.New(t)

	// Generate a key pair
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	c.Assert(err, qt.IsNil)

	testData := []byte("Test message")

	// Sign the payload
	signature := cryptohelpers.SignPayload(priv, testData)

	// Verify original signature
	valid := cryptohelpers.VerifyPayload(pub, testData, signature)
	c.Assert(valid, qt.IsTrue)

	// Modify signature
	modifiedSignature := make([]byte, len(signature))
	copy(modifiedSignature, signature)
	modifiedSignature[0] ^= 0xFF // Flip bits

	// Verify modified signature should fail
	valid = cryptohelpers.VerifyPayload(pub, testData, modifiedSignature)
	c.Assert(valid, qt.IsFalse)
}

func TestSplitBundle_Success(t *testing.T) {
	c := qt.New(t)

	// Create a test bundle
	payload := []byte("This is the payload")
	signature := make([]byte, ed25519.SignatureSize)
	_, err := rand.Read(signature)
	c.Assert(err, qt.IsNil)

	bundle := append(payload, signature...)

	// Split the bundle
	extractedPayload, extractedSignature, err := cryptohelpers.SplitBundle(bundle)
	c.Assert(err, qt.IsNil)
	c.Assert(extractedPayload, qt.DeepEquals, payload)
	c.Assert(extractedSignature, qt.DeepEquals, signature)
}

func TestSplitBundle_EmptyPayload(t *testing.T) {
	c := qt.New(t)

	// Create a bundle with empty payload
	payload := make([]byte, 0)
	signature := make([]byte, ed25519.SignatureSize)
	_, err := rand.Read(signature)
	c.Assert(err, qt.IsNil)

	bundle := append(payload, signature...)

	// Split the bundle
	extractedPayload, extractedSignature, err := cryptohelpers.SplitBundle(bundle)
	c.Assert(err, qt.IsNil)
	c.Assert(extractedPayload, qt.DeepEquals, payload)
	c.Assert(extractedSignature, qt.DeepEquals, signature)
	c.Assert(len(extractedPayload), qt.Equals, 0)
	c.Assert(len(extractedSignature), qt.Equals, ed25519.SignatureSize)
}

func TestSplitBundle_TooSmall(t *testing.T) {
	testCases := []struct {
		name   string
		bundle []byte
	}{
		{"empty", make([]byte, 0)},
		{"1 byte", []byte{0x00}},
		{"63 bytes", make([]byte, 63)},
		{"half signature", make([]byte, 32)},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			c := qt.New(t)
			_, _, err := cryptohelpers.SplitBundle(tc.bundle)
			c.Assert(err, qt.IsNotNil)
			c.Assert(err.Error(), qt.Equals, "bundle too small to contain signature")
		})
	}
}

func TestSplitBundle_ExactlySignatureSize(t *testing.T) {
	c := qt.New(t)

	// Create a bundle that is exactly the signature size
	bundle := make([]byte, ed25519.SignatureSize)
	_, err := rand.Read(bundle)
	c.Assert(err, qt.IsNil)

	// Split should succeed with empty payload
	payload, signature, err := cryptohelpers.SplitBundle(bundle)
	c.Assert(err, qt.IsNil)
	c.Assert(len(payload), qt.Equals, 0)
	c.Assert(signature, qt.DeepEquals, bundle)
}

func TestSplitBundle_LargePayload(t *testing.T) {
	c := qt.New(t)

	// Create a large payload
	payload := make([]byte, 1024*1024) // 1MB
	_, err := rand.Read(payload)
	c.Assert(err, qt.IsNil)

	signature := make([]byte, ed25519.SignatureSize)
	_, err = rand.Read(signature)
	c.Assert(err, qt.IsNil)

	bundle := append(payload, signature...)

	// Split the bundle
	extractedPayload, extractedSignature, err := cryptohelpers.SplitBundle(bundle)
	c.Assert(err, qt.IsNil)
	c.Assert(len(extractedPayload), qt.Equals, len(payload))
	c.Assert(extractedSignature, qt.DeepEquals, signature)
}

func TestSignVerifySplitBundle_Integration(t *testing.T) {
	c := qt.New(t)

	// Generate a key pair
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	c.Assert(err, qt.IsNil)

	// Create a payload
	payload := []byte("Integration test payload")

	// Sign the payload
	signature := cryptohelpers.SignPayload(priv, payload)

	// Create a bundle
	bundle := append(payload, signature...)

	// Split the bundle
	extractedPayload, extractedSignature, err := cryptohelpers.SplitBundle(bundle)
	c.Assert(err, qt.IsNil)

	// Verify the extracted signature
	valid := cryptohelpers.VerifyPayload(pub, extractedPayload, extractedSignature)
	c.Assert(valid, qt.IsTrue)
}

func TestSignVerifySplitBundle_InvalidSignature(t *testing.T) {
	c := qt.New(t)

	// Generate a key pair
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	c.Assert(err, qt.IsNil)

	// Create a payload
	payload := []byte("Test payload")

	// Sign the payload
	signature := cryptohelpers.SignPayload(priv, payload)

	// Create a bundle
	bundle := append(payload, signature...)

	// Corrupt the bundle
	bundle[len(bundle)-1] ^= 0xFF

	// Split the bundle
	extractedPayload, extractedSignature, err := cryptohelpers.SplitBundle(bundle)
	c.Assert(err, qt.IsNil)

	// Verify should fail due to corrupted signature
	valid := cryptohelpers.VerifyPayload(pub, extractedPayload, extractedSignature)
	c.Assert(valid, qt.IsFalse)
}
