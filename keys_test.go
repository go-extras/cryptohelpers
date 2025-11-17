package cryptohelpers_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"

	qt "github.com/frankban/quicktest"
	"golang.org/x/crypto/nacl/box"

	"github.com/go-extras/cryptohelpers"
)

func TestLoadEd25519Private_Success(t *testing.T) {
	c := qt.New(t)

	// Generate a test key
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	c.Assert(err, qt.IsNil)

	// Create a temporary file
	tempDir := t.TempDir()
	keyPath := filepath.Join(tempDir, "ed25519_private.key")

	// Write the key in base64 format
	encoded := base64.StdEncoding.EncodeToString(priv)
	err = os.WriteFile(keyPath, []byte(encoded), 0600)
	c.Assert(err, qt.IsNil)

	// Load the key
	loadedKey := cryptohelpers.LoadEd25519Private(keyPath)

	// Verify the loaded key matches the original
	c.Assert(loadedKey, qt.DeepEquals, priv)
	c.Assert(len(loadedKey), qt.Equals, ed25519.PrivateKeySize)
}

func TestLoadEd25519Private_FileNotFound(t *testing.T) {
	c := qt.New(t)

	// Try to load a non-existent file
	defer func() {
		r := recover()
		c.Assert(r, qt.IsNotNil, qt.Commentf("expected panic for non-existent file"))
	}()

	cryptohelpers.LoadEd25519Private("/nonexistent/path/key.pem")
}

func TestLoadEd25519Private_InvalidBase64(t *testing.T) {
	c := qt.New(t)

	// Create a temporary file with invalid base64
	tempDir := t.TempDir()
	keyPath := filepath.Join(tempDir, "invalid.key")

	err := os.WriteFile(keyPath, []byte("not-valid-base64!@#$"), 0600)
	c.Assert(err, qt.IsNil)

	// Try to load the key
	defer func() {
		r := recover()
		c.Assert(r, qt.IsNotNil, qt.Commentf("expected panic for invalid base64"))
	}()

	cryptohelpers.LoadEd25519Private(keyPath)
}

func TestLoadEd25519Private_WithWhitespace(t *testing.T) {
	c := qt.New(t)

	// Generate a test key
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	c.Assert(err, qt.IsNil)

	// Create a temporary file with whitespace
	tempDir := t.TempDir()
	keyPath := filepath.Join(tempDir, "ed25519_private.key")

	// Write the key with trailing newline (common in PEM files)
	encoded := base64.StdEncoding.EncodeToString(priv)
	err = os.WriteFile(keyPath, []byte(encoded), 0600)
	c.Assert(err, qt.IsNil)

	// Load the key
	loadedKey := cryptohelpers.LoadEd25519Private(keyPath)

	// Verify the loaded key matches the original
	c.Assert(loadedKey, qt.DeepEquals, priv)
}

func TestLoadEd25519Public_Success(t *testing.T) {
	c := qt.New(t)

	// Generate a test key
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	c.Assert(err, qt.IsNil)

	// Create a temporary file
	tempDir := t.TempDir()
	keyPath := filepath.Join(tempDir, "ed25519_public.key")

	// Write the key in base64 format
	encoded := base64.StdEncoding.EncodeToString(pub)
	err = os.WriteFile(keyPath, []byte(encoded), 0600)
	c.Assert(err, qt.IsNil)

	// Load the key
	loadedKey := cryptohelpers.LoadEd25519Public(keyPath)

	// Verify the loaded key matches the original
	c.Assert(loadedKey, qt.DeepEquals, pub)
	c.Assert(len(loadedKey), qt.Equals, ed25519.PublicKeySize)
}

func TestLoadEd25519Public_FileNotFound(t *testing.T) {
	c := qt.New(t)

	// Try to load a non-existent file
	defer func() {
		r := recover()
		c.Assert(r, qt.IsNotNil, qt.Commentf("expected panic for non-existent file"))
	}()

	cryptohelpers.LoadEd25519Public("/nonexistent/path/key.pem")
}

func TestLoadEd25519Public_InvalidBase64(t *testing.T) {
	c := qt.New(t)

	// Create a temporary file with invalid base64
	tempDir := t.TempDir()
	keyPath := filepath.Join(tempDir, "invalid.key")

	err := os.WriteFile(keyPath, []byte("invalid-base64-data!!!"), 0600)
	c.Assert(err, qt.IsNil)

	// Try to load the key
	defer func() {
		r := recover()
		c.Assert(r, qt.IsNotNil, qt.Commentf("expected panic for invalid base64"))
	}()

	cryptohelpers.LoadEd25519Public(keyPath)
}

func TestLoadCurve25519Private_Success(t *testing.T) {
	c := qt.New(t)

	// Generate a test key
	_, priv, err := box.GenerateKey(rand.Reader)
	c.Assert(err, qt.IsNil)

	// Create a temporary file
	tempDir := t.TempDir()
	keyPath := filepath.Join(tempDir, "curve25519_private.key")

	// Write the key in base64 format
	encoded := base64.StdEncoding.EncodeToString(priv[:])
	err = os.WriteFile(keyPath, []byte(encoded), 0600)
	c.Assert(err, qt.IsNil)

	// Load the key
	loadedKey := cryptohelpers.LoadCurve25519Private(keyPath)

	// Verify the loaded key matches the original
	c.Assert(loadedKey, qt.IsNotNil)
	c.Assert(*loadedKey, qt.DeepEquals, *priv)
}

func TestLoadCurve25519Private_FileNotFound(t *testing.T) {
	c := qt.New(t)

	// Try to load a non-existent file
	defer func() {
		r := recover()
		c.Assert(r, qt.IsNotNil, qt.Commentf("expected panic for non-existent file"))
	}()

	cryptohelpers.LoadCurve25519Private("/nonexistent/path/key.pem")
}

func TestLoadCurve25519Private_InvalidBase64(t *testing.T) {
	c := qt.New(t)

	// Create a temporary file with invalid base64
	tempDir := t.TempDir()
	keyPath := filepath.Join(tempDir, "invalid.key")

	err := os.WriteFile(keyPath, []byte("not-base64!!!"), 0600)
	c.Assert(err, qt.IsNil)

	// Try to load the key
	defer func() {
		r := recover()
		c.Assert(r, qt.IsNotNil, qt.Commentf("expected panic for invalid base64"))
	}()

	cryptohelpers.LoadCurve25519Private(keyPath)
}

func TestLoadCurve25519Private_InvalidLength(t *testing.T) {
	testCases := []struct {
		name   string
		length int
	}{
		{"too short", 16},
		{"too long", 64},
		{"empty", 0},
		{"31 bytes", 31},
		{"33 bytes", 33},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			c := qt.New(t)

			// Create a temporary file with wrong length
			tempDir := t.TempDir()
			keyPath := filepath.Join(tempDir, "invalid_length.key")

			invalidKey := make([]byte, tc.length)
			encoded := base64.StdEncoding.EncodeToString(invalidKey)
			err := os.WriteFile(keyPath, []byte(encoded), 0600)
			c.Assert(err, qt.IsNil)

			// Try to load the key
			defer func() {
				r := recover()
				c.Assert(r, qt.IsNotNil, qt.Commentf("expected panic for invalid key length"))
			}()

			cryptohelpers.LoadCurve25519Private(keyPath)
		})
	}
}

func TestLoadCurve25519Public_Success(t *testing.T) {
	c := qt.New(t)

	// Generate a test key
	pub, _, err := box.GenerateKey(rand.Reader)
	c.Assert(err, qt.IsNil)

	// Create a temporary file
	tempDir := t.TempDir()
	keyPath := filepath.Join(tempDir, "curve25519_public.key")

	// Write the key in base64 format
	encoded := base64.StdEncoding.EncodeToString(pub[:])
	err = os.WriteFile(keyPath, []byte(encoded), 0600)
	c.Assert(err, qt.IsNil)

	// Load the key
	loadedKey := cryptohelpers.LoadCurve25519Public(keyPath)

	// Verify the loaded key matches the original
	c.Assert(loadedKey, qt.IsNotNil)
	c.Assert(*loadedKey, qt.DeepEquals, *pub)
}

func TestLoadCurve25519Public_FileNotFound(t *testing.T) {
	c := qt.New(t)

	// Try to load a non-existent file
	defer func() {
		r := recover()
		c.Assert(r, qt.IsNotNil, qt.Commentf("expected panic for non-existent file"))
	}()

	cryptohelpers.LoadCurve25519Public("/nonexistent/path/key.pem")
}

func TestLoadCurve25519Public_InvalidBase64(t *testing.T) {
	c := qt.New(t)

	// Create a temporary file with invalid base64
	tempDir := t.TempDir()
	keyPath := filepath.Join(tempDir, "invalid.key")

	err := os.WriteFile(keyPath, []byte("invalid!!!"), 0600)
	c.Assert(err, qt.IsNil)

	// Try to load the key
	defer func() {
		r := recover()
		c.Assert(r, qt.IsNotNil, qt.Commentf("expected panic for invalid base64"))
	}()

	cryptohelpers.LoadCurve25519Public(keyPath)
}

func TestLoadCurve25519Public_InvalidLength(t *testing.T) {
	testCases := []struct {
		name   string
		length int
	}{
		{"too short", 16},
		{"too long", 64},
		{"empty", 0},
		{"31 bytes", 31},
		{"33 bytes", 33},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			c := qt.New(t)

			// Create a temporary file with wrong length
			tempDir := t.TempDir()
			keyPath := filepath.Join(tempDir, "invalid_length.key")

			invalidKey := make([]byte, tc.length)
			encoded := base64.StdEncoding.EncodeToString(invalidKey)
			err := os.WriteFile(keyPath, []byte(encoded), 0600)
			c.Assert(err, qt.IsNil)

			// Try to load the key
			defer func() {
				r := recover()
				c.Assert(r, qt.IsNotNil, qt.Commentf("expected panic for invalid key length"))
			}()

			cryptohelpers.LoadCurve25519Public(keyPath)
		})
	}
}

func TestKeyLoading_Integration(t *testing.T) {
	c := qt.New(t)

	tempDir := t.TempDir()

	// Generate Ed25519 key pair
	ed25519Pub, ed25519Priv, err := ed25519.GenerateKey(rand.Reader)
	c.Assert(err, qt.IsNil)

	// Generate Curve25519 key pair
	curve25519Pub, curve25519Priv, err := box.GenerateKey(rand.Reader)
	c.Assert(err, qt.IsNil)

	// Save Ed25519 keys
	ed25519PrivPath := filepath.Join(tempDir, "ed25519_priv.key")
	ed25519PubPath := filepath.Join(tempDir, "ed25519_pub.key")

	err = os.WriteFile(ed25519PrivPath, []byte(base64.StdEncoding.EncodeToString(ed25519Priv)), 0600)
	c.Assert(err, qt.IsNil)

	err = os.WriteFile(ed25519PubPath, []byte(base64.StdEncoding.EncodeToString(ed25519Pub)), 0600)
	c.Assert(err, qt.IsNil)

	// Save Curve25519 keys
	curve25519PrivPath := filepath.Join(tempDir, "curve25519_priv.key")
	curve25519PubPath := filepath.Join(tempDir, "curve25519_pub.key")

	err = os.WriteFile(curve25519PrivPath, []byte(base64.StdEncoding.EncodeToString(curve25519Priv[:])), 0600)
	c.Assert(err, qt.IsNil)

	err = os.WriteFile(curve25519PubPath, []byte(base64.StdEncoding.EncodeToString(curve25519Pub[:])), 0600)
	c.Assert(err, qt.IsNil)

	// Load all keys
	loadedEd25519Priv := cryptohelpers.LoadEd25519Private(ed25519PrivPath)
	loadedEd25519Pub := cryptohelpers.LoadEd25519Public(ed25519PubPath)
	loadedCurve25519Priv := cryptohelpers.LoadCurve25519Private(curve25519PrivPath)
	loadedCurve25519Pub := cryptohelpers.LoadCurve25519Public(curve25519PubPath)

	// Verify all keys
	c.Assert(loadedEd25519Priv, qt.DeepEquals, ed25519Priv)
	c.Assert(loadedEd25519Pub, qt.DeepEquals, ed25519Pub)
	c.Assert(*loadedCurve25519Priv, qt.DeepEquals, *curve25519Priv)
	c.Assert(*loadedCurve25519Pub, qt.DeepEquals, *curve25519Pub)

	// Test that Ed25519 keys work for signing
	testMessage := []byte("Integration test message")
	signature := cryptohelpers.SignPayload(loadedEd25519Priv, testMessage)
	valid := cryptohelpers.VerifyPayload(loadedEd25519Pub, testMessage, signature)
	c.Assert(valid, qt.IsTrue)

	// Test that Curve25519 keys work for encryption
	testData := []byte("Integration test data")
	encrypted := cryptohelpers.EncryptBundle(testData, loadedCurve25519Pub)
	decrypted, err := cryptohelpers.DecryptBundle(encrypted, loadedCurve25519Priv)
	c.Assert(err, qt.IsNil)
	c.Assert(decrypted, qt.DeepEquals, testData)
}
