package cryptohelpers_test

import (
	"crypto/rand"
	"testing"

	qt "github.com/frankban/quicktest"
	"golang.org/x/crypto/nacl/box"

	"github.com/go-extras/cryptohelpers"
)

func TestEncryptBundle_Success(t *testing.T) {
	c := qt.New(t)

	// Generate a recipient key pair
	recipientPub, recipientPriv, err := box.GenerateKey(rand.Reader)
	c.Assert(err, qt.IsNil)

	// Test data
	testData := []byte("Hello, World! This is a test message.")

	// Encrypt the bundle
	encrypted := cryptohelpers.EncryptBundle(testData, recipientPub)

	// Verify the output format
	// Should be: [24 bytes nonce] | [32 bytes ephemeralPub] | [ciphertext]
	c.Assert(len(encrypted), qt.Not(qt.Equals), 0)
	c.Assert(len(encrypted) > 24+32, qt.IsTrue, qt.Commentf("encrypted blob should be larger than nonce + ephemeral key"))

	// Decrypt and verify
	decrypted, err := cryptohelpers.DecryptBundle(encrypted, recipientPriv)
	c.Assert(err, qt.IsNil)
	c.Assert(decrypted, qt.DeepEquals, testData)
}

func TestEncryptBundle_EmptyData(t *testing.T) {
	c := qt.New(t)

	// Generate a recipient key pair
	recipientPub, recipientPriv, err := box.GenerateKey(rand.Reader)
	c.Assert(err, qt.IsNil)

	// Test with empty data
	testData := make([]byte, 0)

	// Encrypt the bundle
	encrypted := cryptohelpers.EncryptBundle(testData, recipientPub)

	// Should still produce output (nonce + ephemeral key + overhead)
	c.Assert(len(encrypted) > 24+32, qt.IsTrue)

	// Decrypt and verify
	decrypted, err := cryptohelpers.DecryptBundle(encrypted, recipientPriv)
	c.Assert(err, qt.IsNil)
	// Note: box.Open returns nil for empty plaintext, not []byte{}
	c.Assert(len(decrypted), qt.Equals, 0)
}

func TestEncryptBundle_LargeData(t *testing.T) {
	c := qt.New(t)

	// Generate a recipient key pair
	recipientPub, recipientPriv, err := box.GenerateKey(rand.Reader)
	c.Assert(err, qt.IsNil)

	// Test with large data (1MB)
	testData := make([]byte, 1024*1024)
	_, err = rand.Read(testData)
	c.Assert(err, qt.IsNil)

	// Encrypt the bundle
	encrypted := cryptohelpers.EncryptBundle(testData, recipientPub)

	// Decrypt and verify
	decrypted, err := cryptohelpers.DecryptBundle(encrypted, recipientPriv)
	c.Assert(err, qt.IsNil)
	c.Assert(decrypted, qt.DeepEquals, testData)
}

func TestEncryptBundle_DifferentRecipients(t *testing.T) {
	c := qt.New(t)

	// Generate two recipient key pairs
	recipientPub1, recipientPriv1, err := box.GenerateKey(rand.Reader)
	c.Assert(err, qt.IsNil)

	recipientPub2, recipientPriv2, err := box.GenerateKey(rand.Reader)
	c.Assert(err, qt.IsNil)

	testData := []byte("Secret message")

	// Encrypt for recipient 1
	encrypted1 := cryptohelpers.EncryptBundle(testData, recipientPub1)

	// Encrypt for recipient 2
	encrypted2 := cryptohelpers.EncryptBundle(testData, recipientPub2)

	// Recipient 1 can decrypt their message
	decrypted1, err := cryptohelpers.DecryptBundle(encrypted1, recipientPriv1)
	c.Assert(err, qt.IsNil)
	c.Assert(decrypted1, qt.DeepEquals, testData)

	// Recipient 2 can decrypt their message
	decrypted2, err := cryptohelpers.DecryptBundle(encrypted2, recipientPriv2)
	c.Assert(err, qt.IsNil)
	c.Assert(decrypted2, qt.DeepEquals, testData)

	// Recipient 1 cannot decrypt recipient 2's message
	_, err = cryptohelpers.DecryptBundle(encrypted2, recipientPriv1)
	c.Assert(err, qt.IsNotNil)
	c.Assert(err.Error(), qt.Equals, "decryption failed")

	// Recipient 2 cannot decrypt recipient 1's message
	_, err = cryptohelpers.DecryptBundle(encrypted1, recipientPriv2)
	c.Assert(err, qt.IsNotNil)
	c.Assert(err.Error(), qt.Equals, "decryption failed")
}

func TestEncryptBundle_UniqueNonces(t *testing.T) {
	c := qt.New(t)

	// Generate a recipient key pair
	recipientPub, _, err := box.GenerateKey(rand.Reader)
	c.Assert(err, qt.IsNil)

	testData := []byte("Test message")

	// Encrypt the same data multiple times
	encrypted1 := cryptohelpers.EncryptBundle(testData, recipientPub)
	encrypted2 := cryptohelpers.EncryptBundle(testData, recipientPub)
	encrypted3 := cryptohelpers.EncryptBundle(testData, recipientPub)

	// All encrypted blobs should be different (due to unique nonces and ephemeral keys)
	c.Assert(encrypted1, qt.Not(qt.DeepEquals), encrypted2)
	c.Assert(encrypted1, qt.Not(qt.DeepEquals), encrypted3)
	c.Assert(encrypted2, qt.Not(qt.DeepEquals), encrypted3)
}

func TestDecryptBundle_Success(t *testing.T) {
	c := qt.New(t)

	// Generate a recipient key pair
	recipientPub, recipientPriv, err := box.GenerateKey(rand.Reader)
	c.Assert(err, qt.IsNil)

	testData := []byte("Test decryption")

	// Encrypt
	encrypted := cryptohelpers.EncryptBundle(testData, recipientPub)

	// Decrypt
	decrypted, err := cryptohelpers.DecryptBundle(encrypted, recipientPriv)
	c.Assert(err, qt.IsNil)
	c.Assert(decrypted, qt.DeepEquals, testData)
}

func TestDecryptBundle_TooSmall(t *testing.T) {
	c := qt.New(t)

	// Generate a recipient key pair
	_, recipientPriv, err := box.GenerateKey(rand.Reader)
	c.Assert(err, qt.IsNil)

	// Test with blob smaller than minimum size (32 + 24 = 56 bytes)
	testCases := []struct {
		name string
		blob []byte
	}{
		{"empty", make([]byte, 0)},
		{"1 byte", []byte{0x00}},
		{"31 bytes", make([]byte, 31)},
		{"55 bytes", make([]byte, 55)},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			c := qt.New(t)
			_, err := cryptohelpers.DecryptBundle(tc.blob, recipientPriv)
			c.Assert(err, qt.IsNotNil)
			c.Assert(err.Error(), qt.Equals, "encrypted blob too small")
		})
	}
}

func TestDecryptBundle_CorruptedData(t *testing.T) {
	c := qt.New(t)

	// Generate a recipient key pair
	recipientPub, recipientPriv, err := box.GenerateKey(rand.Reader)
	c.Assert(err, qt.IsNil)

	testData := []byte("Test message for corruption")

	// Encrypt
	encrypted := cryptohelpers.EncryptBundle(testData, recipientPub)

	// Corrupt different parts of the encrypted blob
	testCases := []struct {
		name   string
		modify func([]byte) []byte
	}{
		{
			"corrupt nonce",
			func(blob []byte) []byte {
				corrupted := make([]byte, len(blob))
				copy(corrupted, blob)
				corrupted[0] ^= 0xFF // Flip bits in nonce
				return corrupted
			},
		},
		{
			"corrupt ephemeral key",
			func(blob []byte) []byte {
				corrupted := make([]byte, len(blob))
				copy(corrupted, blob)
				corrupted[30] ^= 0xFF // Flip bits in ephemeral key
				return corrupted
			},
		},
		{
			"corrupt ciphertext",
			func(blob []byte) []byte {
				corrupted := make([]byte, len(blob))
				copy(corrupted, blob)
				corrupted[len(corrupted)-1] ^= 0xFF // Flip bits in ciphertext
				return corrupted
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			c := qt.New(t)
			corrupted := tc.modify(encrypted)
			_, err := cryptohelpers.DecryptBundle(corrupted, recipientPriv)
			c.Assert(err, qt.IsNotNil)
			c.Assert(err.Error(), qt.Equals, "decryption failed")
		})
	}
}

func TestDecryptBundle_WrongKey(t *testing.T) {
	c := qt.New(t)

	// Generate two recipient key pairs
	recipientPub1, _, err := box.GenerateKey(rand.Reader)
	c.Assert(err, qt.IsNil)

	_, recipientPriv2, err := box.GenerateKey(rand.Reader)
	c.Assert(err, qt.IsNil)

	testData := []byte("Secret message")

	// Encrypt for recipient 1
	encrypted := cryptohelpers.EncryptBundle(testData, recipientPub1)

	// Try to decrypt with recipient 2's key
	_, err = cryptohelpers.DecryptBundle(encrypted, recipientPriv2)
	c.Assert(err, qt.IsNotNil)
	c.Assert(err.Error(), qt.Equals, "decryption failed")
}

func TestEncryptDecrypt_RoundTrip(t *testing.T) {
	c := qt.New(t)

	// Generate a recipient key pair
	recipientPub, recipientPriv, err := box.GenerateKey(rand.Reader)
	c.Assert(err, qt.IsNil)

	// Test various data sizes
	testCases := []struct {
		name string
		data []byte
	}{
		{"empty", make([]byte, 0)},
		{"small", []byte("Hello")},
		{"medium", []byte("This is a medium-sized test message with some content.")},
		{"with nulls", []byte{0x00, 0x01, 0x02, 0x00, 0xFF, 0x00}},
		{"binary", func() []byte {
			data := make([]byte, 256)
			for i := range data {
				data[i] = byte(i)
			}
			return data
		}()},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			c := qt.New(t)

			// Encrypt
			encrypted := cryptohelpers.EncryptBundle(tc.data, recipientPub)

			// Decrypt
			decrypted, err := cryptohelpers.DecryptBundle(encrypted, recipientPriv)
			c.Assert(err, qt.IsNil)
			// For empty data, box.Open returns nil instead of []byte{}
			if len(tc.data) == 0 {
				c.Assert(len(decrypted), qt.Equals, 0)
			} else {
				c.Assert(decrypted, qt.DeepEquals, tc.data)
			}
		})
	}
}
