package crypto

import (
	"crypto"
	"fmt"
	"testing"

	"github.com/dromara/dongle/crypto/keypair"
	"github.com/stretchr/testify/assert"
)

// TestRSAExamples tests RSA encryption with various padding schemes and key formats
func TestRSAExamples(t *testing.T) {
	// Test with generated key pair
	t.Run("generated key pair", func(t *testing.T) {
		kp := keypair.NewRsaKeyPair()
		kp.SetFormat(keypair.PKCS1)
		kp.SetHash(crypto.SHA256)
		kp.GenKeyPair(1024)

		plaintext := "hello world"
		enc := NewEncrypter().FromString(plaintext).ByRsa(kp)
		assert.Nil(t, enc.Error)
		assert.NotEmpty(t, enc.dst)

		dec := NewDecrypter().FromRawBytes(enc.dst).ByRsa(kp)
		assert.Nil(t, dec.Error)
		assert.Equal(t, plaintext, dec.ToString())
	})

	// Test with generated key pair PKCS8
	t.Run("generated key pair PKCS8", func(t *testing.T) {
		kp := keypair.NewRsaKeyPair()
		kp.SetFormat(keypair.PKCS8)
		kp.SetHash(crypto.SHA256)
		kp.GenKeyPair(1024)

		plaintext := "hello world"
		enc := NewEncrypter().FromString(plaintext).ByRsa(kp)
		assert.Nil(t, enc.Error)
		assert.NotEmpty(t, enc.dst)

		dec := NewDecrypter().FromRawBytes(enc.dst).ByRsa(kp)
		assert.Nil(t, dec.Error)
		assert.Equal(t, plaintext, dec.ToString())
	})

	// Test with different data types
	t.Run("different data types", func(t *testing.T) {
		kp := keypair.NewRsaKeyPair()
		kp.SetFormat(keypair.PKCS1)
		kp.SetHash(crypto.SHA256)
		kp.GenKeyPair(1024)

		testCases := []string{
			"hello world",
			"test",
			"123",
			"a",
			"hi",
		}

		for _, plaintext := range testCases {
			enc := NewEncrypter().FromString(plaintext).ByRsa(kp)
			assert.Nil(t, enc.Error)
			assert.NotEmpty(t, enc.dst)

			dec := NewDecrypter().FromRawBytes(enc.dst).ByRsa(kp)
			assert.Nil(t, dec.Error)
			assert.Equal(t, plaintext, dec.ToString())
		}

		// Test empty string separately
		enc := NewEncrypter().FromString("").ByRsa(kp)
		assert.Nil(t, enc.Error)
		// Empty string may result in empty encrypted data
		dec := NewDecrypter().FromRawBytes(enc.dst).ByRsa(kp)
		assert.Nil(t, dec.Error)
		assert.Equal(t, "", dec.ToString())
	})
}

// TestRSAExampleKeyFormats tests RSA encryption with different key formats
func TestRSAExampleKeyFormats(t *testing.T) {
	tests := []struct {
		name           string
		keyFormat      keypair.KeyFormat
		expectedFormat string
	}{
		{
			name:           "PKCS1 format",
			keyFormat:      keypair.PKCS1,
			expectedFormat: "PKCS1",
		},
		{
			name:           "PKCS8 format",
			keyFormat:      keypair.PKCS8,
			expectedFormat: "PKCS8",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			kp := keypair.NewRsaKeyPair()
			kp.SetFormat(tt.keyFormat)
			kp.SetHash(crypto.SHA256)
			kp.GenKeyPair(1024)

			// Test encryption
			enc := NewEncrypter().FromString("hello world").ByRsa(kp)
			assert.Nil(t, enc.Error)
			assert.NotEmpty(t, enc.dst)

			// Test decryption
			dec := NewDecrypter().FromRawBytes(enc.dst).ByRsa(kp)
			assert.Nil(t, dec.Error)
			assert.Equal(t, "hello world", dec.ToString())
		})
	}
}

// Example functions for documentation
func ExampleEncrypter_ByRsa() {
	kp := keypair.NewRsaKeyPair()
	kp.SetFormat(keypair.PKCS1)
	kp.SetHash(crypto.SHA256)
	kp.GenKeyPair(1024)

	plain := "hello world"
	enc := NewEncrypter().FromString(plain).ByRsa(kp)
	fmt.Println("Encrypted length:", len(enc.dst))
	// Output: Encrypted length: 128
}

func ExampleEncrypter_ByRsa_pkcs8() {
	kp := keypair.NewRsaKeyPair()
	kp.SetFormat(keypair.PKCS8)
	kp.SetHash(crypto.SHA256)
	kp.GenKeyPair(1024)

	plain := "hello world"
	enc := NewEncrypter().FromString(plain).ByRsa(kp)
	fmt.Println("Encrypted length:", len(enc.dst))
	// Output: Encrypted length: 128
}

func ExampleDecrypter_ByRsa() {
	kp := keypair.NewRsaKeyPair()
	kp.SetFormat(keypair.PKCS1)
	kp.SetHash(crypto.SHA256)
	kp.GenKeyPair(1024)

	plain := "hello world"

	// Encrypt
	enc := NewEncrypter().FromString(plain).ByRsa(kp)

	// Decrypt
	dec := NewDecrypter().FromRawBytes(enc.dst).ByRsa(kp)
	fmt.Println(dec.ToString())
	// Output: hello world
}

func ExampleDecrypter_ByRsa_pkcs8() {
	kp := keypair.NewRsaKeyPair()
	kp.SetFormat(keypair.PKCS8)
	kp.SetHash(crypto.SHA256)
	kp.GenKeyPair(1024)

	plain := "hello world"

	// Encrypt
	enc := NewEncrypter().FromString(plain).ByRsa(kp)

	// Decrypt
	dec := NewDecrypter().FromRawBytes(enc.dst).ByRsa(kp)
	fmt.Println(dec.ToString())
	// Output: hello world
}

func ExampleSigner_ByRsa() {
	// Generate RSA key pair
	kp := keypair.NewRsaKeyPair()
	kp.SetFormat(keypair.PKCS8)
	kp.SetHash(crypto.SHA256)
	kp.GenKeyPair(1024)

	// Sign data
	data := "Hello, RSA Signature!"
	signature := NewSigner().FromString(data).ByRsa(kp).ToBase64String()
	fmt.Println("Signature length:", len(signature))
	// Output: Signature length: 172
}

func ExampleVerifier_ByRsa() {
	// Generate RSA key pair
	kp := keypair.NewRsaKeyPair()
	kp.SetFormat(keypair.PKCS8)
	kp.SetHash(crypto.SHA256)
	kp.GenKeyPair(1024)

	// Sign data
	data := "Hello, RSA Signature!"
	signature := NewSigner().FromString(data).ByRsa(kp).ToBase64String()

	// Verify signature
	kp.SetBase64Sign([]byte(signature))
	valid := NewVerifier().FromRawString(data).ByRsa(kp).ToBool()
	fmt.Println("Verification result:", valid)
	// Output: Verification result: true
}
