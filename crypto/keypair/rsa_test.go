package keypair

import (
	"crypto"
	"testing"

	"github.com/stretchr/testify/assert"
)

// Basics: constructor and options
func TestRSA_NewAndConfig(t *testing.T) {
	kp := NewRsaKeyPair()
	assert.Equal(t, PKCS8, kp.Format)
	assert.Equal(t, crypto.SHA256, kp.Hash)

	kp.SetFormat(PKCS1)
	assert.Equal(t, PKCS1, kp.Format)
	kp.SetFormat(PKCS8)
	assert.Equal(t, PKCS8, kp.Format)

	kp.SetHash(crypto.SHA512)
	assert.Equal(t, crypto.SHA512, kp.Hash)
}

// Key generation covers PKCS1 and PKCS8 branches
func TestRSA_GenKeyPair(t *testing.T) {
	t.Run("pkcs1", func(t *testing.T) {
		kp := NewRsaKeyPair()
		kp.SetFormat(PKCS1)
		err := kp.GenKeyPair(1024)
		assert.NoError(t, err)
		assert.Contains(t, string(kp.PublicKey), "-----BEGIN RSA PUBLIC KEY-----")
		assert.Contains(t, string(kp.PrivateKey), "-----BEGIN RSA PRIVATE KEY-----")
	})

	t.Run("pkcs8", func(t *testing.T) {
		kp := NewRsaKeyPair()
		kp.SetFormat(PKCS8)
		err := kp.GenKeyPair(1024)
		assert.NoError(t, err)
		assert.Contains(t, string(kp.PublicKey), "-----BEGIN PUBLIC KEY-----")
		assert.Contains(t, string(kp.PrivateKey), "-----BEGIN PRIVATE KEY-----")
	})

	t.Run("invalid size", func(t *testing.T) {
		kp := NewRsaKeyPair()
		err := kp.GenKeyPair(1)
		assert.Error(t, err)
		assert.Nil(t, kp.PublicKey)
		assert.Nil(t, kp.PrivateKey)
	})

	t.Run("unsupported format", func(t *testing.T) {
		kp := NewRsaKeyPair()
		kp.SetFormat("unknown")
		err := kp.GenKeyPair(1024)
		assert.Error(t, err)
		assert.IsType(t, UnsupportedKeyFormatError{}, err)
	})
}

// SetPublicKey/SetPrivateKey calls FormatPublicKey/FormatPrivateKey internally
func TestRSA_SetPublicKeyAndPrivateKey(t *testing.T) {
	// Build keys with PKCS1, then rewrap by PKCS8 from base64 body
	kp := NewRsaKeyPair()
	kp.SetFormat(PKCS1)
	_ = kp.GenKeyPair(1024)
	pubBody := kp.CompressPublicKey(kp.PublicKey)
	priBody := kp.CompressPrivateKey(kp.PrivateKey)

	kp.SetFormat(PKCS8)
	err := kp.SetPublicKey(pubBody)
	assert.NoError(t, err)
	assert.Contains(t, string(kp.PublicKey), "-----BEGIN PUBLIC KEY-----")

	err = kp.SetPrivateKey(priBody)
	assert.NoError(t, err)
	assert.Contains(t, string(kp.PrivateKey), "-----BEGIN PRIVATE KEY-----")

	// Reverse: PKCS8 -> PKCS1
	kp2 := NewRsaKeyPair()
	kp2.SetFormat(PKCS8)
	_ = kp2.GenKeyPair(1024)
	pubBody2 := kp2.CompressPublicKey(kp2.PublicKey)
	priBody2 := kp2.CompressPrivateKey(kp2.PrivateKey)

	kp2.SetFormat(PKCS1)
	err = kp2.SetPublicKey(pubBody2)
	assert.NoError(t, err)
	assert.Contains(t, string(kp2.PublicKey), "-----BEGIN RSA PUBLIC KEY-----")

	err = kp2.SetPrivateKey(priBody2)
	assert.NoError(t, err)
	assert.Contains(t, string(kp2.PrivateKey), "-----BEGIN RSA PRIVATE KEY-----")

	// Empty public key
	kp3 := NewRsaKeyPair()
	err = kp3.SetPublicKey([]byte{})
	assert.Error(t, err)
	assert.IsType(t, EmptyPublicKeyError{}, err)

	// Invalid base64 public key
	kp3.SetFormat(PKCS8)
	err = kp3.SetPublicKey([]byte("!not-base64!"))
	assert.Error(t, err)
	assert.IsType(t, InvalidPublicKeyError{}, err)

	// Empty private key should return error and keep empty value
	err = kp3.SetPrivateKey([]byte{})
	assert.Error(t, err)
	assert.IsType(t, EmptyPrivateKeyError{}, err)
	assert.Empty(t, kp3.PrivateKey)

	// Invalid base64 private key
	err = kp3.SetPrivateKey([]byte("!not-base64!"))
	assert.Error(t, err)
	assert.IsType(t, InvalidPrivateKeyError{}, err)

	// Unsupported format for SetPublicKey/SetPrivateKey
	kp4 := NewRsaKeyPair()
	_ = kp4.GenKeyPair(1024)
	bodyPub := kp4.CompressPublicKey(kp4.PublicKey)
	bodyPri := kp4.CompressPrivateKey(kp4.PrivateKey)
	kp4.SetFormat("unknown")
	err = kp4.SetPublicKey(bodyPub)
	assert.Error(t, err)
	assert.IsType(t, UnsupportedKeyFormatError{}, err)
	err = kp4.SetPrivateKey(bodyPri)
	assert.Error(t, err)
	assert.IsType(t, UnsupportedKeyFormatError{}, err)
}

// ParsePublicKey/ParsePrivateKey coverage for all branches
func TestRSA_ParsePublicKey(t *testing.T) {
	// Success: PKCS1
	kp1 := NewRsaKeyPair()
	kp1.SetFormat(PKCS1)
	_ = kp1.GenKeyPair(1024)
	pub1, err := kp1.ParsePublicKey()
	assert.NoError(t, err)
	assert.NotNil(t, pub1)

	// Success: PKCS8
	kp2 := NewRsaKeyPair()
	kp2.SetFormat(PKCS8)
	_ = kp2.GenKeyPair(1024)
	pub2, err := kp2.ParsePublicKey()
	assert.NoError(t, err)
	assert.NotNil(t, pub2)

	// Empty public key
	kp3 := NewRsaKeyPair()
	pub3, err := kp3.ParsePublicKey()
	assert.Nil(t, pub3)
	assert.IsType(t, EmptyPublicKeyError{}, err)

	// Invalid PEM (not PEM text)
	kp3.PublicKey = []byte("invalid")
	pub3, err = kp3.ParsePublicKey()
	assert.Nil(t, pub3)
	assert.IsType(t, InvalidPublicKeyError{}, err)

	// Unknown block type -> UnsupportedKeyFormatError
	kp4 := NewRsaKeyPair()
	kp4.PublicKey = []byte("-----BEGIN UNKNOWN KEY-----\nAA==\n-----END UNKNOWN KEY-----\n")
	pub4, err := kp4.ParsePublicKey()
	assert.Error(t, err)
	assert.IsType(t, UnsupportedKeyFormatError{}, err)
	assert.Nil(t, pub4)

	// PKCS1 block but invalid DER -> parse error
	kp5 := NewRsaKeyPair()
	kp5.PublicKey = []byte("-----BEGIN RSA PUBLIC KEY-----\nAA==\n-----END RSA PUBLIC KEY-----\n")
	pub5, err := kp5.ParsePublicKey()
	assert.Nil(t, pub5)
	assert.IsType(t, InvalidPublicKeyError{}, err)

	// PKIX block but invalid DER -> parse error
	kp6 := NewRsaKeyPair()
	kp6.PublicKey = []byte("-----BEGIN PUBLIC KEY-----\nAA==\n-----END PUBLIC KEY-----\n")
	pub6, err := kp6.ParsePublicKey()
	assert.Nil(t, pub6)
	assert.IsType(t, InvalidPublicKeyError{}, err)
}

func TestRSA_ParsePrivateKey(t *testing.T) {
	// Success: PKCS1
	kp1 := NewRsaKeyPair()
	kp1.SetFormat(PKCS1)
	_ = kp1.GenKeyPair(1024)
	pri1, err := kp1.ParsePrivateKey()
	assert.NoError(t, err)
	assert.NotNil(t, pri1)

	// Success: PKCS8
	kp2 := NewRsaKeyPair()
	kp2.SetFormat(PKCS8)
	_ = kp2.GenKeyPair(1024)
	pri2, err := kp2.ParsePrivateKey()
	assert.NoError(t, err)
	assert.NotNil(t, pri2)

	// Empty private key
	kp3 := NewRsaKeyPair()
	pri3, err := kp3.ParsePrivateKey()
	assert.Nil(t, pri3)
	assert.IsType(t, EmptyPrivateKeyError{}, err)

	// Invalid PEM (not PEM text)
	kp3.PrivateKey = []byte("invalid")
	pri3, err = kp3.ParsePrivateKey()
	assert.Nil(t, pri3)
	assert.IsType(t, InvalidPrivateKeyError{}, err)

	// Unknown block type -> UnsupportedKeyFormatError
	kp4 := NewRsaKeyPair()
	kp4.PrivateKey = []byte("-----BEGIN UNKNOWN PRIVATE KEY-----\nAA==\n-----END UNKNOWN PRIVATE KEY-----\n")
	pri4, err := kp4.ParsePrivateKey()
	assert.Error(t, err)
	assert.IsType(t, UnsupportedKeyFormatError{}, err)
	assert.Nil(t, pri4)

	// PKCS1 block but invalid DER -> parse error
	kp5 := NewRsaKeyPair()
	kp5.PrivateKey = []byte("-----BEGIN RSA PRIVATE KEY-----\nAA==\n-----END RSA PRIVATE KEY-----\n")
	pri5, err := kp5.ParsePrivateKey()
	assert.Nil(t, pri5)
	assert.IsType(t, InvalidPrivateKeyError{}, err)

	// PKCS8 block but invalid DER -> parse error
	kp6 := NewRsaKeyPair()
	kp6.PrivateKey = []byte("-----BEGIN PRIVATE KEY-----\nAA==\n-----END PRIVATE KEY-----\n")
	pri6, err := kp6.ParsePrivateKey()
	assert.Nil(t, pri6)
	assert.IsType(t, InvalidPrivateKeyError{}, err)
}

// Format and compress
func TestRSA_FormatAndCompress(t *testing.T) {
	kp := NewRsaKeyPair()
	_ = kp.GenKeyPair(1024)

	// Compress should remove headers, footers and newlines
	pubBody := kp.CompressPublicKey(kp.PublicKey)
	priBody := kp.CompressPrivateKey(kp.PrivateKey)
	assert.NotContains(t, string(pubBody), "BEGIN")
	assert.NotContains(t, string(priBody), "BEGIN")
	assert.NotContains(t, string(pubBody), "\n")
	assert.NotContains(t, string(priBody), "\n")

	// Re-wrap with different formats
	kp.SetFormat(PKCS1)
	pemPub1, err := kp.FormatPublicKey(pubBody)
	assert.NoError(t, err)
	assert.Contains(t, string(pemPub1), "-----BEGIN RSA PUBLIC KEY-----")

	kp.SetFormat(PKCS8)
	pemPub2, err := kp.FormatPublicKey(pubBody)
	assert.NoError(t, err)
	assert.Contains(t, string(pemPub2), "-----BEGIN PUBLIC KEY-----")

	// Empty public body
	_, err = kp.FormatPublicKey(nil)
	assert.Error(t, err)
	assert.IsType(t, EmptyPublicKeyError{}, err)

	// Invalid public body
	_, err = kp.FormatPublicKey([]byte("!"))
	assert.Error(t, err)
	assert.IsType(t, InvalidPublicKeyError{}, err)

	// Private key re-wrap with different formats
	kp.SetFormat(PKCS1)
	pemPri1, err := kp.FormatPrivateKey(priBody)
	assert.NoError(t, err)
	assert.Contains(t, string(pemPri1), "-----BEGIN RSA PRIVATE KEY-----")

	kp.SetFormat(PKCS8)
	pemPri2, err := kp.FormatPrivateKey(priBody)
	assert.NoError(t, err)
	assert.Contains(t, string(pemPri2), "-----BEGIN PRIVATE KEY-----")

	// Empty private body -> error
	_, err = kp.FormatPrivateKey(nil)
	assert.Error(t, err)
	assert.IsType(t, EmptyPrivateKeyError{}, err)

	// Invalid private body
	_, err = kp.FormatPrivateKey([]byte("!"))
	assert.Error(t, err)
	assert.IsType(t, InvalidPrivateKeyError{}, err)

	// Unsupported format branches for FormatPublicKey/FormatPrivateKey
	kp.SetFormat("unknown")
	_, err = kp.FormatPublicKey(pubBody)
	assert.Error(t, err)
	assert.IsType(t, UnsupportedKeyFormatError{}, err)
	_, err = kp.FormatPrivateKey(priBody)
	assert.Error(t, err)
	assert.IsType(t, UnsupportedKeyFormatError{}, err)
}

// TestRSA_SetPadding tests the SetPadding method
func TestRSA_SetPadding(t *testing.T) {
	kp := NewRsaKeyPair()

	// Test default padding (empty, will use fallback)
	assert.Equal(t, RsaPaddingScheme(""), kp.Padding)

	// Test SetPadding
	kp.SetPadding(PKCS1v15)
	assert.Equal(t, PKCS1v15, kp.Padding)

	kp.SetPadding(PSS)
	assert.Equal(t, PSS, kp.Padding)

	kp.SetPadding(OAEP)
	assert.Equal(t, OAEP, kp.Padding)
}

// TestRSA_SetFormat_OnlyAffectsFormat tests that SetFormat only sets Format, not Padding
func TestRSA_SetFormat_OnlyAffectsFormat(t *testing.T) {
	kp := NewRsaKeyPair()

	// Verify default values
	assert.Equal(t, PKCS8, kp.Format)
	assert.Equal(t, RsaPaddingScheme(""), kp.Padding)

	// SetFormat should ONLY affect Format field, not Padding
	kp.SetFormat(PKCS1)
	assert.Equal(t, PKCS1, kp.Format)
	assert.Equal(t, RsaPaddingScheme(""), kp.Padding) // Padding unchanged

	kp.SetFormat(PKCS8)
	assert.Equal(t, PKCS8, kp.Format)
	assert.Equal(t, RsaPaddingScheme(""), kp.Padding) // Padding still unchanged
}

// TestRSA_FormatVsPadding verifies that Format and Padding are independent
func TestRSA_FormatVsPadding(t *testing.T) {
	t.Run("PKCS8 format with PKCS1v15 padding", func(t *testing.T) {
		kp := NewRsaKeyPair()
		kp.Format = PKCS8
		kp.SetPadding(PKCS1v15)

		err := kp.GenKeyPair(2048)
		assert.NoError(t, err)

		// Verify key format
		assert.Contains(t, string(kp.PrivateKey), "-----BEGIN PRIVATE KEY-----")
		// Verify padding setting
		assert.Equal(t, PKCS1v15, kp.Padding)
	})

	t.Run("PKCS1 format with OAEP padding", func(t *testing.T) {
		kp := NewRsaKeyPair()
		kp.Format = PKCS1
		kp.SetPadding(OAEP)

		err := kp.GenKeyPair(2048)
		assert.NoError(t, err)

		// Verify key format
		assert.Contains(t, string(kp.PrivateKey), "-----BEGIN RSA PRIVATE KEY-----")
		// Verify padding setting
		assert.Equal(t, OAEP, kp.Padding)
	})

	t.Run("PKCS8 format with PSS padding", func(t *testing.T) {
		kp := NewRsaKeyPair()
		kp.Format = PKCS8
		kp.SetPadding(PSS)

		err := kp.GenKeyPair(2048)
		assert.NoError(t, err)

		// Verify key format
		assert.Contains(t, string(kp.PrivateKey), "-----BEGIN PRIVATE KEY-----")
		// Verify padding setting
		assert.Equal(t, PSS, kp.Padding)
	})
}
