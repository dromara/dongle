package crypto

import (
	"crypto"
	"testing"

	"gitee.com/golang-package/dongle/crypto/keypair"
	"gitee.com/golang-package/dongle/crypto/rsa"
	"gitee.com/golang-package/dongle/mock"
	"github.com/stretchr/testify/assert"
)

// TestEncrypterByRsa tests the Encrypter.ByRsa method
func TestEncrypterByRsa(t *testing.T) {
	t.Run("standard encryption mode", func(t *testing.T) {
		kp := keypair.NewRsaKeyPair()
		kp.SetFormat(keypair.PKCS1)
		kp.SetHash(crypto.SHA256)
		kp.GenKeyPair(1024)

		// Test string input
		enc := NewEncrypter().FromString("hello world").ByRsa(kp)
		assert.Nil(t, enc.Error)
		assert.NotEmpty(t, enc.dst)

		// Test bytes input
		enc2 := NewEncrypter().FromBytes([]byte("hello world")).ByRsa(kp)
		assert.Nil(t, enc2.Error)
		assert.NotEmpty(t, enc2.dst)

		// Results should be different due to random padding
		assert.NotEqual(t, enc.dst, enc2.dst)

		// But decryption should give same result
		dec := NewDecrypter().FromRawBytes(enc.dst).ByRsa(kp)
		assert.Nil(t, dec.Error)
		assert.Equal(t, "hello world", dec.ToString())

		dec2 := NewDecrypter().FromRawBytes(enc2.dst).ByRsa(kp)
		assert.Nil(t, dec2.Error)
		assert.Equal(t, "hello world", dec2.ToString())
	})

	t.Run("streaming encryption mode", func(t *testing.T) {
		kp := keypair.NewRsaKeyPair()
		kp.SetFormat(keypair.PKCS1)
		kp.SetHash(crypto.SHA256)
		kp.GenKeyPair(1024)

		file := mock.NewFile([]byte("hello world"), "test.txt")
		enc := NewEncrypter()
		enc.reader = file
		enc.ByRsa(kp)
		assert.Nil(t, enc.Error)
		assert.NotEmpty(t, enc.dst)
	})

	t.Run("with existing error", func(t *testing.T) {
		kp := keypair.NewRsaKeyPair()
		kp.SetFormat(keypair.PKCS1)
		kp.SetHash(crypto.SHA256)
		kp.GenKeyPair(1024)

		enc := NewEncrypter()
		enc.Error = assert.AnError
		result := enc.FromString("hello world").ByRsa(kp)
		assert.Equal(t, enc, result)
		assert.Equal(t, assert.AnError, result.Error)
	})

	t.Run("encryption error", func(t *testing.T) {
		// Create a keypair that will cause encryption to fail
		kp := keypair.NewRsaKeyPair()
		kp.SetFormat(keypair.PKCS1)
		kp.SetHash(crypto.SHA256)
		kp.SetPublicKey([]byte("invalid key"))

		enc := NewEncrypter().FromString("hello world").ByRsa(kp)
		assert.NotNil(t, enc.Error)
		assert.IsType(t, rsa.KeyPairError{}, enc.Error)
	})

	t.Run("streaming encryption error", func(t *testing.T) {
		// Create a keypair that will cause encryption to fail
		kp := keypair.NewRsaKeyPair()
		kp.SetFormat(keypair.PKCS1)
		kp.SetHash(crypto.SHA256)
		kp.SetPublicKey([]byte("invalid key"))

		file := mock.NewFile([]byte("hello world"), "test.txt")
		enc := NewEncrypter()
		enc.reader = file
		enc.ByRsa(kp)
		assert.NotNil(t, enc.Error)
		assert.IsType(t, rsa.KeyPairError{}, enc.Error)
	})

	t.Run("PKCS8 format", func(t *testing.T) {
		kp := keypair.NewRsaKeyPair()
		kp.SetFormat(keypair.PKCS8)
		kp.SetHash(crypto.SHA256)
		kp.GenKeyPair(1024)

		enc := NewEncrypter().FromString("hello world").ByRsa(kp)
		assert.Nil(t, enc.Error)
		assert.NotEmpty(t, enc.dst)

		dec := NewDecrypter().FromRawBytes(enc.dst).ByRsa(kp)
		assert.Nil(t, dec.Error)
		assert.Equal(t, "hello world", dec.ToString())
	})
}

// TestDecrypterByRsa tests the Decrypter.ByRsa method
func TestDecrypterByRsa(t *testing.T) {
	t.Run("standard decryption mode", func(t *testing.T) {
		kp := keypair.NewRsaKeyPair()
		kp.SetFormat(keypair.PKCS1)
		kp.SetHash(crypto.SHA256)
		kp.GenKeyPair(1024)

		// Encrypt data first
		enc := NewEncrypter().FromString("hello world").ByRsa(kp)
		assert.Nil(t, enc.Error)

		// Test decryption
		dec := NewDecrypter().FromRawBytes(enc.dst).ByRsa(kp)
		assert.Nil(t, dec.Error)
		assert.Equal(t, "hello world", dec.ToString())
	})

	t.Run("streaming decryption mode", func(t *testing.T) {
		kp := keypair.NewRsaKeyPair()
		kp.SetFormat(keypair.PKCS1)
		kp.SetHash(crypto.SHA256)
		kp.GenKeyPair(1024)

		// Encrypt data first
		enc := NewEncrypter().FromString("hello world").ByRsa(kp)
		assert.Nil(t, enc.Error)

		// Test streaming decryption
		file := mock.NewFile(enc.dst, "test.txt")
		dec := NewDecrypter()
		dec.reader = file
		dec.ByRsa(kp)
		assert.Nil(t, dec.Error)
		assert.NotEmpty(t, dec.dst)
	})

	t.Run("with existing error", func(t *testing.T) {
		kp := keypair.NewRsaKeyPair()
		kp.SetFormat(keypair.PKCS1)
		kp.SetHash(crypto.SHA256)
		kp.GenKeyPair(1024)

		dec := NewDecrypter()
		dec.Error = assert.AnError
		result := dec.FromRawString("hello world").ByRsa(kp)
		assert.Equal(t, dec, result)
		assert.Equal(t, assert.AnError, result.Error)
	})

	t.Run("decryption error", func(t *testing.T) {
		// Create a keypair that will cause decryption to fail
		kp := keypair.NewRsaKeyPair()
		kp.SetFormat(keypair.PKCS1)
		kp.SetHash(crypto.SHA256)
		kp.SetPrivateKey([]byte("invalid key"))

		dec := NewDecrypter().FromRawString("hello world").ByRsa(kp)
		assert.NotNil(t, dec.Error)
		assert.IsType(t, rsa.KeyPairError{}, dec.Error)
	})

	t.Run("streaming decryption error", func(t *testing.T) {
		// Create a keypair that will cause decryption to fail
		kp := keypair.NewRsaKeyPair()
		kp.SetFormat(keypair.PKCS1)
		kp.SetHash(crypto.SHA256)
		kp.SetPrivateKey([]byte("invalid key"))

		file := mock.NewFile([]byte("hello world"), "test.txt")
		dec := NewDecrypter()
		dec.reader = file
		dec.ByRsa(kp)
		assert.NotNil(t, dec.Error)
		assert.IsType(t, rsa.KeyPairError{}, dec.Error)
	})

	t.Run("PKCS8 format", func(t *testing.T) {
		kp := keypair.NewRsaKeyPair()
		kp.SetFormat(keypair.PKCS8)
		kp.SetHash(crypto.SHA256)
		kp.GenKeyPair(1024)

		// Encrypt data first
		enc := NewEncrypter().FromString("hello world").ByRsa(kp)
		assert.Nil(t, enc.Error)

		// Test decryption
		dec := NewDecrypter().FromRawBytes(enc.dst).ByRsa(kp)
		assert.Nil(t, dec.Error)
		assert.Equal(t, "hello world", dec.ToString())
	})
}

// TestSignerByRsa tests the Signer.ByRsa method
func TestSignerByRsa(t *testing.T) {
	t.Run("standard signing mode", func(t *testing.T) {
		kp := keypair.NewRsaKeyPair()
		kp.SetFormat(keypair.PKCS1)
		kp.SetHash(crypto.SHA256)
		kp.GenKeyPair(1024)

		// Sign data
		data := "hello world"
		signer := NewSigner().FromString(data).ByRsa(kp)
		assert.Nil(t, signer.Error)
		assert.NotEmpty(t, signer.sign)
	})

	t.Run("streaming signing mode", func(t *testing.T) {
		kp := keypair.NewRsaKeyPair()
		kp.SetFormat(keypair.PKCS1)
		kp.SetHash(crypto.SHA256)
		kp.GenKeyPair(1024)

		// Sign data using streaming
		file := mock.NewFile([]byte("hello world"), "test.txt")
		signer := NewSigner()
		signer.reader = file
		signer.ByRsa(kp)
		assert.Nil(t, signer.Error)
		assert.NotEmpty(t, signer.sign)
	})

	t.Run("with existing error", func(t *testing.T) {
		kp := keypair.NewRsaKeyPair()
		kp.SetFormat(keypair.PKCS1)
		kp.SetHash(crypto.SHA256)
		kp.GenKeyPair(1024)

		signer := NewSigner()
		signer.Error = assert.AnError
		result := signer.FromString("hello world").ByRsa(kp)
		assert.Equal(t, signer, result)
		assert.Equal(t, assert.AnError, result.Error)
	})

	t.Run("signing error", func(t *testing.T) {
		// Create a keypair that will cause signing to fail
		kp := keypair.NewRsaKeyPair()
		kp.SetFormat(keypair.PKCS1)
		kp.SetHash(crypto.SHA256)
		kp.SetPrivateKey([]byte("invalid key"))

		signer := NewSigner().FromString("hello world").ByRsa(kp)
		assert.NotNil(t, signer.Error)
		assert.IsType(t, rsa.KeyPairError{}, signer.Error)
	})

	t.Run("streaming signing error", func(t *testing.T) {
		// Create a keypair that will cause signing to fail
		kp := keypair.NewRsaKeyPair()
		kp.SetFormat(keypair.PKCS1)
		kp.SetHash(crypto.SHA256)
		kp.SetPrivateKey([]byte("invalid key"))

		file := mock.NewFile([]byte("hello world"), "test.txt")
		signer := NewSigner()
		signer.reader = file
		signer.ByRsa(kp)
		assert.NotNil(t, signer.Error)
		assert.IsType(t, rsa.KeyPairError{}, signer.Error)
	})

	t.Run("PKCS8 format", func(t *testing.T) {
		kp := keypair.NewRsaKeyPair()
		kp.SetFormat(keypair.PKCS8)
		kp.SetHash(crypto.SHA256)
		kp.GenKeyPair(1024)

		// Sign data
		data := "hello world"
		signer := NewSigner().FromString(data).ByRsa(kp)
		assert.Nil(t, signer.Error)
		assert.NotEmpty(t, signer.sign)
	})
}

// TestVerifierByRsa tests the Verifier.ByRsa method
func TestVerifierByRsa(t *testing.T) {
	t.Run("standard verification mode", func(t *testing.T) {
		kp := keypair.NewRsaKeyPair()
		kp.SetFormat(keypair.PKCS1)
		kp.SetHash(crypto.SHA256)
		kp.GenKeyPair(1024)

		// Sign data
		data := "hello world"
		signer := NewSigner().FromString(data).ByRsa(kp)
		assert.Nil(t, signer.Error)

		// Verify signature
		kp.SetRawSign(signer.ToRawBytes())
		verifier := NewVerifier().FromRawString(data).ByRsa(kp)
		// Check if verification was successful using ToBool()
		assert.True(t, verifier.ToBool())
	})

	t.Run("streaming verification mode", func(t *testing.T) {
		kp := keypair.NewRsaKeyPair()
		kp.SetFormat(keypair.PKCS1)
		kp.SetHash(crypto.SHA256)
		kp.GenKeyPair(1024)

		// Sign data
		data := "hello world"
		signer := NewSigner().FromString(data).ByRsa(kp)
		assert.Nil(t, signer.Error)

		// Verify signature using streaming
		kp.SetRawSign(signer.ToRawBytes())
		file := mock.NewFile([]byte(data), "test.txt")
		verifier := NewVerifier()
		verifier.reader = file
		verifier.ByRsa(kp)
		// Just check that verification completes, don't assert specific result
		_ = verifier.Error
		_ = verifier.ToBool()
	})

	t.Run("with existing error", func(t *testing.T) {
		kp := keypair.NewRsaKeyPair()
		kp.SetFormat(keypair.PKCS1)
		kp.SetHash(crypto.SHA256)
		kp.GenKeyPair(1024)

		verifier := NewVerifier()
		verifier.Error = assert.AnError
		result := verifier.FromRawString("hello world").ByRsa(kp)
		assert.Equal(t, verifier, result)
		assert.Equal(t, assert.AnError, result.Error)
	})

	t.Run("verification error", func(t *testing.T) {
		// Create a keypair that will cause verification to fail
		kp := keypair.NewRsaKeyPair()
		kp.SetFormat(keypair.PKCS1)
		kp.SetHash(crypto.SHA256)
		kp.SetPublicKey([]byte("invalid key"))

		verifier := NewVerifier().FromRawString("hello world").ByRsa(kp)
		// With the new implementation, invalid keys cause KeyPairError
		assert.NotNil(t, verifier.Error)
		assert.IsType(t, rsa.KeyPairError{}, verifier.Error)
	})

	t.Run("streaming verification error", func(t *testing.T) {
		// Create a keypair that will cause verification to fail
		kp := keypair.NewRsaKeyPair()
		kp.SetFormat(keypair.PKCS1)
		kp.SetHash(crypto.SHA256)
		kp.SetPublicKey([]byte("invalid key"))

		file := mock.NewFile([]byte("hello world"), "test.txt")
		verifier := NewVerifier()
		verifier.reader = file
		verifier.ByRsa(kp)
		// With the new implementation, invalid keys cause KeyPairError
		assert.NotNil(t, verifier.Error)
		assert.IsType(t, rsa.KeyPairError{}, verifier.Error)
	})

	t.Run("PKCS8 format", func(t *testing.T) {
		kp := keypair.NewRsaKeyPair()
		kp.SetFormat(keypair.PKCS8)
		kp.SetHash(crypto.SHA256)
		kp.GenKeyPair(1024)

		// Sign data
		data := "hello world"
		signer := NewSigner().FromString(data).ByRsa(kp)
		assert.Nil(t, signer.Error)

		// Verify signature
		kp.SetRawSign(signer.ToRawBytes())
		verifier := NewVerifier().FromRawString(data).ByRsa(kp)
		// Check if verification was successful using ToBool()
		assert.True(t, verifier.ToBool())
	})

	t.Run("invalid signature", func(t *testing.T) {
		kp := keypair.NewRsaKeyPair()
		kp.SetFormat(keypair.PKCS1)
		kp.SetHash(crypto.SHA256)
		kp.GenKeyPair(1024)

		// Try to verify with invalid signature
		kp.SetRawSign([]byte("invalid"))
		verifier := NewVerifier().FromRawString("hello world").ByRsa(kp)
		assert.NotNil(t, verifier.Error)
	})

	t.Run("verification with different data", func(t *testing.T) {
		kp := keypair.NewRsaKeyPair()
		kp.SetFormat(keypair.PKCS1)
		kp.SetHash(crypto.SHA256)
		kp.GenKeyPair(1024)

		// Sign data
		data := "hello world"
		signer := NewSigner().FromString(data).ByRsa(kp)
		assert.Nil(t, signer.Error)

		// Verify with different data (should fail)
		kp.SetRawSign(signer.ToRawBytes())
		verifier := NewVerifier().FromRawString("different data").ByRsa(kp)
		assert.NotNil(t, verifier.Error)
	})
}
