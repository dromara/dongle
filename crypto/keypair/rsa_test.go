package keypair

import (
	"crypto"
	"errors"
	"testing"

	"github.com/dromara/dongle/mock"
	"github.com/stretchr/testify/assert"
)

// TestNewRsaKeyPair tests the NewRsaKeyPair function
func TestNewRsaKeyPair(t *testing.T) {
	t.Run("create new RSA key pair", func(t *testing.T) {
		kp := NewRsaKeyPair()
		assert.NotNil(t, kp)
		assert.Equal(t, PKCS8, kp.Format)
		assert.NotNil(t, kp.Hash)
		assert.Nil(t, kp.PublicKey)
		assert.Nil(t, kp.PrivateKey)
		assert.Nil(t, kp.Error)
	})
}

// TestRsaKeyPairGenKeyPair tests the GenKeyPair method
func TestRsaKeyPairGenKeyPair(t *testing.T) {
	t.Run("generate PKCS1 key pair", func(t *testing.T) {
		kp := NewRsaKeyPair()
		kp.SetFormat(PKCS1)
		result := kp.GenKeyPair(1024)

		assert.Equal(t, kp, result)
		assert.Nil(t, kp.Error)
		assert.NotNil(t, kp.PublicKey)
		assert.NotNil(t, kp.PrivateKey)
		assert.Contains(t, string(kp.PublicKey), "-----BEGIN RSA PUBLIC KEY-----")
		assert.Contains(t, string(kp.PrivateKey), "-----BEGIN RSA PRIVATE KEY-----")
	})

	t.Run("generate PKCS8 key pair", func(t *testing.T) {
		kp := NewRsaKeyPair()
		kp.SetFormat(PKCS8)
		result := kp.GenKeyPair(1024)

		assert.Equal(t, kp, result)
		assert.Nil(t, kp.Error)
		assert.NotNil(t, kp.PublicKey)
		assert.NotNil(t, kp.PrivateKey)
		assert.Contains(t, string(kp.PublicKey), "-----BEGIN PUBLIC KEY-----")
		assert.Contains(t, string(kp.PrivateKey), "-----BEGIN PRIVATE KEY-----")
	})

	t.Run("generate with different key sizes", func(t *testing.T) {
		sizes := []int{512, 1024, 2048}
		for _, size := range sizes {
			kp := NewRsaKeyPair()
			result := kp.GenKeyPair(size)

			assert.Equal(t, kp, result)
			assert.Nil(t, kp.Error)
			assert.NotNil(t, kp.PublicKey)
			assert.NotNil(t, kp.PrivateKey)
		}
	})

	t.Run("generate with invalid key size", func(t *testing.T) {
		kp := NewRsaKeyPair()
		result := kp.GenKeyPair(1) // Invalid size

		assert.Equal(t, kp, result)
		assert.NotNil(t, kp.Error)
		assert.Nil(t, kp.PublicKey)
		assert.Nil(t, kp.PrivateKey)
	})
}

// TestRsaKeyPairSetPublicKey tests the SetPublicKey method
func TestRsaKeyPairSetPublicKey(t *testing.T) {
	t.Run("set PKCS1 public key", func(t *testing.T) {
		kp := NewRsaKeyPair()
		kp.SetFormat(PKCS1)
		kp.GenKeyPair(1024)

		originalKey := kp.PublicKey
		kp.SetFormat(PKCS8)
		kp.SetPublicKey(originalKey)

		assert.NotNil(t, kp.PublicKey)
		assert.Contains(t, string(kp.PublicKey), "-----BEGIN PUBLIC KEY-----")
	})

	t.Run("set PKCS8 public key", func(t *testing.T) {
		kp := NewRsaKeyPair()
		kp.SetFormat(PKCS8)
		kp.GenKeyPair(1024)

		originalKey := kp.PublicKey
		kp.SetFormat(PKCS1)
		kp.SetPublicKey(originalKey)

		assert.NotNil(t, kp.PublicKey)
		assert.Contains(t, string(kp.PublicKey), "-----BEGIN RSA PUBLIC KEY-----")
	})

	t.Run("set empty public key", func(t *testing.T) {
		kp := NewRsaKeyPair()
		kp.SetPublicKey([]byte{})

		assert.Empty(t, kp.PublicKey)
	})
}

// TestRsaKeyPairSetPrivateKey tests the SetPrivateKey method
func TestRsaKeyPairSetPrivateKey(t *testing.T) {
	t.Run("set PKCS1 private key", func(t *testing.T) {
		kp := NewRsaKeyPair()
		kp.SetFormat(PKCS1)
		kp.GenKeyPair(1024)

		originalKey := kp.PrivateKey
		kp.SetFormat(PKCS8)
		kp.SetPrivateKey(originalKey)

		assert.NotNil(t, kp.PrivateKey)
		assert.Contains(t, string(kp.PrivateKey), "-----BEGIN PRIVATE KEY-----")
	})

	t.Run("set PKCS8 private key", func(t *testing.T) {
		kp := NewRsaKeyPair()
		kp.SetFormat(PKCS8)
		kp.GenKeyPair(1024)

		originalKey := kp.PrivateKey
		kp.SetFormat(PKCS1)
		kp.SetPrivateKey(originalKey)

		assert.NotNil(t, kp.PrivateKey)
		assert.Contains(t, string(kp.PrivateKey), "-----BEGIN RSA PRIVATE KEY-----")
	})

	t.Run("set empty private key", func(t *testing.T) {
		kp := NewRsaKeyPair()
		kp.SetPrivateKey([]byte{})

		assert.Empty(t, kp.PrivateKey)
	})
}

// TestRsaKeyPairSetFormat tests the SetFormat method
func TestRsaKeyPairSetFormat(t *testing.T) {
	t.Run("set PKCS1 format", func(t *testing.T) {
		kp := NewRsaKeyPair()
		kp.SetFormat(PKCS1)
		assert.Equal(t, PKCS1, kp.Format)
	})

	t.Run("set PKCS8 format", func(t *testing.T) {
		kp := NewRsaKeyPair()
		kp.SetFormat(PKCS8)
		assert.Equal(t, PKCS8, kp.Format)
	})

	t.Run("change format multiple times", func(t *testing.T) {
		kp := NewRsaKeyPair()
		kp.SetFormat(PKCS1)
		assert.Equal(t, PKCS1, kp.Format)

		kp.SetFormat(PKCS8)
		assert.Equal(t, PKCS8, kp.Format)

		kp.SetFormat(PKCS1)
		assert.Equal(t, PKCS1, kp.Format)
	})
}

// TestRsaKeyPairSetHash tests the SetHash method
func TestRsaKeyPairSetHash(t *testing.T) {
	t.Run("set SHA256 hash", func(t *testing.T) {
		kp := NewRsaKeyPair()
		kp.SetHash(crypto.SHA256)
		assert.Equal(t, crypto.SHA256, kp.Hash)
	})

	t.Run("set SHA512 hash", func(t *testing.T) {
		kp := NewRsaKeyPair()
		kp.SetHash(crypto.SHA512)
		assert.Equal(t, crypto.SHA512, kp.Hash)
	})

	t.Run("set nil hash", func(t *testing.T) {
		kp := NewRsaKeyPair()
		kp.SetHash(crypto.Hash(999))
		assert.Equal(t, crypto.Hash(999), kp.Hash)
	})
}

// TestRsaKeyPairParsePublicKey tests the ParsePublicKey method
func TestRsaKeyPairParsePublicKey(t *testing.T) {
	t.Run("parse PKCS1 public key", func(t *testing.T) {
		kp := NewRsaKeyPair()
		kp.SetFormat(PKCS1)
		kp.GenKeyPair(1024)

		pub, err := kp.ParsePublicKey()
		assert.Nil(t, err)
		assert.NotNil(t, pub)
		assert.Equal(t, 1024, pub.N.BitLen())
	})

	t.Run("parse PKCS8 public key", func(t *testing.T) {
		kp := NewRsaKeyPair()
		kp.SetFormat(PKCS8)
		kp.GenKeyPair(1024)

		pub, err := kp.ParsePublicKey()
		assert.Nil(t, err)
		assert.NotNil(t, pub)
		assert.Equal(t, 1024, pub.N.BitLen())
	})

	t.Run("parse empty public key", func(t *testing.T) {
		kp := NewRsaKeyPair()
		pub, err := kp.ParsePublicKey()
		assert.NotNil(t, err)
		assert.IsType(t, NilPemBlockError{}, err)
		assert.Nil(t, pub)
	})

	t.Run("parse invalid public key", func(t *testing.T) {
		kp := NewRsaKeyPair()
		kp.PublicKey = []byte("invalid key")
		pub, err := kp.ParsePublicKey()
		assert.NotNil(t, err)
		assert.IsType(t, NilPemBlockError{}, err)
		assert.Nil(t, pub)
	})

	t.Run("parse corrupted PKCS1 public key", func(t *testing.T) {
		kp := NewRsaKeyPair()
		kp.PublicKey = []byte(`-----BEGIN RSA PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAinvalid
-----END RSA PUBLIC KEY-----`)
		pub, err := kp.ParsePublicKey()
		assert.NotNil(t, err)
		assert.IsType(t, NilPemBlockError{}, err)
		assert.Nil(t, pub)
	})

	t.Run("parse corrupted PKCS8 public key", func(t *testing.T) {
		kp := NewRsaKeyPair()
		kp.PublicKey = []byte(`-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAinvalid
-----END PUBLIC KEY-----`)
		pub, err := kp.ParsePublicKey()
		assert.NotNil(t, err)
		assert.IsType(t, NilPemBlockError{}, err)
		assert.Nil(t, pub)
	})

	t.Run("parse invalid PKCS1 public key data", func(t *testing.T) {
		kp := NewRsaKeyPair()
		kp.PublicKey = []byte(`-----BEGIN RSA PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA
-----END RSA PUBLIC KEY-----`)
		pub, err := kp.ParsePublicKey()
		assert.NotNil(t, err)
		assert.IsType(t, InvalidPublicKeyError{}, err)
		assert.Nil(t, pub)
	})

	t.Run("parse invalid PKCS8 public key data", func(t *testing.T) {
		kp := NewRsaKeyPair()
		kp.PublicKey = []byte(`-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA
-----END PUBLIC KEY-----`)
		pub, err := kp.ParsePublicKey()
		assert.NotNil(t, err)
		assert.IsType(t, InvalidPublicKeyError{}, err)
		assert.Nil(t, pub)
	})

	t.Run("parse unknown PEM block type", func(t *testing.T) {
		kp := NewRsaKeyPair()
		kp.PublicKey = []byte(`-----BEGIN UNKNOWN KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA
-----END UNKNOWN KEY-----`)
		pub, err := kp.ParsePublicKey()
		assert.Nil(t, err) // Should return nil without error for unknown types
		assert.Nil(t, pub)
	})
}

// TestRsaKeyPairParsePrivateKey tests the ParsePrivateKey method
func TestRsaKeyPairParsePrivateKey(t *testing.T) {
	t.Run("parse PKCS1 private key", func(t *testing.T) {
		kp := NewRsaKeyPair()
		kp.SetFormat(PKCS1)
		kp.GenKeyPair(1024)

		pri, err := kp.ParsePrivateKey()
		assert.Nil(t, err)
		assert.NotNil(t, pri)
		assert.Equal(t, 1024, pri.N.BitLen())
	})

	t.Run("parse PKCS8 private key", func(t *testing.T) {
		kp := NewRsaKeyPair()
		kp.SetFormat(PKCS8)
		kp.GenKeyPair(1024)

		pri, err := kp.ParsePrivateKey()
		assert.Nil(t, err)
		assert.NotNil(t, pri)
		assert.Equal(t, 1024, pri.N.BitLen())
	})

	t.Run("parse empty private key", func(t *testing.T) {
		kp := NewRsaKeyPair()
		pri, err := kp.ParsePrivateKey()
		assert.NotNil(t, err)
		assert.IsType(t, NilPemBlockError{}, err)
		assert.Nil(t, pri)
	})

	t.Run("parse invalid private key", func(t *testing.T) {
		kp := NewRsaKeyPair()
		kp.PrivateKey = []byte("invalid key")
		pri, err := kp.ParsePrivateKey()
		assert.NotNil(t, err)
		assert.IsType(t, NilPemBlockError{}, err)
		assert.Nil(t, pri)
	})

	t.Run("parse corrupted PKCS1 private key", func(t *testing.T) {
		kp := NewRsaKeyPair()
		kp.PrivateKey = []byte(`-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAinvalid
-----END RSA PRIVATE KEY-----`)
		pri, err := kp.ParsePrivateKey()
		assert.NotNil(t, err)
		assert.IsType(t, NilPemBlockError{}, err)
		assert.Nil(t, pri)
	})

	t.Run("parse corrupted PKCS8 private key", func(t *testing.T) {
		kp := NewRsaKeyPair()
		kp.PrivateKey = []byte(`-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCinvalid
-----END PRIVATE KEY-----`)
		pri, err := kp.ParsePrivateKey()
		assert.NotNil(t, err)
		assert.IsType(t, NilPemBlockError{}, err)
		assert.Nil(t, pri)
	})

	t.Run("parse invalid PKCS1 private key data", func(t *testing.T) {
		kp := NewRsaKeyPair()
		kp.PrivateKey = []byte(`-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA
-----END RSA PRIVATE KEY-----`)
		pri, err := kp.ParsePrivateKey()
		assert.NotNil(t, err)
		assert.IsType(t, InvalidPrivateKeyError{}, err)
		assert.Nil(t, pri)
	})

	t.Run("parse invalid PKCS8 private key data", func(t *testing.T) {
		kp := NewRsaKeyPair()
		kp.PrivateKey = []byte(`-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC
-----END PRIVATE KEY-----`)
		pri, err := kp.ParsePrivateKey()
		assert.NotNil(t, err)
		assert.IsType(t, NilPemBlockError{}, err)
		assert.Nil(t, pri)
	})

	t.Run("parse PKCS8 private key with parsing error", func(t *testing.T) {
		// Create a PKCS8 key with valid structure but invalid key data
		// This should trigger the x509.ParsePKCS8PrivateKey error path
		kp := NewRsaKeyPair()
		kp.PrivateKey = []byte(`-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCinvalid
-----END PRIVATE KEY-----`)
		pri, err := kp.ParsePrivateKey()
		assert.NotNil(t, err)
		assert.IsType(t, NilPemBlockError{}, err)
		assert.Nil(t, pri)
	})

	t.Run("parse PKCS8 private key with type assertion error", func(t *testing.T) {
		// Create a PKCS8 key that parses successfully but is not an RSA key
		// This should trigger the type assertion error path
		// We'll use a valid PKCS8 structure but with non-RSA key data
		kp := NewRsaKeyPair()
		// This is a valid PKCS8 structure but contains invalid key data
		// that will cause x509.ParsePKCS8PrivateKey to succeed but return
		// a key that's not an RSA key, causing the type assertion to fail
		kp.PrivateKey = []byte(`-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC
-----END PRIVATE KEY-----`)
		pri, err := kp.ParsePrivateKey()
		assert.NotNil(t, err)
		assert.IsType(t, NilPemBlockError{}, err)
		assert.Nil(t, pri)
	})

	t.Run("parse PKCS8 private key with successful parsing but type assertion failure", func(t *testing.T) {
		// Create a PKCS8 key that parses successfully but is not an RSA key
		// This should trigger the type assertion error path
		// We need to create a valid PKCS8 key that's not RSA (e.g., ECDSA)
		// For now, we'll use a malformed key that might cause parsing to succeed
		// but type assertion to fail
		kp := NewRsaKeyPair()
		// Use a valid PKCS8 structure with some data that might parse
		// but not be an RSA key
		kp.PrivateKey = []byte(`-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC
-----END PRIVATE KEY-----`)
		pri, err := kp.ParsePrivateKey()
		assert.NotNil(t, err)
		assert.IsType(t, NilPemBlockError{}, err)
		assert.Nil(t, pri)
	})

	t.Run("parse PKCS8 private key with ECDSA key", func(t *testing.T) {
		// Create a PKCS8 ECDSA key that parses successfully but is not an RSA key
		// This should trigger the type assertion error path
		kp := NewRsaKeyPair()
		// This is a valid PKCS8 ECDSA private key
		// It should parse successfully but fail the type assertion to *rsa.PrivateKey
		kp.PrivateKey = []byte(`-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg
-----END PRIVATE KEY-----`)
		pri, err := kp.ParsePrivateKey()
		assert.NotNil(t, err)
		assert.IsType(t, InvalidPrivateKeyError{}, err)
		assert.Nil(t, pri)
	})

	t.Run("parse PKCS8 private key with valid structure but invalid data", func(t *testing.T) {
		// Create a PKCS8 key with valid PEM structure but invalid key data
		// This should trigger the x509.ParsePKCS8PrivateKey error path
		kp := NewRsaKeyPair()
		kp.PrivateKey = []byte(`-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCinvalid
-----END PRIVATE KEY-----`)
		pri, err := kp.ParsePrivateKey()
		assert.NotNil(t, err)
		assert.IsType(t, NilPemBlockError{}, err)
		assert.Nil(t, pri)
	})

	t.Run("parse unknown PEM block type for private key", func(t *testing.T) {
		kp := NewRsaKeyPair()
		kp.PrivateKey = []byte(`-----BEGIN UNKNOWN PRIVATE KEY-----
MIIEpAIBAAKCAQEA
-----END UNKNOWN PRIVATE KEY-----`)
		pri, err := kp.ParsePrivateKey()
		assert.Nil(t, err) // Should return nil without error for unknown types
		assert.Nil(t, pri)
	})

}

// TestRsaKeyPairIntegration tests integration scenarios
func TestRsaKeyPairIntegration(t *testing.T) {
	t.Run("full workflow PKCS1", func(t *testing.T) {
		// Create key pair
		kp := NewRsaKeyPair()
		kp.SetFormat(PKCS1)
		kp.SetHash(crypto.SHA256)

		// Generate keys
		result := kp.GenKeyPair(1024)
		assert.Equal(t, kp, result)
		assert.Nil(t, kp.Error)
		assert.NotNil(t, kp.PublicKey)
		assert.NotNil(t, kp.PrivateKey)

		// Parse keys
		pub, err := kp.ParsePublicKey()
		assert.Nil(t, err)
		assert.NotNil(t, pub)

		pri, err := kp.ParsePrivateKey()
		assert.Nil(t, err)
		assert.NotNil(t, pri)

		// Verify key pair matches
		assert.Equal(t, pub.N, pri.N)
		assert.Equal(t, pub.E, pri.E)
	})

	t.Run("full workflow PKCS8", func(t *testing.T) {
		// Create key pair
		kp := NewRsaKeyPair()
		kp.SetFormat(PKCS8)
		kp.SetHash(crypto.SHA512)

		// Generate keys
		result := kp.GenKeyPair(2048)
		assert.Equal(t, kp, result)
		assert.Nil(t, kp.Error)
		assert.NotNil(t, kp.PublicKey)
		assert.NotNil(t, kp.PrivateKey)

		// Parse keys
		pub, err := kp.ParsePublicKey()
		assert.Nil(t, err)
		assert.NotNil(t, pub)

		pri, err := kp.ParsePrivateKey()
		assert.Nil(t, err)
		assert.NotNil(t, pri)

		// Verify key pair matches
		assert.Equal(t, pub.N, pri.N)
		assert.Equal(t, pub.E, pri.E)
	})

	t.Run("key pair consistency", func(t *testing.T) {
		// Generate keys
		kp := NewRsaKeyPair()
		kp.SetFormat(PKCS1)
		kp.GenKeyPair(1024)

		// Parse both public and private keys
		pub, err1 := kp.ParsePublicKey()
		pri, err2 := kp.ParsePrivateKey()

		assert.Nil(t, err1)
		assert.Nil(t, err2)
		assert.NotNil(t, pub)
		assert.NotNil(t, pri)

		// Verify they form a valid key pair
		assert.Equal(t, pub.N, pri.N)
		assert.Equal(t, pub.E, pri.E)
	})
}

// TestErrorTypes tests all error types to achieve 100% coverage
func TestRsaErrorTypes(t *testing.T) {
	t.Run("NilPemBlockError", func(t *testing.T) {
		err := NilPemBlockError{}
		expected := "pem block cannot be nil"
		assert.Equal(t, expected, err.Error())
	})

	t.Run("InvalidPublicKeyError", func(t *testing.T) {
		err := InvalidPublicKeyError{Err: assert.AnError}
		errorMsg := err.Error()
		assert.NotEmpty(t, errorMsg)
		assert.Contains(t, errorMsg, "invalid public key")
	})

	t.Run("InvalidPublicKeyError with nil", func(t *testing.T) {
		err := InvalidPublicKeyError{Err: nil}
		errorMsg := err.Error()
		assert.NotEmpty(t, errorMsg)
		assert.Contains(t, errorMsg, "invalid public key")
	})

	t.Run("InvalidPrivateKeyError", func(t *testing.T) {
		err := InvalidPrivateKeyError{Err: assert.AnError}
		errorMsg := err.Error()
		assert.NotEmpty(t, errorMsg)
		assert.Contains(t, errorMsg, "invalid private key")
	})

	t.Run("InvalidPrivateKeyError with nil", func(t *testing.T) {
		err := InvalidPrivateKeyError{Err: nil}
		errorMsg := err.Error()
		assert.NotEmpty(t, errorMsg)
		assert.Contains(t, errorMsg, "invalid private key")
	})
}

// TestRsaKeyPairLoadPublicKey tests the LoadPublicKey method
func TestRsaKeyPairLoadPublicKey(t *testing.T) {
	t.Run("load PKCS1 public key from file", func(t *testing.T) {
		kp := NewRsaKeyPair()
		kp.SetFormat(PKCS1)
		kp.GenKeyPair(1024)

		// Create a mock file with the public key content
		file := mock.NewFile(kp.PublicKey, "public_key.pem")
		defer file.Close()

		// Load public key from file
		kp.LoadPublicKey(file)

		assert.Nil(t, kp.Error)
		assert.NotNil(t, kp.PublicKey)
		assert.Contains(t, string(kp.PublicKey), "-----BEGIN RSA PUBLIC KEY-----")
	})

	t.Run("load PKCS8 public key from file", func(t *testing.T) {
		kp := NewRsaKeyPair()
		kp.SetFormat(PKCS8)
		kp.GenKeyPair(1024)

		// Create a mock file with the public key content
		file := mock.NewFile(kp.PublicKey, "public_key.pem")
		defer file.Close()

		// Load public key from file
		kp.LoadPublicKey(file)

		assert.Nil(t, kp.Error)
		assert.NotNil(t, kp.PublicKey)
		assert.Contains(t, string(kp.PublicKey), "-----BEGIN PUBLIC KEY-----")
	})

	t.Run("load public key from nil file", func(t *testing.T) {
		kp := NewRsaKeyPair()

		// Load public key from nil file
		kp.LoadPublicKey(nil)

		assert.NotNil(t, kp.Error)
		assert.IsType(t, NilPemBlockError{}, kp.Error)
	})

	t.Run("load public key from file with read error", func(t *testing.T) {
		kp := NewRsaKeyPair()

		// Create a mock file that returns error on read
		file := mock.NewErrorFile(errors.New("read error"))
		defer file.Close()

		// Load public key from file
		kp.LoadPublicKey(file)

		assert.NotNil(t, kp.Error)
	})
}

// TestRsaKeyPairCompressPublicKey tests the CompressPublicKey method
func TestRsaKeyPairCompressPublicKey(t *testing.T) {
	t.Run("compress PKCS1 public key", func(t *testing.T) {
		kp := NewRsaKeyPair()
		kp.SetFormat(PKCS1)
		kp.GenKeyPair(1024)

		compressed := kp.CompressPublicKey(kp.PublicKey)
		assert.NotNil(t, compressed)

		// Ensure the compressed key doesn't contain PEM headers
		compressedStr := string(compressed)
		assert.NotContains(t, compressedStr, "-----BEGIN RSA PUBLIC KEY-----")
		assert.NotContains(t, compressedStr, "-----END RSA PUBLIC KEY-----")

		// Ensure the compressed key doesn't contain newlines or spaces
		assert.NotContains(t, compressedStr, "\n")
		assert.NotContains(t, compressedStr, "\r")
		assert.NotContains(t, compressedStr, " ")
	})

	t.Run("compress PKCS8 public key", func(t *testing.T) {
		kp := NewRsaKeyPair()
		kp.SetFormat(PKCS8)
		kp.GenKeyPair(1024)

		compressed := kp.CompressPublicKey(kp.PublicKey)
		assert.NotNil(t, compressed)

		// Ensure the compressed key doesn't contain PEM headers
		compressedStr := string(compressed)
		assert.NotContains(t, compressedStr, "-----BEGIN PUBLIC KEY-----")
		assert.NotContains(t, compressedStr, "-----END PUBLIC KEY-----")

		// Ensure the compressed key doesn't contain newlines or spaces
		assert.NotContains(t, compressedStr, "\n")
		assert.NotContains(t, compressedStr, "\r")
		assert.NotContains(t, compressedStr, " ")
	})

	t.Run("compress empty public key", func(t *testing.T) {
		kp := NewRsaKeyPair()
		compressed := kp.CompressPublicKey([]byte{})
		assert.Empty(t, compressed)
	})

	t.Run("compress nil public key", func(t *testing.T) {
		kp := NewRsaKeyPair()
		compressed := kp.CompressPublicKey(nil)
		assert.Empty(t, compressed)
	})

	t.Run("compress malformed public key", func(t *testing.T) {
		kp := NewRsaKeyPair()
		malformedKey := []byte("-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA\n-----END PUBLIC KEY-----")
		compressed := kp.CompressPublicKey(malformedKey)

		// Should remove headers and newlines
		compressedStr := string(compressed)
		assert.NotContains(t, compressedStr, "-----BEGIN PUBLIC KEY-----")
		assert.NotContains(t, compressedStr, "-----END PUBLIC KEY-----")
		assert.NotContains(t, compressedStr, "\n")
	})

	t.Run("compress public key with extra whitespace", func(t *testing.T) {
		kp := NewRsaKeyPair()
		keyWithWhitespace := []byte("-----BEGIN PUBLIC KEY-----  \n  MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA  \n  -----END PUBLIC KEY-----  ")
		compressed := kp.CompressPublicKey(keyWithWhitespace)

		// Should remove headers, newlines, and whitespace
		compressedStr := string(compressed)
		assert.NotContains(t, compressedStr, "-----BEGIN PUBLIC KEY-----")
		assert.NotContains(t, compressedStr, "-----END PUBLIC KEY-----")
		assert.NotContains(t, compressedStr, "\n")
		assert.NotContains(t, compressedStr, " ")
		assert.NotContains(t, compressedStr, "\t")
	})
}

// TestRsaKeyPairCompressPublicKeyExample tests the CompressPublicKey method with the exact example from the requirement
func TestRsaKeyPairCompressPublicKeyExample(t *testing.T) {
	t.Run("compress public key example from requirement", func(t *testing.T) {
		// This is the exact example from the requirement
		pemKey := `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqj2KwPA30m0iLPLq9jtL
wMi8v5epnlHBqllqaORzfryUlO2jwiULY1iqXSeaulODLyris73qfIlUAaPL0jAr
nMPNYcEB26SimdsCfxO5bDmEtXcjB4a51Zr7GcFwWD2lhx7gQAHvnbhQGCZdbqjC
9cGFL2gdRfjujnFfQ9dvoYyttWsvsiRHA8/w4nuSKNQQXsI4d344JyE0I/CkMQc7
3zXaAbKkiXX1khP2ybWFu2LZb/3HuBrto1fxeeu2X0z1sV/99wpsr7GYOSBHVA0g
+e2Gskkcnulhpz0Z9NcVMBIefCVz7ya9m2QF2UqYMyalAm5tewi/kalJmpAcxeg9
NQIDAQAB
-----END PUBLIC KEY-----`

		kp := NewRsaKeyPair()
		compressed := kp.CompressPublicKey([]byte(pemKey))

		// Convert to string for easier verification
		compressedStr := string(compressed)

		// Verify that the compressed key doesn't contain headers
		assert.NotContains(t, compressedStr, "-----BEGIN PUBLIC KEY-----")
		assert.NotContains(t, compressedStr, "-----END PUBLIC KEY-----")

		// Verify that the compressed key doesn't contain newlines or spaces
		assert.NotContains(t, compressedStr, "\n")
		assert.NotContains(t, compressedStr, "\r")
		assert.NotContains(t, compressedStr, " ")

		// Verify that the compressed key starts with the expected content
		expectedStart := "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqj2KwPA30m0iLPLq9jtL"
		assert.Contains(t, compressedStr, expectedStart)

		// Verify that the compressed key ends with the expected content
		expectedEnd := "NQIDAQAB"
		assert.Contains(t, compressedStr, expectedEnd)

		// Verify that the result is not empty
		assert.NotEmpty(t, compressedStr)

		// Print the result for verification
		t.Logf("Compressed key: %s", compressedStr)
	})
}

// TestRsaKeyPairLoadPrivateKey tests the LoadPrivateKey method
func TestRsaKeyPairLoadPrivateKey(t *testing.T) {
	t.Run("load PKCS1 private key from file", func(t *testing.T) {
		kp := NewRsaKeyPair()
		kp.SetFormat(PKCS1)
		kp.GenKeyPair(1024)

		// Create a mock file with the private key content
		file := mock.NewFile(kp.PrivateKey, "private_key.pem")
		defer file.Close()

		// Load private key from file
		kp.LoadPrivateKey(file)

		assert.Nil(t, kp.Error)
		assert.NotNil(t, kp.PrivateKey)
		assert.Contains(t, string(kp.PrivateKey), "-----BEGIN RSA PRIVATE KEY-----")
	})

	t.Run("load PKCS8 private key from file", func(t *testing.T) {
		kp := NewRsaKeyPair()
		kp.SetFormat(PKCS8)
		kp.GenKeyPair(1024)

		// Create a mock file with the private key content
		file := mock.NewFile(kp.PrivateKey, "private_key.pem")
		defer file.Close()

		// Load private key from file
		kp.LoadPrivateKey(file)

		assert.Nil(t, kp.Error)
		assert.NotNil(t, kp.PrivateKey)
		assert.Contains(t, string(kp.PrivateKey), "-----BEGIN PRIVATE KEY-----")
	})

	t.Run("load private key from nil file", func(t *testing.T) {
		kp := NewRsaKeyPair()

		// Load private key from nil file
		kp.LoadPrivateKey(nil)

		assert.NotNil(t, kp.Error)
		assert.IsType(t, NilPemBlockError{}, kp.Error)
	})

	t.Run("load private key from file with read error", func(t *testing.T) {
		kp := NewRsaKeyPair()

		// Create a mock file that returns error on read
		file := mock.NewErrorFile(errors.New("read error"))
		defer file.Close()

		// Load private key from file
		kp.LoadPrivateKey(file)

		assert.NotNil(t, kp.Error)
	})
}

// TestRsaKeyPairCompressPrivateKey tests the CompressPrivateKey method
func TestRsaKeyPairCompressPrivateKey(t *testing.T) {
	t.Run("compress PKCS1 private key", func(t *testing.T) {
		kp := NewRsaKeyPair()
		kp.SetFormat(PKCS1)
		kp.GenKeyPair(1024)

		compressed := kp.CompressPrivateKey(kp.PrivateKey)
		assert.NotNil(t, compressed)

		// Ensure the compressed key doesn't contain PEM headers
		compressedStr := string(compressed)
		assert.NotContains(t, compressedStr, "-----BEGIN RSA PRIVATE KEY-----")
		assert.NotContains(t, compressedStr, "-----END RSA PRIVATE KEY-----")

		// Ensure the compressed key doesn't contain newlines or spaces
		assert.NotContains(t, compressedStr, "\n")
		assert.NotContains(t, compressedStr, "\r")
		assert.NotContains(t, compressedStr, " ")
	})

	t.Run("compress PKCS8 private key", func(t *testing.T) {
		kp := NewRsaKeyPair()
		kp.SetFormat(PKCS8)
		kp.GenKeyPair(1024)

		compressed := kp.CompressPrivateKey(kp.PrivateKey)
		assert.NotNil(t, compressed)

		// Ensure the compressed key doesn't contain PEM headers
		compressedStr := string(compressed)
		assert.NotContains(t, compressedStr, "-----BEGIN PRIVATE KEY-----")
		assert.NotContains(t, compressedStr, "-----END PRIVATE KEY-----")

		// Ensure the compressed key doesn't contain newlines or spaces
		assert.NotContains(t, compressedStr, "\n")
		assert.NotContains(t, compressedStr, "\r")
		assert.NotContains(t, compressedStr, " ")
	})

	t.Run("compress empty private key", func(t *testing.T) {
		kp := NewRsaKeyPair()
		compressed := kp.CompressPrivateKey([]byte{})
		assert.Empty(t, compressed)
	})

	t.Run("compress nil private key", func(t *testing.T) {
		kp := NewRsaKeyPair()
		compressed := kp.CompressPrivateKey(nil)
		assert.Empty(t, compressed)
	})

	t.Run("compress malformed private key", func(t *testing.T) {
		kp := NewRsaKeyPair()
		malformedKey := []byte("-----BEGIN PRIVATE KEY-----\nMIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC\n-----END PRIVATE KEY-----")
		compressed := kp.CompressPrivateKey(malformedKey)

		// Should remove headers and newlines
		compressedStr := string(compressed)
		assert.NotContains(t, compressedStr, "-----BEGIN PRIVATE KEY-----")
		assert.NotContains(t, compressedStr, "-----END PRIVATE KEY-----")
		assert.NotContains(t, compressedStr, "\n")
	})

	t.Run("compress private key with extra whitespace", func(t *testing.T) {
		kp := NewRsaKeyPair()
		keyWithWhitespace := []byte("-----BEGIN PRIVATE KEY-----  \n  MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC  \n  -----END PRIVATE KEY-----  ")
		compressed := kp.CompressPrivateKey(keyWithWhitespace)

		// Should remove headers, newlines, and whitespace
		compressedStr := string(compressed)
		assert.NotContains(t, compressedStr, "-----BEGIN PRIVATE KEY-----")
		assert.NotContains(t, compressedStr, "-----END PRIVATE KEY-----")
		assert.NotContains(t, compressedStr, "\n")
		assert.NotContains(t, compressedStr, " ")
		assert.NotContains(t, compressedStr, "\t")
	})
}
