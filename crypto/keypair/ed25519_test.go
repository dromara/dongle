package keypair

import (
	"errors"
	"testing"

	"github.com/dromara/dongle/mock"
	"github.com/stretchr/testify/assert"
)

// TestNewEd25519KeyPair tests the NewEd25519KeyPair function
func TestNewEd25519KeyPair(t *testing.T) {
	t.Run("create new ED25519 key pair", func(t *testing.T) {
		kp := NewEd25519KeyPair()
		assert.NotNil(t, kp)
		assert.Nil(t, kp.PublicKey)
		assert.Nil(t, kp.PrivateKey)
		assert.Nil(t, kp.Error)
	})
}

// TestEd25519KeyPairGenKeyPair tests the GenKeyPair method
func TestEd25519KeyPairGenKeyPair(t *testing.T) {
	t.Run("generate ED25519 key pair", func(t *testing.T) {
		kp := NewEd25519KeyPair()
		result := kp.GenKeyPair()

		assert.Equal(t, kp, result)
		assert.Nil(t, kp.Error)
		assert.NotNil(t, kp.PublicKey)
		assert.NotNil(t, kp.PrivateKey)
		assert.Contains(t, string(kp.PublicKey), "-----BEGIN PUBLIC KEY-----")
		assert.Contains(t, string(kp.PrivateKey), "-----BEGIN PRIVATE KEY-----")
	})

}

// TestEd25519KeyPairSetPublicKey tests the SetPublicKey method
func TestEd25519KeyPairSetPublicKey(t *testing.T) {
	t.Run("set public key", func(t *testing.T) {
		kp := NewEd25519KeyPair()
		kp.GenKeyPair()

		originalKey := kp.PublicKey
		kp.SetPublicKey(originalKey)

		assert.NotNil(t, kp.PublicKey)
		assert.Contains(t, string(kp.PublicKey), "-----BEGIN PUBLIC KEY-----")
	})

	t.Run("set empty public key", func(t *testing.T) {
		kp := NewEd25519KeyPair()
		kp.SetPublicKey([]byte{})

		assert.Empty(t, kp.PublicKey)
	})
}

// TestEd25519KeyPairSetPrivateKey tests the SetPrivateKey method
func TestEd25519KeyPairSetPrivateKey(t *testing.T) {
	t.Run("set private key", func(t *testing.T) {
		kp := NewEd25519KeyPair()
		kp.GenKeyPair()

		originalKey := kp.PrivateKey
		kp.SetPrivateKey(originalKey)

		assert.NotNil(t, kp.PrivateKey)
		assert.Contains(t, string(kp.PrivateKey), "-----BEGIN PRIVATE KEY-----")
	})

	t.Run("set empty private key", func(t *testing.T) {
		kp := NewEd25519KeyPair()
		kp.SetPrivateKey([]byte{})

		assert.Empty(t, kp.PrivateKey)
	})
}

// TestEd25519KeyPairParsePublicKey tests the ParsePublicKey method
func TestEd25519KeyPairParsePublicKey(t *testing.T) {
	t.Run("parse public key", func(t *testing.T) {
		kp := NewEd25519KeyPair()
		kp.GenKeyPair()

		pub, err := kp.ParsePublicKey()
		assert.Nil(t, err)
		assert.NotNil(t, pub)
	})

	t.Run("parse empty public key", func(t *testing.T) {
		kp := NewEd25519KeyPair()
		pub, err := kp.ParsePublicKey()
		assert.NotNil(t, err)
		assert.IsType(t, NilPemBlockError{}, err)
		assert.Nil(t, pub)
	})

	t.Run("parse invalid public key", func(t *testing.T) {
		kp := NewEd25519KeyPair()
		kp.PublicKey = []byte("invalid key")
		pub, err := kp.ParsePublicKey()
		assert.NotNil(t, err)
		assert.IsType(t, NilPemBlockError{}, err)
		assert.Nil(t, pub)
	})

	t.Run("parse corrupted public key", func(t *testing.T) {
		kp := NewEd25519KeyPair()
		kp.PublicKey = []byte(`-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAinvalid
-----END PUBLIC KEY-----`)
		pub, err := kp.ParsePublicKey()
		assert.NotNil(t, err)
		assert.IsType(t, NilPemBlockError{}, err)
		assert.Nil(t, pub)
	})

	t.Run("parse invalid public key data", func(t *testing.T) {
		kp := NewEd25519KeyPair()
		kp.PublicKey = []byte(`-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEANs0R/+1w1lk4sA==
-----END PUBLIC KEY-----`)
		pub, err := kp.ParsePublicKey()
		assert.NotNil(t, err)
		assert.IsType(t, InvalidPublicKeyError{}, err)
		assert.Nil(t, pub)
	})

	t.Run("parse unknown PEM block type", func(t *testing.T) {
		kp := NewEd25519KeyPair()
		kp.PublicKey = []byte(`-----BEGIN UNKNOWN KEY-----
MCowBQYDK2VwAyEA
-----END UNKNOWN KEY-----`)
		pub, err := kp.ParsePublicKey()
		assert.Nil(t, err) // Should return nil without error for unknown types
		assert.Nil(t, pub)
	})
}

// TestEd25519KeyPairParsePrivateKey tests the ParsePrivateKey method
func TestEd25519KeyPairParsePrivateKey(t *testing.T) {
	t.Run("parse private key", func(t *testing.T) {
		kp := NewEd25519KeyPair()
		kp.GenKeyPair()

		pri, err := kp.ParsePrivateKey()
		assert.Nil(t, err)
		assert.NotNil(t, pri)
	})

	t.Run("parse empty private key", func(t *testing.T) {
		kp := NewEd25519KeyPair()
		pri, err := kp.ParsePrivateKey()
		assert.NotNil(t, err)
		assert.IsType(t, NilPemBlockError{}, err)
		assert.Nil(t, pri)
	})

	t.Run("parse invalid private key", func(t *testing.T) {
		kp := NewEd25519KeyPair()
		kp.PrivateKey = []byte("invalid key")
		pri, err := kp.ParsePrivateKey()
		assert.NotNil(t, err)
		assert.IsType(t, NilPemBlockError{}, err)
		assert.Nil(t, pri)
	})

	t.Run("parse corrupted private key", func(t *testing.T) {
		kp := NewEd25519KeyPair()
		kp.PrivateKey = []byte(`-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIN5invalid
-----END PRIVATE KEY-----`)
		pri, err := kp.ParsePrivateKey()
		assert.NotNil(t, err)
		assert.IsType(t, NilPemBlockError{}, err)
		assert.Nil(t, pri)
	})

	t.Run("parse invalid private key data", func(t *testing.T) {
		kp := NewEd25519KeyPair()
		kp.PrivateKey = []byte(`-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIA1SoqzUlXOe
-----END PRIVATE KEY-----`)
		pri, err := kp.ParsePrivateKey()
		assert.NotNil(t, err)
		assert.IsType(t, InvalidPrivateKeyError{}, err)
		assert.Nil(t, pri)
	})

	t.Run("parse unknown PEM block type for private key", func(t *testing.T) {
		kp := NewEd25519KeyPair()
		kp.PrivateKey = []byte(`-----BEGIN UNKNOWN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIA1SoqzUlXOeBM9hQXp/Ow58v6N+15FwXByUhfFSRJ2J
-----END UNKNOWN PRIVATE KEY-----`)
		pri, err := kp.ParsePrivateKey()
		assert.Nil(t, err) // Should return nil without error for unknown types
		assert.Nil(t, pri)
	})
}

// TestEd25519KeyPairLoadPublicKey tests the LoadPublicKey method
func TestEd25519KeyPairLoadPublicKey(t *testing.T) {
	t.Run("load public key from file", func(t *testing.T) {
		kp := NewEd25519KeyPair()
		kp.GenKeyPair()

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
		kp := NewEd25519KeyPair()

		// Load public key from nil file
		kp.LoadPublicKey(nil)

		assert.NotNil(t, kp.Error)
		assert.IsType(t, NilPemBlockError{}, kp.Error)
	})

	t.Run("load public key from file with read error", func(t *testing.T) {
		kp := NewEd25519KeyPair()

		// Create a mock file that returns error on read
		file := mock.NewErrorFile(errors.New("read error"))
		defer file.Close()

		// Load public key from file
		kp.LoadPublicKey(file)

		assert.NotNil(t, kp.Error)
	})
}

// TestEd25519KeyPairLoadPrivateKey tests the LoadPrivateKey method
func TestEd25519KeyPairLoadPrivateKey(t *testing.T) {
	t.Run("load private key from file", func(t *testing.T) {
		kp := NewEd25519KeyPair()
		kp.GenKeyPair()

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
		kp := NewEd25519KeyPair()

		// Load private key from nil file
		kp.LoadPrivateKey(nil)

		assert.NotNil(t, kp.Error)
		assert.IsType(t, NilPemBlockError{}, kp.Error)
	})

	t.Run("load private key from file with read error", func(t *testing.T) {
		kp := NewEd25519KeyPair()

		// Create a mock file that returns error on read
		file := mock.NewErrorFile(errors.New("read error"))
		defer file.Close()

		// Load private key from file
		kp.LoadPrivateKey(file)

		assert.NotNil(t, kp.Error)
	})
}

// TestErrorTypes tests all error types to achieve 100% coverage
func TestErrorTypes(t *testing.T) {
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

// TestEd25519KeyPairCompressPublicKey tests the CompressPublicKey method
func TestEd25519KeyPairCompressPublicKey(t *testing.T) {
	t.Run("compress PKCS8 public key", func(t *testing.T) {
		kp := NewEd25519KeyPair()
		kp.GenKeyPair()

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
		kp := NewEd25519KeyPair()
		compressed := kp.CompressPublicKey([]byte{})
		assert.Empty(t, compressed)
	})

	t.Run("compress nil public key", func(t *testing.T) {
		kp := NewEd25519KeyPair()
		compressed := kp.CompressPublicKey(nil)
		assert.Empty(t, compressed)
	})

	t.Run("compress malformed public key", func(t *testing.T) {
		kp := NewEd25519KeyPair()
		malformedKey := []byte("-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEANs0R/+1w1lk4sA==\n-----END PUBLIC KEY-----")
		compressed := kp.CompressPublicKey(malformedKey)

		// Should remove headers and newlines
		compressedStr := string(compressed)
		assert.NotContains(t, compressedStr, "-----BEGIN PUBLIC KEY-----")
		assert.NotContains(t, compressedStr, "-----END PUBLIC KEY-----")
		assert.NotContains(t, compressedStr, "\n")
	})

	t.Run("compress public key with extra whitespace", func(t *testing.T) {
		kp := NewEd25519KeyPair()
		keyWithWhitespace := []byte("-----BEGIN PUBLIC KEY-----  \n  MCowBQYDK2VwAyEANs0R/+1w1lk4sA==  \n  -----END PUBLIC KEY-----  ")
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

// TestEd25519KeyPairCompressPrivateKey tests the CompressPrivateKey method
func TestEd25519KeyPairCompressPrivateKey(t *testing.T) {
	t.Run("compress PKCS8 private key", func(t *testing.T) {
		kp := NewEd25519KeyPair()
		kp.GenKeyPair()

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
		kp := NewEd25519KeyPair()
		compressed := kp.CompressPrivateKey([]byte{})
		assert.Empty(t, compressed)
	})

	t.Run("compress nil private key", func(t *testing.T) {
		kp := NewEd25519KeyPair()
		compressed := kp.CompressPrivateKey(nil)
		assert.Empty(t, compressed)
	})

	t.Run("compress malformed private key", func(t *testing.T) {
		kp := NewEd25519KeyPair()
		malformedKey := []byte("-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIN5invalid\n-----END PRIVATE KEY-----")
		compressed := kp.CompressPrivateKey(malformedKey)

		// Should remove headers and newlines
		compressedStr := string(compressed)
		assert.NotContains(t, compressedStr, "-----BEGIN PRIVATE KEY-----")
		assert.NotContains(t, compressedStr, "-----END PRIVATE KEY-----")
		assert.NotContains(t, compressedStr, "\n")
	})

	t.Run("compress private key with extra whitespace", func(t *testing.T) {
		kp := NewEd25519KeyPair()
		keyWithWhitespace := []byte("-----BEGIN PRIVATE KEY-----  \n  MC4CAQAwBQYDK2VwBCIEIN5invalid  \n  -----END PRIVATE KEY-----  ")
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

// TestEd25519KeyPairFormatPublicKey tests the FormatPublicKey method
func TestEd25519KeyPairFormatPublicKey(t *testing.T) {
	t.Run("format valid public key", func(t *testing.T) {
		kp := NewEd25519KeyPair()
		kp.GenKeyPair()

		// Create a simple test key body
		testKeyBody := []byte("test public key body")

		formatted := kp.FormatPublicKey(testKeyBody)
		assert.NotNil(t, formatted)
		assert.Contains(t, string(formatted), "-----BEGIN PUBLIC KEY-----")
		assert.Contains(t, string(formatted), "-----END PUBLIC KEY-----")
	})

	t.Run("format empty public key", func(t *testing.T) {
		kp := NewEd25519KeyPair()
		formatted := kp.FormatPublicKey([]byte{})
		assert.Empty(t, formatted)
	})

	t.Run("format nil public key", func(t *testing.T) {
		kp := NewEd25519KeyPair()
		formatted := kp.FormatPublicKey(nil)
		assert.Empty(t, formatted)
	})
}

// TestEd25519KeyPairFormatPrivateKey tests the FormatPrivateKey method
func TestEd25519KeyPairFormatPrivateKey(t *testing.T) {
	t.Run("format valid private key", func(t *testing.T) {
		kp := NewEd25519KeyPair()
		kp.GenKeyPair()

		// Create a simple test key body
		testKeyBody := []byte("test private key body")

		formatted := kp.FormatPrivateKey(testKeyBody)
		assert.NotNil(t, formatted)
		assert.Contains(t, string(formatted), "-----BEGIN PRIVATE KEY-----")
		assert.Contains(t, string(formatted), "-----END PRIVATE KEY-----")
	})

	t.Run("format empty private key", func(t *testing.T) {
		kp := NewEd25519KeyPair()
		formatted := kp.FormatPrivateKey([]byte{})
		assert.Empty(t, formatted)
	})

	t.Run("format nil private key", func(t *testing.T) {
		kp := NewEd25519KeyPair()
		formatted := kp.FormatPrivateKey(nil)
		assert.Empty(t, formatted)
	})
}
