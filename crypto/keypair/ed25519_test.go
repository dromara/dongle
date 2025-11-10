package keypair

import (
	stdRand "crypto/rand"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestNewEd25519KeyPair tests the NewEd25519KeyPair function
func TestNewEd25519KeyPair(t *testing.T) {
	t.Run("create new ED25519 key pair", func(t *testing.T) {
		kp := NewEd25519KeyPair()
		assert.NotNil(t, kp)
		assert.Nil(t, kp.PublicKey)
		assert.Nil(t, kp.PrivateKey)
	})
}

// TestEd25519KeyPairGenKeyPair tests the GenKeyPair method
func TestEd25519KeyPairGenKeyPair(t *testing.T) {
	t.Run("generate ED25519 key pair", func(t *testing.T) {
		kp := NewEd25519KeyPair()
		kp.GenKeyPair()

		assert.NotNil(t, kp.PublicKey)
		assert.NotNil(t, kp.PrivateKey)
		assert.Contains(t, string(kp.PublicKey), "-----BEGIN PUBLIC KEY-----")
		assert.Contains(t, string(kp.PrivateKey), "-----BEGIN PRIVATE KEY-----")
	})

	t.Run("generate ED25519 key pair with rand error", func(t *testing.T) {
		// Override crypto/rand.Reader only within this process to trigger error path
		old := stdRand.Reader
		defer func() { stdRand.Reader = old }()
		stdRand.Reader = badReader{}

		kp := NewEd25519KeyPair()
		err := kp.GenKeyPair()
		assert.Error(t, err)
		assert.Nil(t, kp.PublicKey)
		assert.Nil(t, kp.PrivateKey)
	})
}

// badReader always returns an error to trigger ed25519.GenerateKey failure
type badReader struct{}

func (badReader) Read(p []byte) (int, error) { return 0, errors.New("rand read error") }

// TestEd25519KeyPairSetPublicKey tests the SetPublicKey method
func TestEd25519KeyPairSetPublicKey(t *testing.T) {
	t.Run("set public key from body", func(t *testing.T) {
		kp := NewEd25519KeyPair()
		kp.GenKeyPair()

		body := kp.CompressPublicKey(kp.PublicKey)
		err := kp.SetPublicKey(body)
		assert.NoError(t, err)
		assert.NotNil(t, kp.PublicKey)
		assert.Contains(t, string(kp.PublicKey), "-----BEGIN PUBLIC KEY-----")
	})

	t.Run("set empty public key", func(t *testing.T) {
		kp := NewEd25519KeyPair()
		err := kp.SetPublicKey([]byte{})
		assert.Error(t, err)
		assert.IsType(t, EmptyPublicKeyError{}, err)
		assert.Equal(t, "public key cannot be empty", err.Error())
		assert.Empty(t, kp.PublicKey)
	})

	t.Run("set invalid base64 public key", func(t *testing.T) {
		kp := NewEd25519KeyPair()
		err := kp.SetPublicKey([]byte("!not-base64!"))
		assert.Error(t, err)
		assert.IsType(t, InvalidPublicKeyError{}, err)
		assert.Empty(t, kp.PublicKey)
	})
}

// TestEd25519KeyPairSetPrivateKey tests the SetPrivateKey method
func TestEd25519KeyPairSetPrivateKey(t *testing.T) {
	t.Run("set private key from body", func(t *testing.T) {
		kp := NewEd25519KeyPair()
		kp.GenKeyPair()

		body := kp.CompressPrivateKey(kp.PrivateKey)
		err := kp.SetPrivateKey(body)
		assert.NoError(t, err)
		assert.NotNil(t, kp.PrivateKey)
		assert.Contains(t, string(kp.PrivateKey), "-----BEGIN PRIVATE KEY-----")
	})

	t.Run("set empty private key", func(t *testing.T) {
		kp := NewEd25519KeyPair()
		err := kp.SetPrivateKey([]byte{})
		assert.Error(t, err)
		assert.IsType(t, EmptyPrivateKeyError{}, err)
		assert.Equal(t, "private key cannot be empty", err.Error())
		assert.Empty(t, kp.PrivateKey)
	})

	t.Run("set invalid base64 private key", func(t *testing.T) {
		kp := NewEd25519KeyPair()
		err := kp.SetPrivateKey([]byte("!not-base64!"))
		assert.Error(t, err)
		assert.IsType(t, InvalidPrivateKeyError{}, err)
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
		assert.IsType(t, EmptyPublicKeyError{}, err)
		assert.Equal(t, "public key cannot be empty", err.Error())
		assert.Nil(t, pub)
	})

	t.Run("parse invalid public key", func(t *testing.T) {
		kp := NewEd25519KeyPair()
		kp.PublicKey = []byte("invalid key")
		pub, err := kp.ParsePublicKey()
		assert.NotNil(t, err)
		assert.IsType(t, InvalidPublicKeyError{}, err)
		assert.Nil(t, pub)
	})

	t.Run("parse corrupted public key", func(t *testing.T) {
		kp := NewEd25519KeyPair()
		kp.PublicKey = []byte(`-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAinvalid
-----END PUBLIC KEY-----`)
		pub, err := kp.ParsePublicKey()
		assert.NotNil(t, err)
		assert.IsType(t, InvalidPublicKeyError{}, err)
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
		assert.Error(t, err)
		assert.IsType(t, UnsupportedPemTypeError{}, err)
		assert.Equal(t, "unsupported pem block type", err.Error())
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
		assert.IsType(t, EmptyPrivateKeyError{}, err)
		assert.Equal(t, "private key cannot be empty", err.Error())
		assert.Nil(t, pri)
	})

	t.Run("parse invalid private key", func(t *testing.T) {
		kp := NewEd25519KeyPair()
		kp.PrivateKey = []byte("invalid key")
		pri, err := kp.ParsePrivateKey()
		assert.NotNil(t, err)
		assert.IsType(t, InvalidPrivateKeyError{}, err)
		assert.Nil(t, pri)
	})

	t.Run("parse corrupted private key", func(t *testing.T) {
		kp := NewEd25519KeyPair()
		kp.PrivateKey = []byte(`-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIN5invalid
-----END PRIVATE KEY-----`)
		pri, err := kp.ParsePrivateKey()
		assert.NotNil(t, err)
		assert.IsType(t, InvalidPrivateKeyError{}, err)
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
		assert.Error(t, err)
		assert.IsType(t, UnsupportedPemTypeError{}, err)
		assert.Equal(t, "unsupported pem block type", err.Error())
		assert.Nil(t, pri)
	})
}

// TestErrorTypes tests all error types to achieve 100% coverage
func TestErrorTypes(t *testing.T) {
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

// TestEd25519KeyPairFormatPublicKey tests the FormatPublicKey method
func TestEd25519KeyPairFormatPublicKey(t *testing.T) {
	t.Run("format valid public key body", func(t *testing.T) {
		kp := NewEd25519KeyPair()
		kp.GenKeyPair()

		body := kp.CompressPublicKey(kp.PublicKey)
		formatted, err := kp.FormatPublicKey(body)
		assert.NoError(t, err)
		assert.NotNil(t, formatted)
		assert.Contains(t, string(formatted), "-----BEGIN PUBLIC KEY-----")
	})

	t.Run("format empty public key body", func(t *testing.T) {
		kp := NewEd25519KeyPair()
		formatted, err := kp.FormatPublicKey([]byte{})
		assert.Error(t, err)
		assert.IsType(t, EmptyPublicKeyError{}, err)
		assert.Equal(t, "public key cannot be empty", err.Error())
		assert.Empty(t, formatted)
	})

	t.Run("format invalid base64 public key body", func(t *testing.T) {
		kp := NewEd25519KeyPair()
		formatted, err := kp.FormatPublicKey([]byte("!"))
		assert.Error(t, err)
		assert.IsType(t, InvalidPublicKeyError{}, err)
		assert.Empty(t, formatted)
	})
}

// TestEd25519KeyPairFormatPrivateKey tests the FormatPrivateKey method
func TestEd25519KeyPairFormatPrivateKey(t *testing.T) {
	t.Run("format valid private key body", func(t *testing.T) {
		kp := NewEd25519KeyPair()
		kp.GenKeyPair()

		body := kp.CompressPrivateKey(kp.PrivateKey)
		formatted, err := kp.FormatPrivateKey(body)
		assert.NoError(t, err)
		assert.NotNil(t, formatted)
		assert.Contains(t, string(formatted), "-----BEGIN PRIVATE KEY-----")
	})

	t.Run("format empty private key body", func(t *testing.T) {
		kp := NewEd25519KeyPair()
		formatted, err := kp.FormatPrivateKey([]byte{})
		assert.Error(t, err)
		assert.IsType(t, EmptyPrivateKeyError{}, err)
		assert.Equal(t, "private key cannot be empty", err.Error())
		assert.Empty(t, formatted)
	})

	t.Run("format invalid base64 private key body", func(t *testing.T) {
		kp := NewEd25519KeyPair()
		formatted, err := kp.FormatPrivateKey([]byte("!"))
		assert.Error(t, err)
		assert.IsType(t, InvalidPrivateKeyError{}, err)
		assert.Empty(t, formatted)
	})
}

// Test compress helpers
func TestEd25519_Compress(t *testing.T) {
	kp := NewEd25519KeyPair()
	kp.GenKeyPair()

	pubBody := kp.CompressPublicKey(kp.PublicKey)
	priBody := kp.CompressPrivateKey(kp.PrivateKey)
	assert.NotContains(t, string(pubBody), "BEGIN")
	assert.NotContains(t, string(pubBody), "\n")
	assert.NotContains(t, string(priBody), "BEGIN")
	assert.NotContains(t, string(priBody), "\n")
}
