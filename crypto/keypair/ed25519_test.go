package keypair

import (
	stdRand "crypto/rand"
	"errors"
	"testing"

	"github.com/dromara/dongle/internal/mock"
	"github.com/stretchr/testify/assert"
)

func TestNewEd25519KeyPair(t *testing.T) {
	kp := NewEd25519KeyPair()
	assert.NotNil(t, kp)
	assert.Nil(t, kp.PublicKey)
	assert.Nil(t, kp.PrivateKey)
}

func TestEd25519KeyPairGenKeyPair(t *testing.T) {
	t.Run("generate key pair", func(t *testing.T) {
		kp := NewEd25519KeyPair()
		kp.GenKeyPair()

		assert.NotNil(t, kp.PublicKey)
		assert.NotNil(t, kp.PrivateKey)
		assert.Contains(t, string(kp.PublicKey), "-----BEGIN PUBLIC KEY-----")
		assert.Contains(t, string(kp.PrivateKey), "-----BEGIN PRIVATE KEY-----")
	})

	t.Run("generate with rand error", func(t *testing.T) {
		old := stdRand.Reader
		defer func() { stdRand.Reader = old }()
		stdRand.Reader = mock.NewErrorReadWriteCloser(errors.New("rand read error"))

		kp := NewEd25519KeyPair()
		err := kp.GenKeyPair()
		assert.Error(t, err)
		assert.Nil(t, kp.PublicKey)
		assert.Nil(t, kp.PrivateKey)
	})
}

func TestEd25519KeyPairSetPublicKey(t *testing.T) {
	t.Run("set from body", func(t *testing.T) {
		kp := NewEd25519KeyPair()
		kp.GenKeyPair()

		body := kp.CompressPublicKey(kp.PublicKey)
		err := kp.SetPublicKey(body)
		assert.NoError(t, err)
		assert.NotNil(t, kp.PublicKey)
		assert.Contains(t, string(kp.PublicKey), "-----BEGIN PUBLIC KEY-----")
	})

	t.Run("set empty", func(t *testing.T) {
		kp := NewEd25519KeyPair()
		err := kp.SetPublicKey([]byte{})
		assert.Error(t, err)
		assert.IsType(t, EmptyPublicKeyError{}, err)
		assert.Empty(t, kp.PublicKey)
	})

	t.Run("set invalid base64", func(t *testing.T) {
		kp := NewEd25519KeyPair()
		err := kp.SetPublicKey([]byte("!not-base64!"))
		assert.Error(t, err)
		assert.IsType(t, InvalidPublicKeyError{}, err)
		assert.Empty(t, kp.PublicKey)
	})
}

func TestEd25519KeyPairSetPrivateKey(t *testing.T) {
	t.Run("set from body", func(t *testing.T) {
		kp := NewEd25519KeyPair()
		kp.GenKeyPair()

		body := kp.CompressPrivateKey(kp.PrivateKey)
		err := kp.SetPrivateKey(body)
		assert.NoError(t, err)
		assert.NotNil(t, kp.PrivateKey)
		assert.Contains(t, string(kp.PrivateKey), "-----BEGIN PRIVATE KEY-----")
	})

	t.Run("set empty", func(t *testing.T) {
		kp := NewEd25519KeyPair()
		err := kp.SetPrivateKey([]byte{})
		assert.Error(t, err)
		assert.IsType(t, EmptyPrivateKeyError{}, err)
		assert.Empty(t, kp.PrivateKey)
	})

	t.Run("set invalid base64", func(t *testing.T) {
		kp := NewEd25519KeyPair()
		err := kp.SetPrivateKey([]byte("!not-base64!"))
		assert.Error(t, err)
		assert.IsType(t, InvalidPrivateKeyError{}, err)
		assert.Empty(t, kp.PrivateKey)
	})
}

func TestEd25519KeyPairParsePublicKey(t *testing.T) {
	t.Run("parse valid", func(t *testing.T) {
		kp := NewEd25519KeyPair()
		err := kp.GenKeyPair()
		assert.NoError(t, err)

		pub, err := kp.ParsePublicKey()
		assert.NoError(t, err)
		assert.NotNil(t, pub)
		assert.Equal(t, 32, len(pub))
	})

	t.Run("parse empty", func(t *testing.T) {
		kp := NewEd25519KeyPair()
		pub, err := kp.ParsePublicKey()
		assert.NotNil(t, err)
		assert.IsType(t, EmptyPublicKeyError{}, err)
		assert.Nil(t, pub)
	})

	t.Run("parse invalid PEM", func(t *testing.T) {
		kp := NewEd25519KeyPair()
		kp.PublicKey = []byte("invalid key")
		pub, err := kp.ParsePublicKey()
		assert.NotNil(t, err)
		assert.IsType(t, InvalidPublicKeyError{}, err)
		assert.Nil(t, pub)
	})

	t.Run("parse corrupted key with invalid DER", func(t *testing.T) {
		kp := NewEd25519KeyPair()
		kp.PublicKey = []byte(`-----BEGIN PUBLIC KEY-----
aW52YWxpZCBkZXIgZGF0YQ==
-----END PUBLIC KEY-----`)
		pub, err := kp.ParsePublicKey()
		assert.NotNil(t, err)
		assert.IsType(t, InvalidPublicKeyError{}, err)
		assert.Nil(t, pub)
	})

	t.Run("parse unknown block type", func(t *testing.T) {
		kp := NewEd25519KeyPair()
		kp.PublicKey = []byte(`-----BEGIN UNKNOWN KEY-----
MCowBQYDK2VwAyEA
-----END UNKNOWN KEY-----`)
		pub, err := kp.ParsePublicKey()
		assert.Error(t, err)
		assert.IsType(t, UnsupportedKeyFormatError{}, err)
		assert.Nil(t, pub)
	})
}

func TestEd25519KeyPairParsePrivateKey(t *testing.T) {
	t.Run("parse valid", func(t *testing.T) {
		kp := NewEd25519KeyPair()
		err := kp.GenKeyPair()
		assert.NoError(t, err)

		pri, err := kp.ParsePrivateKey()
		assert.NoError(t, err)
		assert.NotNil(t, pri)
		assert.Equal(t, 64, len(pri))
	})

	t.Run("parse empty", func(t *testing.T) {
		kp := NewEd25519KeyPair()
		pri, err := kp.ParsePrivateKey()
		assert.NotNil(t, err)
		assert.IsType(t, EmptyPrivateKeyError{}, err)
		assert.Nil(t, pri)
	})

	t.Run("parse invalid PEM", func(t *testing.T) {
		kp := NewEd25519KeyPair()
		kp.PrivateKey = []byte("invalid key")
		pri, err := kp.ParsePrivateKey()
		assert.NotNil(t, err)
		assert.IsType(t, InvalidPrivateKeyError{}, err)
		assert.Nil(t, pri)
	})

	t.Run("parse corrupted key with invalid DER", func(t *testing.T) {
		kp := NewEd25519KeyPair()
		kp.PrivateKey = []byte(`-----BEGIN PRIVATE KEY-----
aW52YWxpZCBkZXIgZGF0YQ==
-----END PRIVATE KEY-----`)
		pri, err := kp.ParsePrivateKey()
		assert.NotNil(t, err)
		assert.IsType(t, InvalidPrivateKeyError{}, err)
		assert.Nil(t, pri)
	})

	t.Run("parse unknown block type", func(t *testing.T) {
		kp := NewEd25519KeyPair()
		kp.PrivateKey = []byte(`-----BEGIN UNKNOWN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIA1SoqzUlXOeBM9hQXp/Ow58v6N+15FwXByUhfFSRJ2J
-----END UNKNOWN PRIVATE KEY-----`)
		pri, err := kp.ParsePrivateKey()
		assert.Error(t, err)
		assert.IsType(t, UnsupportedKeyFormatError{}, err)
		assert.Nil(t, pri)
	})
}

func TestEd25519KeyPairFormatPublicKey(t *testing.T) {
	t.Run("format valid body", func(t *testing.T) {
		kp := NewEd25519KeyPair()
		kp.GenKeyPair()

		body := kp.CompressPublicKey(kp.PublicKey)
		formatted, err := kp.FormatPublicKey(body)
		assert.NoError(t, err)
		assert.NotNil(t, formatted)
		assert.Contains(t, string(formatted), "-----BEGIN PUBLIC KEY-----")
	})

	t.Run("format empty body", func(t *testing.T) {
		kp := NewEd25519KeyPair()
		formatted, err := kp.FormatPublicKey([]byte{})
		assert.Error(t, err)
		assert.IsType(t, EmptyPublicKeyError{}, err)
		assert.Empty(t, formatted)
	})

	t.Run("format invalid base64", func(t *testing.T) {
		kp := NewEd25519KeyPair()
		formatted, err := kp.FormatPublicKey([]byte("!"))
		assert.Error(t, err)
		assert.IsType(t, InvalidPublicKeyError{}, err)
		assert.Empty(t, formatted)
	})
}

func TestEd25519KeyPairFormatPrivateKey(t *testing.T) {
	t.Run("format valid body", func(t *testing.T) {
		kp := NewEd25519KeyPair()
		kp.GenKeyPair()

		body := kp.CompressPrivateKey(kp.PrivateKey)
		formatted, err := kp.FormatPrivateKey(body)
		assert.NoError(t, err)
		assert.NotNil(t, formatted)
		assert.Contains(t, string(formatted), "-----BEGIN PRIVATE KEY-----")
	})

	t.Run("format empty body", func(t *testing.T) {
		kp := NewEd25519KeyPair()
		formatted, err := kp.FormatPrivateKey([]byte{})
		assert.Error(t, err)
		assert.IsType(t, EmptyPrivateKeyError{}, err)
		assert.Empty(t, formatted)
	})

	t.Run("format invalid base64", func(t *testing.T) {
		kp := NewEd25519KeyPair()
		formatted, err := kp.FormatPrivateKey([]byte("!"))
		assert.Error(t, err)
		assert.IsType(t, InvalidPrivateKeyError{}, err)
		assert.Empty(t, formatted)
	})
}

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
