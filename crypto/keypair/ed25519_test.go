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

		assert.Nil(t, kp.PublicKey)
	})

	t.Run("set invalid public key", func(t *testing.T) {
		kp := NewEd25519KeyPair()
		kp.SetPublicKey([]byte("invalid key"))

		assert.Nil(t, kp.PublicKey)
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

		assert.Nil(t, kp.PrivateKey)
	})

	t.Run("set invalid private key", func(t *testing.T) {
		kp := NewEd25519KeyPair()
		kp.SetPrivateKey([]byte("invalid key"))

		assert.Nil(t, kp.PrivateKey)
	})
}

// TestEd25519KeyPairSetRawSign tests the SetRawSign method
func TestEd25519KeyPairSetRawSign(t *testing.T) {
	t.Run("set raw signature", func(t *testing.T) {
		kp := NewEd25519KeyPair()
		signature := []byte("test signature")
		kp.SetRawSign(signature)
		assert.Equal(t, signature, kp.Sign)
	})

	t.Run("set empty raw signature", func(t *testing.T) {
		kp := NewEd25519KeyPair()
		kp.SetRawSign([]byte{})
		assert.Equal(t, []byte{}, kp.Sign)
	})

	t.Run("set nil raw signature", func(t *testing.T) {
		kp := NewEd25519KeyPair()
		kp.SetRawSign(nil)
		assert.Nil(t, kp.Sign)
	})

	t.Run("overwrite existing signature with raw", func(t *testing.T) {
		kp := NewEd25519KeyPair()
		originalSignature := []byte("original signature")
		kp.SetRawSign(originalSignature)
		assert.Equal(t, originalSignature, kp.Sign)

		newSignature := []byte("new signature")
		kp.SetRawSign(newSignature)
		assert.Equal(t, newSignature, kp.Sign)
	})
}

// TestEd25519KeyPairSetHexSign tests the SetHexSign method
func TestEd25519KeyPairSetHexSign(t *testing.T) {
	t.Run("set hex signature", func(t *testing.T) {
		kp := NewEd25519KeyPair()
		hexSignature := []byte("74657374207369676e6174757265") // "test signature" in hex
		kp.SetHexSign(hexSignature)
		assert.Equal(t, []byte("test signature"), kp.Sign)
	})

	t.Run("set empty hex signature", func(t *testing.T) {
		kp := NewEd25519KeyPair()
		kp.SetHexSign([]byte{})
		assert.Equal(t, []byte{}, kp.Sign)
	})

	t.Run("overwrite existing signature with hex", func(t *testing.T) {
		kp := NewEd25519KeyPair()
		originalSignature := []byte("original signature")
		kp.Sign = originalSignature

		hexSignature := []byte("6e6577207369676e6174757265") // "new signature" in hex
		kp.SetHexSign(hexSignature)
		assert.Equal(t, []byte("new signature"), kp.Sign)
	})
}

// TestEd25519KeyPairSetBase64Sign tests the SetBase64Sign method
func TestEd25519KeyPairSetBase64Sign(t *testing.T) {
	t.Run("set base64 signature", func(t *testing.T) {
		kp := NewEd25519KeyPair()
		base64Signature := []byte("dGVzdCBzaWduYXR1cmU=") // "test signature" in base64
		kp.SetBase64Sign(base64Signature)
		assert.Equal(t, []byte("test signature"), kp.Sign)
	})

	t.Run("set empty base64 signature", func(t *testing.T) {
		kp := NewEd25519KeyPair()
		kp.SetBase64Sign([]byte{})
		assert.Equal(t, []byte{}, kp.Sign)
	})

	t.Run("overwrite existing signature with base64", func(t *testing.T) {
		kp := NewEd25519KeyPair()
		originalSignature := []byte("original signature")
		kp.Sign = originalSignature

		base64Signature := []byte("bmV3IHNpZ25hdHVyZQ==") // "new signature" in base64
		kp.SetBase64Sign(base64Signature)
		assert.Equal(t, []byte("new signature"), kp.Sign)
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
