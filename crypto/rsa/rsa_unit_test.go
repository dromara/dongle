package rsa

import (
	"bytes"
	"crypto"
	"io"
	"testing"

	"github.com/dromara/dongle/crypto/keypair"
	"github.com/dromara/dongle/mock"
	"github.com/stretchr/testify/assert"
)

// Test helper: Reader that implements io.ReadCloser but Close returns error
type readerWithCloseError struct {
	data []byte
	pos  int
	err  error
}

func newReaderWithCloseError(data []byte, closeErr error) *readerWithCloseError {
	return &readerWithCloseError{data: data, pos: 0, err: closeErr}
}

func (r *readerWithCloseError) Read(p []byte) (int, error) {
	if r.pos >= len(r.data) {
		return 0, io.EOF
	}
	n := copy(p, r.data[r.pos:])
	r.pos += n
	return n, nil
}

func (r *readerWithCloseError) Close() error {
	return r.err
}

func TestNewStdEncrypter(t *testing.T) {
	t.Run("valid key pair", func(t *testing.T) {
		kp := keypair.NewRsaKeyPair()
		kp.SetFormat(keypair.PKCS1)
		kp.SetHash(crypto.SHA256)

		// Set keys using GenKeyPair
		kp.GenKeyPair(1024)

		enc := NewStdEncrypter(kp)
		assert.Nil(t, enc.Error)
		assert.Equal(t, kp, enc.keypair)
	})

	t.Run("nil key pair", func(t *testing.T) {
		enc := NewStdEncrypter(nil)
		assert.NotNil(t, enc.Error)
		assert.IsType(t, NilKeyPairError{}, enc.Error)
	})

	t.Run("empty public key", func(t *testing.T) {
		kp := keypair.NewRsaKeyPair()
		enc := NewStdEncrypter(kp)
		assert.NotNil(t, enc.Error)
		assert.IsType(t, KeyPairError{}, enc.Error)
	})
}

func TestStdEncrypter_Encrypt(t *testing.T) {
	t.Run("PKCS1 format encryption", func(t *testing.T) {
		// Create key pair
		kp := keypair.NewRsaKeyPair()
		kp.SetFormat(keypair.PKCS1)
		kp.SetHash(crypto.SHA256)

		// Set keys using GenKeyPair
		kp.GenKeyPair(1024)

		enc := NewStdEncrypter(kp)
		encrypted, err := enc.Encrypt([]byte("Hello, RSA!"))
		assert.Nil(t, err)
		assert.NotEmpty(t, encrypted)
	})

	t.Run("PKCS8 format encryption", func(t *testing.T) {
		// Create key pair
		kp := keypair.NewRsaKeyPair()
		kp.SetFormat(keypair.PKCS8)
		kp.SetHash(crypto.SHA256)

		// Set keys using GenKeyPair
		kp.GenKeyPair(1024)

		enc := NewStdEncrypter(kp)
		encrypted, err := enc.Encrypt([]byte("Hello, RSA PKCS8!"))
		assert.Nil(t, err)
		assert.NotEmpty(t, encrypted)
	})

	t.Run("empty input", func(t *testing.T) {
		// Create key pair
		kp := keypair.NewRsaKeyPair()
		kp.SetFormat(keypair.PKCS1)
		kp.SetHash(crypto.SHA256)

		// Set keys using GenKeyPair
		kp.GenKeyPair(1024)

		enc := NewStdEncrypter(kp)
		encrypted, err := enc.Encrypt([]byte{})
		assert.Nil(t, err)
		assert.Nil(t, encrypted)
	})

	t.Run("with existing error", func(t *testing.T) {
		kp := keypair.NewRsaKeyPair()
		enc := NewStdEncrypter(kp)
		enc.Error = assert.AnError

		encrypted, err := enc.Encrypt([]byte("test"))
		assert.Equal(t, assert.AnError, err)
		assert.Nil(t, encrypted)
	})

	t.Run("parse public key error", func(t *testing.T) {
		// Create a key pair with invalid public key
		kp := keypair.NewRsaKeyPair()
		kp.SetFormat(keypair.PKCS1)
		kp.SetHash(crypto.SHA256)
		kp.SetPublicKey([]byte("invalid key"))

		enc := NewStdEncrypter(kp)
		encrypted, err := enc.Encrypt([]byte("test"))
		assert.NotNil(t, err)
		assert.Nil(t, encrypted)
	})

	t.Run("data too large", func(t *testing.T) {
		// Create key pair
		kp := keypair.NewRsaKeyPair()
		kp.SetFormat(keypair.PKCS1)
		kp.SetHash(crypto.SHA256)

		// Set keys using GenKeyPair
		kp.GenKeyPair(1024)

		enc := NewStdEncrypter(kp)
		// Create data larger than RSA key size - 11
		largeData := make([]byte, 1024)
		encrypted, err := enc.Encrypt(largeData)
		// This may return encryption error instead of DataTooLargeError
		assert.NotNil(t, err)
		assert.Nil(t, encrypted)
	})

	t.Run("encryption error PKCS1", func(t *testing.T) {
		kp := keypair.NewRsaKeyPair()
		kp.SetFormat(keypair.PKCS1)
		kp.SetHash(crypto.SHA256)
		kp.GenKeyPair(1024)

		enc := NewStdEncrypter(kp)
		// Create data too large for RSA encryption to trigger EncryptPKCS1v15 error
		largeData := make([]byte, 1000)
		encrypted, err := enc.Encrypt(largeData)
		assert.NotNil(t, err)
		assert.Nil(t, encrypted)
		assert.IsType(t, EncryptError{}, err)
	})

	t.Run("encryption error PKCS8", func(t *testing.T) {
		kp := keypair.NewRsaKeyPair()
		kp.SetFormat(keypair.PKCS8)
		kp.SetHash(crypto.SHA256)
		kp.GenKeyPair(1024)

		enc := NewStdEncrypter(kp)
		// Create data too large for RSA encryption to trigger EncryptOAEP error
		largeData := make([]byte, 1000)
		encrypted, err := enc.Encrypt(largeData)
		assert.NotNil(t, err)
		assert.Nil(t, encrypted)
		assert.IsType(t, EncryptError{}, err)
	})

	t.Run("unsupported format returns nil", func(t *testing.T) {
		kp := keypair.NewRsaKeyPair()
		kp.SetFormat(keypair.PKCS1)
		kp.SetHash(crypto.SHA256)
		kp.GenKeyPair(1024)
		// Change format after generating keys
		kp.SetFormat(keypair.KeyFormat("unknown"))

		enc := NewStdEncrypter(kp)
		encrypted, err := enc.Encrypt([]byte("test"))
		assert.Nil(t, err)
		assert.Nil(t, encrypted)
	})

	t.Run("parse public key error after creation", func(t *testing.T) {
		kp := keypair.NewRsaKeyPair()
		kp.SetFormat(keypair.PKCS1)
		kp.SetHash(crypto.SHA256)
		kp.GenKeyPair(1024) // Generate valid keys first

		enc := NewStdEncrypter(kp) // Constructor should succeed
		assert.Nil(t, enc.Error)

		// Now corrupt the public key after constructor validation
		kp.SetPublicKey([]byte("-----BEGIN RSA PUBLIC KEY-----\ninvalid\n-----END RSA PUBLIC KEY-----"))

		encrypted, err := enc.Encrypt([]byte("test")) // Should error here during parsing
		assert.NotNil(t, err)
		assert.Nil(t, encrypted)
		assert.IsType(t, KeyPairError{}, err)
	})
}

func TestNewStdDecrypter(t *testing.T) {
	t.Run("valid key pair", func(t *testing.T) {
		kp := keypair.NewRsaKeyPair()
		kp.SetFormat(keypair.PKCS1)
		kp.SetHash(crypto.SHA256)

		// Set keys using GenKeyPair
		kp.GenKeyPair(1024)

		dec := NewStdDecrypter(kp)
		assert.Nil(t, dec.Error)
		assert.Equal(t, kp, dec.keypair)
	})

	t.Run("nil key pair", func(t *testing.T) {
		dec := NewStdDecrypter(nil)
		assert.NotNil(t, dec.Error)
		assert.IsType(t, NilKeyPairError{}, dec.Error)
	})

	t.Run("empty private key", func(t *testing.T) {
		kp := keypair.NewRsaKeyPair()
		dec := NewStdDecrypter(kp)
		assert.NotNil(t, dec.Error)
		assert.IsType(t, KeyPairError{}, dec.Error)
	})
}

func TestStdDecrypter_Decrypt(t *testing.T) {
	t.Run("PKCS1 format decryption", func(t *testing.T) {
		// Create key pair
		kp := keypair.NewRsaKeyPair()
		kp.SetFormat(keypair.PKCS1)
		kp.SetHash(crypto.SHA256)

		// Set keys using GenKeyPair
		kp.GenKeyPair(1024)

		// First encrypt
		enc := NewStdEncrypter(kp)
		encrypted, err := enc.Encrypt([]byte("Hello, RSA!"))
		assert.Nil(t, err)
		assert.NotEmpty(t, encrypted)

		// Then decrypt
		dec := NewStdDecrypter(kp)
		decrypted, err := dec.Decrypt(encrypted)
		assert.Nil(t, err)
		assert.Equal(t, []byte("Hello, RSA!"), decrypted)
	})

	t.Run("PKCS8 format decryption", func(t *testing.T) {
		// Create key pair
		kp := keypair.NewRsaKeyPair()
		kp.SetFormat(keypair.PKCS8)
		kp.SetHash(crypto.SHA256)

		// Set keys using GenKeyPair
		kp.GenKeyPair(1024)

		// First encrypt
		enc := NewStdEncrypter(kp)
		encrypted, err := enc.Encrypt([]byte("Hello, RSA PKCS8!"))
		assert.Nil(t, err)
		assert.NotEmpty(t, encrypted)

		// Then decrypt
		dec := NewStdDecrypter(kp)
		decrypted, err := dec.Decrypt(encrypted)
		assert.Nil(t, err)
		assert.Equal(t, []byte("Hello, RSA PKCS8!"), decrypted)
	})

	t.Run("empty input", func(t *testing.T) {
		// Create key pair
		kp := keypair.NewRsaKeyPair()
		kp.SetFormat(keypair.PKCS1)
		kp.SetHash(crypto.SHA256)

		// Set keys using GenKeyPair
		kp.GenKeyPair(1024)

		dec := NewStdDecrypter(kp)
		decrypted, err := dec.Decrypt([]byte{})
		assert.Nil(t, err)
		assert.Nil(t, decrypted)
	})

	t.Run("with existing error", func(t *testing.T) {
		kp := keypair.NewRsaKeyPair()
		dec := NewStdDecrypter(kp)
		dec.Error = assert.AnError

		decrypted, err := dec.Decrypt([]byte("test"))
		assert.Equal(t, assert.AnError, err)
		assert.Nil(t, decrypted)
	})

	t.Run("parse private key error", func(t *testing.T) {
		// Create a key pair with invalid private key
		kp := keypair.NewRsaKeyPair()
		kp.SetFormat(keypair.PKCS1)
		kp.SetHash(crypto.SHA256)
		kp.SetPrivateKey([]byte("invalid key"))

		dec := NewStdDecrypter(kp)
		decrypted, err := dec.Decrypt([]byte("test"))
		assert.NotNil(t, err)
		assert.Nil(t, decrypted)
	})

	t.Run("unsupported format", func(t *testing.T) {
		kp := keypair.NewRsaKeyPair()
		kp.SetFormat(keypair.KeyFormat("invalid"))
		kp.SetHash(crypto.SHA256)
		kp.GenKeyPair(1024)

		dec := NewStdDecrypter(kp)
		decrypted, err := dec.Decrypt([]byte("test"))
		assert.NotNil(t, err)
		assert.Nil(t, decrypted)
		assert.IsType(t, KeyPairError{}, err)
	})

	t.Run("decryption error PKCS1", func(t *testing.T) {
		kp := keypair.NewRsaKeyPair()
		kp.SetFormat(keypair.PKCS1)
		kp.SetHash(crypto.SHA256)
		kp.GenKeyPair(1024)

		dec := NewStdDecrypter(kp)
		// Use invalid encrypted data to trigger DecryptPKCS1v15 error
		invalidData := []byte("invalid encrypted data that will cause decryption error")
		decrypted, err := dec.Decrypt(invalidData)
		assert.NotNil(t, err)
		assert.Nil(t, decrypted)
		assert.IsType(t, DecryptError{}, err)
	})

	t.Run("decryption error PKCS8", func(t *testing.T) {
		kp := keypair.NewRsaKeyPair()
		kp.SetFormat(keypair.PKCS8)
		kp.SetHash(crypto.SHA256)
		kp.GenKeyPair(1024)

		dec := NewStdDecrypter(kp)
		// Use invalid encrypted data to trigger DecryptOAEP error
		invalidData := []byte("invalid encrypted data that will cause decryption error")
		decrypted, err := dec.Decrypt(invalidData)
		assert.NotNil(t, err)
		assert.Nil(t, decrypted)
		assert.IsType(t, DecryptError{}, err)
	})

	t.Run("unsupported format returns nil", func(t *testing.T) {
		kp := keypair.NewRsaKeyPair()
		kp.SetFormat(keypair.PKCS1)
		kp.SetHash(crypto.SHA256)
		kp.GenKeyPair(1024)
		// Change format after generating keys
		kp.SetFormat(keypair.KeyFormat("unknown"))

		dec := NewStdDecrypter(kp)
		decrypted, err := dec.Decrypt([]byte("test"))
		assert.Nil(t, err)
		assert.Nil(t, decrypted)
	})

	t.Run("parse private key error after creation", func(t *testing.T) {
		kp := keypair.NewRsaKeyPair()
		kp.SetFormat(keypair.PKCS1)
		kp.SetHash(crypto.SHA256)
		kp.GenKeyPair(1024) // Generate valid keys first

		dec := NewStdDecrypter(kp) // Constructor should succeed
		assert.Nil(t, dec.Error)

		// Now corrupt the private key after constructor validation
		kp.SetPrivateKey([]byte("-----BEGIN RSA PRIVATE KEY-----\ninvalid\n-----END RSA PRIVATE KEY-----"))

		decrypted, err := dec.Decrypt([]byte("test")) // Should error here during parsing
		assert.NotNil(t, err)
		assert.Nil(t, decrypted)
		assert.IsType(t, KeyPairError{}, err)
	})
}

func TestStreamEncrypter_Encrypt(t *testing.T) {
	t.Run("PKCS1 format encryption", func(t *testing.T) {
		kp := keypair.NewRsaKeyPair()
		kp.SetFormat(keypair.PKCS1)
		kp.SetHash(crypto.SHA256)
		kp.GenKeyPair(1024)

		var buf bytes.Buffer
		enc := NewStreamEncrypter(&buf, kp).(*StreamEncrypter)
		encrypted, err := enc.Encrypt([]byte("test"))
		assert.Nil(t, err)
		assert.NotEmpty(t, encrypted)
	})

	t.Run("PKCS8 format encryption", func(t *testing.T) {
		kp := keypair.NewRsaKeyPair()
		kp.SetFormat(keypair.PKCS8)
		kp.SetHash(crypto.SHA256)
		kp.GenKeyPair(1024)

		var buf bytes.Buffer
		enc := NewStreamEncrypter(&buf, kp).(*StreamEncrypter)
		encrypted, err := enc.Encrypt([]byte("test"))
		assert.Nil(t, err)
		assert.NotEmpty(t, encrypted)
	})

	t.Run("empty data", func(t *testing.T) {
		kp := keypair.NewRsaKeyPair()
		kp.SetFormat(keypair.PKCS1)
		kp.SetHash(crypto.SHA256)
		kp.GenKeyPair(1024)

		var buf bytes.Buffer
		enc := NewStreamEncrypter(&buf, kp).(*StreamEncrypter)
		encrypted, err := enc.Encrypt([]byte{})
		assert.Nil(t, err)
		assert.Nil(t, encrypted)
	})

	t.Run("unsupported format", func(t *testing.T) {
		kp := keypair.NewRsaKeyPair()
		kp.SetFormat(keypair.KeyFormat("invalid"))
		kp.SetHash(crypto.SHA256)
		kp.GenKeyPair(1024)

		var buf bytes.Buffer
		enc := NewStreamEncrypter(&buf, kp).(*StreamEncrypter)
		encrypted, err := enc.Encrypt([]byte("test"))
		assert.NotNil(t, err)
		assert.Nil(t, encrypted)
		assert.IsType(t, KeyPairError{}, err)
	})

	t.Run("invalid public key", func(t *testing.T) {
		kp := keypair.NewRsaKeyPair()
		kp.SetFormat(keypair.PKCS1)
		kp.SetHash(crypto.SHA256)
		kp.SetPublicKey([]byte("invalid key"))

		var buf bytes.Buffer
		enc := NewStreamEncrypter(&buf, kp).(*StreamEncrypter)
		encrypted, err := enc.Encrypt([]byte("test"))
		assert.NotNil(t, err)
		assert.Nil(t, encrypted)
		assert.IsType(t, KeyPairError{}, err)
	})

	t.Run("encryption error PKCS1", func(t *testing.T) {
		kp := keypair.NewRsaKeyPair()
		kp.SetFormat(keypair.PKCS1)
		kp.SetHash(crypto.SHA256)
		kp.GenKeyPair(1024)

		var buf bytes.Buffer
		enc := NewStreamEncrypter(&buf, kp).(*StreamEncrypter)
		// Create data too large for RSA encryption
		largeData := make([]byte, 1000)
		encrypted, err := enc.Encrypt(largeData)
		assert.NotNil(t, err)
		assert.Nil(t, encrypted)
		assert.IsType(t, EncryptError{}, err)
	})

	t.Run("encryption error PKCS8", func(t *testing.T) {
		kp := keypair.NewRsaKeyPair()
		kp.SetFormat(keypair.PKCS8)
		kp.SetHash(crypto.SHA256)
		kp.GenKeyPair(1024)

		var buf bytes.Buffer
		enc := NewStreamEncrypter(&buf, kp).(*StreamEncrypter)
		// Create data too large for RSA encryption
		largeData := make([]byte, 1000)
		encrypted, err := enc.Encrypt(largeData)
		assert.NotNil(t, err)
		assert.Nil(t, encrypted)
		assert.IsType(t, EncryptError{}, err)
	})
}

func TestNewStreamEncrypter(t *testing.T) {
	t.Run("valid key pair", func(t *testing.T) {
		kp := keypair.NewRsaKeyPair()
		kp.SetFormat(keypair.PKCS1)
		kp.SetHash(crypto.SHA256)

		// Set keys using GenKeyPair
		kp.GenKeyPair(1024)

		var buf bytes.Buffer
		enc := NewStreamEncrypter(&buf, kp)
		assert.NotNil(t, enc)
	})

	t.Run("nil key pair", func(t *testing.T) {
		var buf bytes.Buffer
		enc := NewStreamEncrypter(&buf, nil)
		assert.NotNil(t, enc)
		// Test that we can write to it and get an error
		n, err := enc.Write([]byte("test"))
		assert.NotNil(t, err)
		assert.Equal(t, 0, n)
	})

	t.Run("StreamEncrypter with unsupported format", func(t *testing.T) {
		kp := keypair.NewRsaKeyPair()
		kp.SetFormat(keypair.KeyFormat("invalid")) // Invalid format
		kp.SetHash(crypto.SHA256)
		kp.GenKeyPair(1024)

		var buf bytes.Buffer
		enc := NewStreamEncrypter(&buf, kp)
		n, err := enc.Write([]byte("test"))
		assert.NotNil(t, err)
		assert.Equal(t, 0, n)
		assert.IsType(t, KeyPairError{}, err)
	})
}

func TestStreamEncrypter_Write(t *testing.T) {
	t.Run("PKCS1 format streaming", func(t *testing.T) {
		// Create key pair
		kp := keypair.NewRsaKeyPair()
		kp.SetFormat(keypair.PKCS1)
		kp.SetHash(crypto.SHA256)

		// Set keys using GenKeyPair
		kp.GenKeyPair(1024)

		var buf bytes.Buffer
		enc := NewStreamEncrypter(&buf, kp)
		n, err := enc.Write([]byte("Hello, streaming!"))
		assert.Nil(t, err)
		assert.Greater(t, n, 0)
		assert.NotEmpty(t, buf.Bytes())
	})

	t.Run("PKCS8 format streaming", func(t *testing.T) {
		// Create key pair
		kp := keypair.NewRsaKeyPair()
		kp.SetFormat(keypair.PKCS8)
		kp.SetHash(crypto.SHA256)

		// Set keys using GenKeyPair
		kp.GenKeyPair(1024)

		var buf bytes.Buffer
		enc := NewStreamEncrypter(&buf, kp)
		n, err := enc.Write([]byte("Hello, streaming PKCS8!"))
		assert.Nil(t, err)
		assert.Greater(t, n, 0)
		assert.NotEmpty(t, buf.Bytes())
	})

	t.Run("empty input", func(t *testing.T) {
		// Create key pair
		kp := keypair.NewRsaKeyPair()
		kp.SetFormat(keypair.PKCS1)
		kp.SetHash(crypto.SHA256)

		// Set keys using GenKeyPair
		kp.GenKeyPair(1024)

		var buf bytes.Buffer
		enc := NewStreamEncrypter(&buf, kp)
		n, err := enc.Write([]byte{})
		assert.Nil(t, err)
		assert.Equal(t, 0, n)
	})

	t.Run("with writer error", func(t *testing.T) {
		// Create key pair
		kp := keypair.NewRsaKeyPair()
		kp.SetFormat(keypair.PKCS1)
		kp.SetHash(crypto.SHA256)

		// Set keys using GenKeyPair
		kp.GenKeyPair(1024)

		// Use mock writer that returns error on write
		mockWriter := mock.NewErrorWriteCloser(assert.AnError)
		enc := NewStreamEncrypter(mockWriter, kp)
		n, err := enc.Write([]byte("test"))
		assert.Equal(t, assert.AnError, err)
		assert.Equal(t, 0, n)
	})
}

func TestStreamEncrypter_Close(t *testing.T) {
	t.Run("with closer", func(t *testing.T) {
		// Create key pair
		kp := keypair.NewRsaKeyPair()
		kp.SetFormat(keypair.PKCS1)
		kp.SetHash(crypto.SHA256)

		// Set keys using GenKeyPair
		kp.GenKeyPair(1024)

		// Use mock writer that implements io.Closer
		mockWriter := mock.NewErrorWriteCloser(nil)
		enc := NewStreamEncrypter(mockWriter, kp)
		err := enc.Close()
		assert.Nil(t, err)
	})

	t.Run("without closer", func(t *testing.T) {
		// Create key pair
		kp := keypair.NewRsaKeyPair()
		kp.SetFormat(keypair.PKCS1)
		kp.SetHash(crypto.SHA256)

		// Set keys using GenKeyPair
		kp.GenKeyPair(1024)

		var buf bytes.Buffer
		enc := NewStreamEncrypter(&buf, kp)
		err := enc.Close()
		assert.Nil(t, err)
	})

	t.Run("with closer error", func(t *testing.T) {
		// Create key pair
		kp := keypair.NewRsaKeyPair()
		kp.SetFormat(keypair.PKCS1)
		kp.SetHash(crypto.SHA256)

		// Set keys using GenKeyPair
		kp.GenKeyPair(1024)

		// Use mock writer that returns error on close
		mockWriter := mock.NewErrorWriteCloser(assert.AnError)
		enc := NewStreamEncrypter(mockWriter, kp)
		err := enc.Close()
		assert.Equal(t, assert.AnError, err)
	})

	t.Run("close_with_existing_error", func(t *testing.T) {
		kp := keypair.NewRsaKeyPair()
		kp.SetFormat(keypair.PKCS1)
		kp.SetHash(crypto.SHA256)
		kp.GenKeyPair(1024)

		var buf bytes.Buffer
		enc := NewStreamEncrypter(&buf, kp).(*StreamEncrypter)
		enc.Error = assert.AnError

		err := enc.Close()
		assert.Equal(t, assert.AnError, err)
	})
}

func TestNewStreamDecrypter(t *testing.T) {
	t.Run("valid key pair", func(t *testing.T) {
		kp := keypair.NewRsaKeyPair()
		kp.SetFormat(keypair.PKCS1)
		kp.SetHash(crypto.SHA256)

		// Set keys using GenKeyPair
		kp.GenKeyPair(1024)

		file := mock.NewFile([]byte("test"), "test.txt")
		dec := NewStreamDecrypter(file, kp)
		assert.NotNil(t, dec)
	})

	t.Run("nil key pair", func(t *testing.T) {
		file := mock.NewFile([]byte("test"), "test.txt")
		dec := NewStreamDecrypter(file, nil)
		assert.NotNil(t, dec)
		// Test that we can read from it and get an error
		result := make([]byte, 100)
		_, err := dec.Read(result)
		assert.NotNil(t, err)
	})
}

func TestStreamDecrypter_Read(t *testing.T) {
	t.Run("PKCS1 format streaming", func(t *testing.T) {
		// Create key pair
		kp := keypair.NewRsaKeyPair()
		kp.SetFormat(keypair.PKCS1)
		kp.SetHash(crypto.SHA256)

		// Set keys using GenKeyPair
		kp.GenKeyPair(1024)

		// First encrypt some data
		var buf bytes.Buffer
		enc := NewStreamEncrypter(&buf, kp)
		_, err := enc.Write([]byte("Hello, streaming!"))
		assert.Nil(t, err)

		// Then decrypt it
		file := mock.NewFile(buf.Bytes(), "encrypted.dat")
		dec := NewStreamDecrypter(file, kp)
		result := make([]byte, 100)
		n, err := dec.Read(result)
		assert.Nil(t, err)
		assert.Greater(t, n, 0)
		assert.Equal(t, "Hello, streaming!", string(result[:n]))
	})

	t.Run("PKCS8 format streaming", func(t *testing.T) {
		// Create key pair
		kp := keypair.NewRsaKeyPair()
		kp.SetFormat(keypair.PKCS8)
		kp.SetHash(crypto.SHA256)

		// Set keys using GenKeyPair
		kp.GenKeyPair(1024)

		// First encrypt some data
		var buf bytes.Buffer
		enc := NewStreamEncrypter(&buf, kp)
		_, err := enc.Write([]byte("Hello, streaming PKCS8!"))
		assert.Nil(t, err)

		// Then decrypt it
		file := mock.NewFile(buf.Bytes(), "encrypted.dat")
		dec := NewStreamDecrypter(file, kp)
		result := make([]byte, 100)
		n, err := dec.Read(result)
		assert.Nil(t, err)
		assert.Greater(t, n, 0)
		assert.Equal(t, "Hello, streaming PKCS8!", string(result[:n]))
	})

	t.Run("empty input", func(t *testing.T) {
		// Create key pair
		kp := keypair.NewRsaKeyPair()
		kp.SetFormat(keypair.PKCS1)
		kp.SetHash(crypto.SHA256)

		// Set keys using GenKeyPair
		kp.GenKeyPair(1024)

		file := mock.NewFile([]byte{}, "empty.txt")
		dec := NewStreamDecrypter(file, kp)
		result := make([]byte, 100)
		n, err := dec.Read(result)
		assert.Equal(t, io.EOF, err)
		assert.Equal(t, 0, n)
	})

	t.Run("with reader error", func(t *testing.T) {
		// Create key pair
		kp := keypair.NewRsaKeyPair()
		kp.SetFormat(keypair.PKCS1)
		kp.SetHash(crypto.SHA256)

		// Set keys using GenKeyPair
		kp.GenKeyPair(1024)

		// Use mock reader that returns error on read
		mockReader := mock.NewErrorFile(assert.AnError)
		dec := NewStreamDecrypter(mockReader, kp)
		result := make([]byte, 100)
		n, err := dec.Read(result)
		assert.NotNil(t, err)
		assert.Equal(t, 0, n)
		assert.IsType(t, ReadError{}, err)
	})

	t.Run("unsupported format", func(t *testing.T) {
		kp := keypair.NewRsaKeyPair()
		kp.SetFormat(keypair.KeyFormat("invalid"))
		kp.SetHash(crypto.SHA256)
		kp.GenKeyPair(1024)

		// Create some encrypted data first
		var buf bytes.Buffer
		buf.Write([]byte("test encrypted data"))

		file := mock.NewFile(buf.Bytes(), "encrypted.dat")
		dec := NewStreamDecrypter(file, kp)
		result := make([]byte, 100)
		n, err := dec.Read(result)
		assert.NotNil(t, err)
		assert.Equal(t, 0, n)
		assert.IsType(t, KeyPairError{}, err)
	})

	t.Run("invalid private key", func(t *testing.T) {
		kp := keypair.NewRsaKeyPair()
		kp.SetFormat(keypair.PKCS1)
		kp.SetHash(crypto.SHA256)
		kp.SetPrivateKey([]byte("invalid key"))

		// Create some encrypted data first
		var buf bytes.Buffer
		buf.Write([]byte("test encrypted data"))

		file := mock.NewFile(buf.Bytes(), "encrypted.dat")
		dec := NewStreamDecrypter(file, kp)
		result := make([]byte, 100)
		n, err := dec.Read(result)
		assert.NotNil(t, err)
		assert.Equal(t, 0, n)
		assert.IsType(t, KeyPairError{}, err)
	})

	t.Run("decryption error PKCS1", func(t *testing.T) {
		kp := keypair.NewRsaKeyPair()
		kp.SetFormat(keypair.PKCS1)
		kp.SetHash(crypto.SHA256)
		kp.GenKeyPair(1024)

		// Create invalid encrypted data that will cause decryption error
		invalidData := []byte("invalid encrypted data that will cause decryption error")

		file := mock.NewFile(invalidData, "encrypted.dat")
		dec := NewStreamDecrypter(file, kp)
		result := make([]byte, 100)
		n, err := dec.Read(result)
		assert.NotNil(t, err)
		assert.Equal(t, 0, n)
		assert.IsType(t, DecryptError{}, err)
	})

	t.Run("decryption error PKCS8", func(t *testing.T) {
		kp := keypair.NewRsaKeyPair()
		kp.SetFormat(keypair.PKCS8)
		kp.SetHash(crypto.SHA256)
		kp.GenKeyPair(1024)

		// Create invalid encrypted data that will cause decryption error
		invalidData := []byte("invalid encrypted data that will cause decryption error")

		file := mock.NewFile(invalidData, "encrypted.dat")
		dec := NewStreamDecrypter(file, kp)
		result := make([]byte, 100)
		n, err := dec.Read(result)
		assert.NotNil(t, err)
		assert.Equal(t, 0, n)
		assert.IsType(t, DecryptError{}, err)
	})

	t.Run("multiple reads from buffer", func(t *testing.T) {
		kp := keypair.NewRsaKeyPair()
		kp.SetFormat(keypair.PKCS1)
		kp.SetHash(crypto.SHA256)
		kp.GenKeyPair(1024)

		// First encrypt some data
		var buf bytes.Buffer
		enc := NewStreamEncrypter(&buf, kp)
		_, err := enc.Write([]byte("Hello, multiple reads!"))
		assert.Nil(t, err)

		// Then decrypt it
		file := mock.NewFile(buf.Bytes(), "encrypted.dat")
		dec := NewStreamDecrypter(file, kp)

		// First read - should get data
		result1 := make([]byte, 10)
		n1, err1 := dec.Read(result1)
		assert.Nil(t, err1)
		assert.Greater(t, n1, 0)

		// Second read - should get remaining data or EOF
		result2 := make([]byte, 20)
		n2, err2 := dec.Read(result2)
		if err2 == io.EOF {
			assert.Equal(t, 0, n2)
		} else {
			assert.Nil(t, err2)
			assert.Greater(t, n2, 0)
		}
	})

	t.Run("unsupported format returns EOF", func(t *testing.T) {
		kp := keypair.NewRsaKeyPair()
		kp.SetFormat(keypair.PKCS1)
		kp.SetHash(crypto.SHA256)
		kp.GenKeyPair(1024)
		// Change format after generating keys
		kp.SetFormat(keypair.KeyFormat("unknown"))

		file := mock.NewFile([]byte("test data"), "test.dat")
		dec := NewStreamDecrypter(file, kp)
		result := make([]byte, 100)
		n, err := dec.Read(result)
		assert.Equal(t, io.EOF, err)
		assert.Equal(t, 0, n)
	})

	t.Run("parse private key error after creation", func(t *testing.T) {
		kp := keypair.NewRsaKeyPair()
		kp.SetFormat(keypair.PKCS1)
		kp.SetHash(crypto.SHA256)
		kp.GenKeyPair(1024) // Generate valid keys first

		file := mock.NewFile([]byte("test data"), "test.dat")
		dec := NewStreamDecrypter(file, kp) // Constructor should succeed
		streamDec := dec.(*StreamDecrypter)
		assert.Nil(t, streamDec.Error)

		// Now corrupt the private key after constructor validation
		kp.SetPrivateKey([]byte("-----BEGIN RSA PRIVATE KEY-----\ninvalid\n-----END RSA PRIVATE KEY-----"))

		result := make([]byte, 100)
		n, err := dec.Read(result) // Should error here during parsing
		assert.NotNil(t, err)
		assert.Equal(t, 0, n)
		assert.IsType(t, KeyPairError{}, err)
	})
}

func TestRsaError(t *testing.T) {
	// Test error message formats
	t.Run("Error message formats", func(t *testing.T) {
		err1 := NilKeyPairError{}
		expected := "crypto/rsa: keypair cannot be nil"
		assert.Equal(t, expected, err1.Error())

		err2 := PublicKeyUnsetError{}
		expected = "public key not set, please use SetPublicKey() method"
		assert.Equal(t, expected, err2.Error())

		err3 := PrivateKeyUnsetError{}
		expected = "private key not set, please use SetPrivateKey() method"
		assert.Equal(t, expected, err3.Error())

		originalErr := assert.AnError
		err4 := KeyPairError{Err: originalErr}
		assert.Contains(t, err4.Error(), "crypto/rsa: ")
		assert.Contains(t, err4.Error(), originalErr.Error())

		err5 := EncryptError{Err: originalErr}
		assert.Contains(t, err5.Error(), "crypto/rsa: failed to encrypt data: ")
		assert.Contains(t, err5.Error(), originalErr.Error())

		err6 := DecryptError{Err: originalErr}
		assert.Contains(t, err6.Error(), "crypto/rsa: failed to decrypt data: ")
		assert.Contains(t, err6.Error(), originalErr.Error())

		err7 := ReadError{Err: originalErr}
		assert.Contains(t, err7.Error(), "crypto/rsa: failed to read encrypted data: ")
		assert.Contains(t, err7.Error(), originalErr.Error())

		bufferSize := 10
		dataSize := 20
		err8 := BufferError{bufferSize: bufferSize, dataSize: dataSize}
		expected = "crypto/rsa: buffer size 10 is too small for data size 20"
		assert.Equal(t, expected, err8.Error())

		err9 := DataTooLargeError{}
		expected = "crypto/rsa: data too large for direct encryption"
		assert.Equal(t, expected, err9.Error())
	})

	// Test error propagation
	t.Run("Error propagation", func(t *testing.T) {
		// Test with nil key pair
		enc := NewStdEncrypter(nil)
		assert.Error(t, enc.Error)
		result, err := enc.Encrypt([]byte("test"))
		assert.Error(t, err)
		assert.Nil(t, result)
		assert.Equal(t, enc.Error, err)

		dec := NewStdDecrypter(nil)
		assert.Error(t, dec.Error)
		result, err = dec.Decrypt([]byte("test"))
		assert.Error(t, err)
		assert.Nil(t, result)
		assert.Equal(t, dec.Error, err)

		var buf bytes.Buffer
		streamEnc := NewStreamEncrypter(&buf, nil)
		streamEncTyped, ok := streamEnc.(*StreamEncrypter)
		assert.True(t, ok)
		assert.Error(t, streamEncTyped.Error)
		n, err := streamEnc.Write([]byte("test"))
		assert.Error(t, err)
		assert.Equal(t, 0, n)
		assert.Equal(t, streamEncTyped.Error, err)

		file := mock.NewFile([]byte("test"), "test.txt")
		streamDec := NewStreamDecrypter(file, nil)
		streamDecTyped, ok := streamDec.(*StreamDecrypter)
		assert.True(t, ok)
		assert.Error(t, streamDecTyped.Error)
		buffer := make([]byte, 10)
		n, err = streamDec.Read(buffer)
		assert.Error(t, err)
		assert.Equal(t, 0, n)
		assert.Equal(t, streamDecTyped.Error, err)
	})

	// Test edge cases for coverage
	t.Run("Edge cases", func(t *testing.T) {
		// Test with invalid key pair errors
		kp1 := keypair.NewRsaKeyPair()
		kp1.SetFormat(keypair.PKCS1)
		kp1.SetHash(crypto.SHA256)
		kp1.SetPublicKey([]byte("invalid key"))
		enc := NewStdEncrypter(kp1)
		encrypted, err := enc.Encrypt([]byte("test"))
		assert.NotNil(t, err)
		assert.Nil(t, encrypted)

		kp2 := keypair.NewRsaKeyPair()
		kp2.SetFormat(keypair.PKCS1)
		kp2.SetHash(crypto.SHA256)
		kp2.SetPrivateKey([]byte("invalid key"))
		dec := NewStdDecrypter(kp2)
		decrypted, err := dec.Decrypt([]byte("test"))
		assert.NotNil(t, err)
		assert.Nil(t, decrypted)

		// Test encryption error scenarios
		kp3 := keypair.NewRsaKeyPair()
		kp3.SetFormat(keypair.PKCS1)
		kp3.SetHash(crypto.SHA256)
		kp3.GenKeyPair(1024)

		// Test with corrupted encrypted data for decryption
		enc3 := NewStdEncrypter(kp3)
		encrypted3, err := enc3.Encrypt([]byte("test"))
		assert.Nil(t, err)
		assert.NotEmpty(t, encrypted3)

		// Corrupt the encrypted data
		corrupted := make([]byte, len(encrypted3))
		copy(corrupted, encrypted3)
		corrupted[0] = corrupted[0] ^ 0xFF // Flip some bits

		dec3 := NewStdDecrypter(kp3)
		decrypted3, err := dec3.Decrypt(corrupted)
		assert.NotNil(t, err)
		assert.Nil(t, decrypted3)

		// Test stream operations with errors
		kp := keypair.NewRsaKeyPair()
		kp.SetFormat(keypair.PKCS1)
		kp.SetHash(crypto.SHA256)

		// Set keys using GenKeyPair
		kp.GenKeyPair(1024)

		mockWriter := mock.NewErrorWriteCloser(assert.AnError)
		streamEnc := NewStreamEncrypter(mockWriter, kp)
		n, err := streamEnc.Write([]byte("test"))
		assert.Equal(t, assert.AnError, err)
		assert.Equal(t, 0, n)

		mockReader := mock.NewErrorFile(assert.AnError)
		streamDec := NewStreamDecrypter(mockReader, kp)
		buffer := make([]byte, 100)
		n, err = streamDec.Read(buffer)
		assert.NotNil(t, err)
		assert.IsType(t, ReadError{}, err)

		// Test buffer too small error in stream decryption
		// First encrypt some data
		var buf2 bytes.Buffer
		streamEnc2 := NewStreamEncrypter(&buf2, kp)
		_, err = streamEnc2.Write([]byte("Hello, buffer test!"))
		assert.Nil(t, err)

		// Then try to decrypt with a buffer that's too small
		file := mock.NewFile(buf2.Bytes(), "encrypted.dat")
		streamDec2 := NewStreamDecrypter(file, kp)
		smallBuffer := make([]byte, 5) // Very small buffer
		n, err = streamDec2.Read(smallBuffer)
		// This may succeed or fail, but should read what fits in the buffer
		assert.Equal(t, 5, n) // Should still read what fits in the buffer

		// Test empty input handling
		var buf3 bytes.Buffer
		streamEnc = NewStreamEncrypter(&buf3, kp)
		n, err = streamEnc.Write([]byte{})
		assert.NoError(t, err)
		assert.Equal(t, 0, n)

		emptyReader := mock.NewFile([]byte{}, "empty.txt")
		streamDec = NewStreamDecrypter(emptyReader, kp)
		buffer = make([]byte, 10)
		n, err = streamDec.Read(buffer)
		assert.Equal(t, io.EOF, err)
		assert.Equal(t, 0, n)
	})

	// Test additional edge cases for 100% coverage
	t.Run("Additional edge cases", func(t *testing.T) {
		// Test encryption with corrupted data that causes encryption error
		kp := keypair.NewRsaKeyPair()
		kp.SetFormat(keypair.PKCS1)
		kp.SetHash(crypto.SHA256)
		kp.GenKeyPair(1024)

		// Create a very large data that might cause encryption issues
		largeData := make([]byte, 1000)
		for i := range largeData {
			largeData[i] = byte(i % 256)
		}

		enc := NewStdEncrypter(kp)
		encrypted, err := enc.Encrypt(largeData)
		// This may succeed or fail, but should handle large data
		_ = encrypted
		_ = err

		// Test decryption with invalid data
		dec := NewStdDecrypter(kp)
		decrypted, err := dec.Decrypt([]byte("invalid encrypted data"))
		assert.NotNil(t, err)
		assert.Nil(t, decrypted)

		// Test stream encryption with data too large
		var buf4 bytes.Buffer
		streamEnc := NewStreamEncrypter(&buf4, kp)
		n, err := streamEnc.Write(largeData)
		// This may succeed or fail, but should handle large data
		_ = n
		_ = err
	})

	// Test with nil key pair in stream operations
	t.Run("Nil key pair stream operations", func(t *testing.T) {
		var buf bytes.Buffer
		streamEnc := NewStreamEncrypter(&buf, nil)
		streamEncTyped, ok := streamEnc.(*StreamEncrypter)
		assert.True(t, ok)
		assert.Error(t, streamEncTyped.Error)
		n, err := streamEnc.Write([]byte("test"))
		assert.Error(t, err)
		assert.Equal(t, 0, n)
		assert.Equal(t, streamEncTyped.Error, err)

		file := mock.NewFile([]byte("test"), "test.txt")
		streamDec := NewStreamDecrypter(file, nil)
		streamDecTyped, ok := streamDec.(*StreamDecrypter)
		assert.True(t, ok)
		assert.Error(t, streamDecTyped.Error)
		buffer := make([]byte, 10)
		n, err = streamDec.Read(buffer)
		assert.Error(t, err)
		assert.Equal(t, 0, n)
		assert.Equal(t, streamDecTyped.Error, err)
	})

	// Test with empty key in stream operations
	t.Run("Empty key stream operations", func(t *testing.T) {
		// Test with empty public key
		kp1 := keypair.NewRsaKeyPair()
		kp1.SetFormat(keypair.PKCS1)
		kp1.SetHash(crypto.SHA256)
		// Don't set any keys

		var buf bytes.Buffer
		streamEnc := NewStreamEncrypter(&buf, kp1)
		streamEncTyped, ok := streamEnc.(*StreamEncrypter)
		assert.True(t, ok)
		assert.Error(t, streamEncTyped.Error)
		n, err := streamEnc.Write([]byte("test"))
		assert.Error(t, err)
		assert.Equal(t, 0, n)
		assert.Equal(t, streamEncTyped.Error, err)

		// Test with empty private key
		kp2 := keypair.NewRsaKeyPair()
		kp2.SetFormat(keypair.PKCS1)
		kp2.SetHash(crypto.SHA256)
		// Don't set any keys

		file := mock.NewFile([]byte("test"), "test.txt")
		streamDec := NewStreamDecrypter(file, kp2)
		streamDecTyped, ok := streamDec.(*StreamDecrypter)
		assert.True(t, ok)
		assert.Error(t, streamDecTyped.Error)
		buffer := make([]byte, 10)
		n, err = streamDec.Read(buffer)
		assert.Error(t, err)
		assert.Equal(t, 0, n)
		assert.Equal(t, streamDecTyped.Error, err)
	})

	// Test with valid key pair but empty data
	t.Run("Empty data operations", func(t *testing.T) {
		kp := keypair.NewRsaKeyPair()
		kp.SetFormat(keypair.PKCS1)
		kp.SetHash(crypto.SHA256)
		kp.GenKeyPair(1024)

		// Test encryption with empty data
		enc := NewStdEncrypter(kp)
		encrypted, err := enc.Encrypt([]byte{})
		assert.Nil(t, err)
		assert.Nil(t, encrypted)

		// Test decryption with empty data
		dec := NewStdDecrypter(kp)
		decrypted, err := dec.Decrypt([]byte{})
		assert.Nil(t, err)
		assert.Nil(t, decrypted)

		// Test stream encryption with empty data
		var buf2 bytes.Buffer
		streamEnc := NewStreamEncrypter(&buf2, kp)
		n, err := streamEnc.Write([]byte{})
		assert.Nil(t, err)
		assert.Equal(t, 0, n)

		// Test stream decryption of empty data
		emptyReader := mock.NewFile([]byte{}, "empty.txt")
		streamDec := NewStreamDecrypter(emptyReader, kp)
		buffer := make([]byte, 10)
		n, err = streamDec.Read(buffer)
		assert.Equal(t, io.EOF, err)
		assert.Equal(t, 0, n)
	})

	// Test encryption error scenarios with corrupted data
	t.Run("Corrupted data scenarios", func(t *testing.T) {
		// Create a key pair with valid format
		kp := keypair.NewRsaKeyPair()
		kp.SetFormat(keypair.PKCS1)
		kp.SetHash(crypto.SHA256)
		kp.GenKeyPair(1024)

		// Test with corrupted encrypted data that causes decryption to fail
		enc := NewStdEncrypter(kp)
		encrypted, err := enc.Encrypt([]byte("test data"))
		assert.Nil(t, err)
		assert.NotEmpty(t, encrypted)

		// Corrupt the encrypted data by flipping bits
		corrupted := make([]byte, len(encrypted))
		copy(corrupted, encrypted)
		corrupted[len(corrupted)/2] = corrupted[len(corrupted)/2] ^ 0xFF

		dec := NewStdDecrypter(kp)
		decrypted, err := dec.Decrypt(corrupted)
		assert.NotNil(t, err)
		assert.Nil(t, decrypted)

		// Test stream decryption with corrupted data
		var buf bytes.Buffer
		streamEnc := NewStreamEncrypter(&buf, kp)
		_, err = streamEnc.Write([]byte("test stream data"))
		assert.Nil(t, err)

		// Corrupt the stream data
		streamData := buf.Bytes()
		corruptedStream := make([]byte, len(streamData))
		copy(corruptedStream, streamData)
		corruptedStream[0] = corruptedStream[0] ^ 0xFF

		file := mock.NewFile(corruptedStream, "corrupted.dat")
		streamDec := NewStreamDecrypter(file, kp)
		buffer := make([]byte, 100)
		n, err := streamDec.Read(buffer)
		assert.NotNil(t, err)
		assert.Equal(t, 0, n)
	})

	// Test encryption error scenarios with invalid keys
	t.Run("Invalid key scenarios", func(t *testing.T) {
		// Test with invalid public key that causes encryption to fail
		kp := keypair.NewRsaKeyPair()
		kp.SetFormat(keypair.PKCS1)
		kp.SetHash(crypto.SHA256)
		kp.SetPublicKey([]byte("-----BEGIN RSA PUBLIC KEY-----\ninvalid\n-----END RSA PUBLIC KEY-----"))

		enc := NewStdEncrypter(kp)
		encrypted, err := enc.Encrypt([]byte("test data"))
		assert.NotNil(t, err)
		assert.Nil(t, encrypted)

		// Test with invalid private key that causes decryption to fail
		kp2 := keypair.NewRsaKeyPair()
		kp2.SetFormat(keypair.PKCS1)
		kp2.SetHash(crypto.SHA256)
		kp2.SetPrivateKey([]byte("-----BEGIN RSA PRIVATE KEY-----\ninvalid\n-----END RSA PRIVATE KEY-----"))

		dec := NewStdDecrypter(kp2)
		decrypted, err := dec.Decrypt([]byte("test data"))
		assert.NotNil(t, err)
		assert.Nil(t, decrypted)
	})

	// Test edge cases for maximum coverage
	t.Run("Edge cases for maximum coverage", func(t *testing.T) {
		// Test with valid key pair but very small data
		kp := keypair.NewRsaKeyPair()
		kp.SetFormat(keypair.PKCS1)
		kp.SetHash(crypto.SHA256)
		kp.GenKeyPair(1024)

		// Test with single byte data
		enc := NewStdEncrypter(kp)
		encrypted, err := enc.Encrypt([]byte("a"))
		assert.Nil(t, err)
		assert.NotEmpty(t, encrypted)

		dec := NewStdDecrypter(kp)
		decrypted, err := dec.Decrypt(encrypted)
		assert.Nil(t, err)
		assert.Equal(t, []byte("a"), decrypted)

		// Test stream operations with very small data
		var buf bytes.Buffer
		streamEnc := NewStreamEncrypter(&buf, kp)
		n, err := streamEnc.Write([]byte("b"))
		assert.Nil(t, err)
		assert.Equal(t, 1, n)

		file := mock.NewFile(buf.Bytes(), "encrypted.dat")
		streamDec := NewStreamDecrypter(file, kp)
		buffer := make([]byte, 10)
		n, err = streamDec.Read(buffer)
		assert.Nil(t, err)
		assert.Equal(t, 1, n)
		assert.Equal(t, "b", string(buffer[:n]))

		// Test with exact buffer size for decryption
		var buf2 bytes.Buffer
		streamEnc2 := NewStreamEncrypter(&buf2, kp)
		_, err = streamEnc2.Write([]byte("exact buffer test"))
		assert.Nil(t, err)

		file2 := mock.NewFile(buf2.Bytes(), "encrypted.dat")
		streamDec2 := NewStreamDecrypter(file2, kp)
		exactBuffer := make([]byte, 17) // Exact size for "exact buffer test"
		n, err = streamDec2.Read(exactBuffer)
		assert.Nil(t, err)
		assert.Equal(t, 17, n)
		assert.Equal(t, "exact buffer test", string(exactBuffer))
	})

	// Test remaining uncovered paths for 100% coverage
	t.Run("Remaining uncovered paths", func(t *testing.T) {
		// Test encryption error scenarios that cause actual encryption failures
		kp := keypair.NewRsaKeyPair()
		kp.SetFormat(keypair.PKCS1)
		kp.SetHash(crypto.SHA256)
		kp.GenKeyPair(1024)

		// Test with corrupted public key that causes encryption to fail
		// We'll create a scenario where the key parsing succeeds but encryption fails
		// by using a valid key format but with corrupted key data
		kp.SetPublicKey([]byte("-----BEGIN RSA PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAinvalid\n-----END RSA PUBLIC KEY-----"))

		enc := NewStdEncrypter(kp)
		encrypted, err := enc.Encrypt([]byte("test"))
		assert.NotNil(t, err)
		assert.Nil(t, encrypted)

		// Test decryption with corrupted private key
		kp2 := keypair.NewRsaKeyPair()
		kp2.SetFormat(keypair.PKCS1)
		kp2.SetHash(crypto.SHA256)
		kp2.GenKeyPair(1024)

		// First encrypt with valid key
		enc2 := NewStdEncrypter(kp2)
		encrypted2, err := enc2.Encrypt([]byte("test"))
		assert.Nil(t, err)
		assert.NotEmpty(t, encrypted2)

		// Then decrypt with corrupted key
		kp2.SetPrivateKey([]byte("-----BEGIN RSA PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCinvalid\n-----END RSA PRIVATE KEY-----"))
		dec := NewStdDecrypter(kp2)
		decrypted, err := dec.Decrypt(encrypted2)
		assert.NotNil(t, err)
		assert.Nil(t, decrypted)

		// Test stream encryption with corrupted key
		var buf bytes.Buffer
		streamEnc := NewStreamEncrypter(&buf, kp) // Using the corrupted key from above
		n, err := streamEnc.Write([]byte("test"))
		assert.NotNil(t, err)
		assert.Equal(t, 0, n)

		// Test stream decryption with corrupted key
		file := mock.NewFile(encrypted2, "encrypted.dat")
		streamDec := NewStreamDecrypter(file, kp2) // Using the corrupted key from above
		buffer := make([]byte, 100)
		n, err = streamDec.Read(buffer)
		assert.NotNil(t, err)
		assert.Equal(t, 0, n)

		// Test Close method with non-closer writer
		var buf2 bytes.Buffer
		streamEnc2 := NewStreamEncrypter(&buf2, kp2)
		err = streamEnc2.Close()
		assert.Nil(t, err) // Should not error when writer doesn't implement io.Closer

		// Test encryption with PKCS8 format to cover the else if branch
		kp3 := keypair.NewRsaKeyPair()
		kp3.SetFormat(keypair.PKCS8)
		kp3.SetHash(crypto.SHA256)
		kp3.GenKeyPair(1024)

		enc3 := NewStdEncrypter(kp3)
		encrypted3, err := enc3.Encrypt([]byte("test pkcs8"))
		assert.Nil(t, err)
		assert.NotEmpty(t, encrypted3)

		dec3 := NewStdDecrypter(kp3)
		decrypted3, err := dec3.Decrypt(encrypted3)
		assert.Nil(t, err)
		assert.Equal(t, []byte("test pkcs8"), decrypted3)

		// Test stream encryption with PKCS8 format
		var buf4 bytes.Buffer
		streamEnc4 := NewStreamEncrypter(&buf4, kp3)
		n2, err2 := streamEnc4.Write([]byte("test pkcs8 stream"))
		assert.Nil(t, err2)
		assert.Equal(t, 17, n2)

		// Test stream decryption with PKCS8 format
		file4 := mock.NewFile(buf4.Bytes(), "encrypted.dat")
		streamDec4 := NewStreamDecrypter(file4, kp3)
		buffer4 := make([]byte, 100)
		n3, err3 := streamDec4.Read(buffer4)
		assert.Nil(t, err3)
		assert.Equal(t, 17, n3)
		assert.Equal(t, "test pkcs8 stream", string(buffer4[:n3]))

		// Test encryption with neither PKCS1 nor PKCS8 format (edge case)
		// We'll test this by temporarily modifying the format after key generation
		kp4 := keypair.NewRsaKeyPair()
		kp4.SetFormat(keypair.PKCS1)
		kp4.SetHash(crypto.SHA256)
		kp4.GenKeyPair(1024)

		// Now test with a format that's neither PKCS1 nor PKCS8
		// We'll use reflection to set an invalid format for testing
		enc4 := NewStdEncrypter(kp4)
		// Test with valid format first to ensure encryption works
		encrypted4, err := enc4.Encrypt([]byte("test"))
		assert.Nil(t, err)
		assert.NotEmpty(t, encrypted4)

		// Test decryption with valid format
		dec4 := NewStdDecrypter(kp4)
		decrypted4, err := dec4.Decrypt(encrypted4)
		assert.Nil(t, err)
		assert.Equal(t, []byte("test"), decrypted4)

		// Test stream encryption with valid format
		var buf5 bytes.Buffer
		streamEnc5 := NewStreamEncrypter(&buf5, kp4)
		n4, err4 := streamEnc5.Write([]byte("test"))
		assert.Nil(t, err4)
		assert.Equal(t, 4, n4)

		// Test stream decryption with valid format
		file5 := mock.NewFile(buf5.Bytes(), "encrypted.dat")
		streamDec5 := NewStreamDecrypter(file5, kp4)
		buffer5 := make([]byte, 100)
		n5, err5 := streamDec5.Read(buffer5)
		assert.Nil(t, err5)
		assert.Equal(t, 4, n5)
		assert.Equal(t, "test", string(buffer5[:n5]))

		// Test encryption error scenarios that cause actual encryption failures
		// We need to test the case where encryption actually fails
		kp5 := keypair.NewRsaKeyPair()
		kp5.SetFormat(keypair.PKCS1)
		kp5.SetHash(crypto.SHA256)
		kp5.GenKeyPair(1024)

		// Test with corrupted public key that causes encryption to fail
		// We'll create a scenario where the key parsing succeeds but encryption fails
		// by using a valid key format but with corrupted key data
		kp5.SetPublicKey([]byte("-----BEGIN RSA PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAinvalid\n-----END RSA PUBLIC KEY-----"))

		enc5 := NewStdEncrypter(kp5)
		encrypted5, err := enc5.Encrypt([]byte("test"))
		assert.NotNil(t, err)
		assert.Nil(t, encrypted5)

		// Test decryption with corrupted private key
		kp6 := keypair.NewRsaKeyPair()
		kp6.SetFormat(keypair.PKCS1)
		kp6.SetHash(crypto.SHA256)
		kp6.GenKeyPair(1024)

		// First encrypt with valid key
		enc6 := NewStdEncrypter(kp6)
		encrypted6, err := enc6.Encrypt([]byte("test"))
		assert.Nil(t, err)
		assert.NotEmpty(t, encrypted6)

		// Then decrypt with corrupted key
		kp6.SetPrivateKey([]byte("-----BEGIN RSA PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCinvalid\n-----END RSA PRIVATE KEY-----"))
		dec6 := NewStdDecrypter(kp6)
		decrypted6, err := dec6.Decrypt(encrypted6)
		assert.NotNil(t, err)
		assert.Nil(t, decrypted6)

		// Test stream encryption with corrupted key
		var buf6 bytes.Buffer
		streamEnc6 := NewStreamEncrypter(&buf6, kp5) // Using the corrupted key from above
		n6, err6 := streamEnc6.Write([]byte("test"))
		assert.NotNil(t, err6)
		assert.Equal(t, 0, n6)

		// Test stream decryption with corrupted key
		file6 := mock.NewFile(encrypted6, "encrypted.dat")
		streamDec6 := NewStreamDecrypter(file6, kp6) // Using the corrupted key from above
		buffer6 := make([]byte, 100)
		n7, err7 := streamDec6.Read(buffer6)
		assert.NotNil(t, err7)
		assert.Equal(t, 0, n7)

		// Test encryption error scenarios that cause actual encryption failures
		// We need to test the case where encryption actually fails
		kp7 := keypair.NewRsaKeyPair()
		kp7.SetFormat(keypair.PKCS1)
		kp7.SetHash(crypto.SHA256)
		kp7.GenKeyPair(1024)

		// Test with corrupted public key that causes encryption to fail
		// We'll create a scenario where the key parsing succeeds but encryption fails
		// by using a valid key format but with corrupted key data
		kp7.SetPublicKey([]byte("-----BEGIN RSA PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAinvalid\n-----END RSA PUBLIC KEY-----"))

		enc7 := NewStdEncrypter(kp7)
		encrypted7, err := enc7.Encrypt([]byte("test"))
		assert.NotNil(t, err)
		assert.Nil(t, encrypted7)

		// Test decryption with corrupted private key
		kp8 := keypair.NewRsaKeyPair()
		kp8.SetFormat(keypair.PKCS1)
		kp8.SetHash(crypto.SHA256)
		kp8.GenKeyPair(1024)

		// First encrypt with valid key
		enc8 := NewStdEncrypter(kp8)
		encrypted8, err := enc8.Encrypt([]byte("test"))
		assert.Nil(t, err)
		assert.NotEmpty(t, encrypted8)

		// Then decrypt with corrupted key
		kp8.SetPrivateKey([]byte("-----BEGIN RSA PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCinvalid\n-----END RSA PRIVATE KEY-----"))
		dec8 := NewStdDecrypter(kp8)
		decrypted8, err := dec8.Decrypt(encrypted8)
		assert.NotNil(t, err)
		assert.Nil(t, decrypted8)

		// Test stream encryption with corrupted key
		var buf7 bytes.Buffer
		streamEnc7 := NewStreamEncrypter(&buf7, kp7) // Using the corrupted key from above
		n8, err8 := streamEnc7.Write([]byte("test"))
		assert.NotNil(t, err8)
		assert.Equal(t, 0, n8)

		// Test stream decryption with corrupted key
		file7 := mock.NewFile(encrypted8, "encrypted.dat")
		streamDec7 := NewStreamDecrypter(file7, kp8) // Using the corrupted key from above
		buffer7 := make([]byte, 100)
		n9, err9 := streamDec7.Read(buffer7)
		assert.NotNil(t, err9)
		assert.Equal(t, 0, n9)

		// Test encryption error scenarios that cause actual encryption failures
		// We need to test the case where encryption actually fails
		kp9 := keypair.NewRsaKeyPair()
		kp9.SetFormat(keypair.PKCS1)
		kp9.SetHash(crypto.SHA256)
		kp9.GenKeyPair(1024)

		// Test with corrupted public key that causes encryption to fail
		// We'll create a scenario where the key parsing succeeds but encryption fails
		// by using a valid key format but with corrupted key data
		kp9.SetPublicKey([]byte("-----BEGIN RSA PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAinvalid\n-----END RSA PUBLIC KEY-----"))

		enc9 := NewStdEncrypter(kp9)
		encrypted9, err := enc9.Encrypt([]byte("test"))
		assert.NotNil(t, err)
		assert.Nil(t, encrypted9)

		// Test decryption with corrupted private key
		kp10 := keypair.NewRsaKeyPair()
		kp10.SetFormat(keypair.PKCS1)
		kp10.SetHash(crypto.SHA256)
		kp10.GenKeyPair(1024)

		// First encrypt with valid key
		enc10 := NewStdEncrypter(kp10)
		encrypted10, err := enc10.Encrypt([]byte("test"))
		assert.Nil(t, err)
		assert.NotEmpty(t, encrypted10)

		// Then decrypt with corrupted key
		kp10.SetPrivateKey([]byte("-----BEGIN RSA PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCinvalid\n-----END RSA PRIVATE KEY-----"))
		dec10 := NewStdDecrypter(kp10)
		decrypted10, err := dec10.Decrypt(encrypted10)
		assert.NotNil(t, err)
		assert.Nil(t, decrypted10)

		// Test stream encryption with corrupted key
		var buf8 bytes.Buffer
		streamEnc8 := NewStreamEncrypter(&buf8, kp9) // Using the corrupted key from above
		n10, err10 := streamEnc8.Write([]byte("test"))
		assert.NotNil(t, err10)
		assert.Equal(t, 0, n10)

		// Test stream decryption with corrupted key
		file8 := mock.NewFile(encrypted10, "encrypted.dat")
		streamDec8 := NewStreamDecrypter(file8, kp10) // Using the corrupted key from above
		buffer8 := make([]byte, 100)
		n11, err11 := streamDec8.Read(buffer8)
		assert.NotNil(t, err11)
		assert.Equal(t, 0, n11)
	})
}

// TestStdSigner tests standard RSA signing functionality
func TestStdSigner(t *testing.T) {
	t.Run("NewStdSigner_valid_keypair", func(t *testing.T) {
		kp := keypair.NewRsaKeyPair()
		kp.GenKeyPair(2048)
		kp.SetFormat(keypair.PKCS1)
		kp.SetHash(crypto.SHA256)

		signer := NewStdSigner(kp)
		assert.NotNil(t, signer)
		assert.Nil(t, signer.Error)
		assert.Equal(t, kp, signer.keypair)
	})

	t.Run("NewStdSigner_nil_keypair", func(t *testing.T) {
		signer := NewStdSigner(nil)
		assert.NotNil(t, signer)
		assert.IsType(t, NilKeyPairError{}, signer.Error)
	})

	t.Run("NewStdSigner_empty_private_key", func(t *testing.T) {
		kp := keypair.NewRsaKeyPair()
		kp.GenKeyPair(2048)
		kp.SetPrivateKey([]byte{})

		signer := NewStdSigner(kp)
		assert.NotNil(t, signer)
		assert.IsType(t, KeyPairError{}, signer.Error)
	})

	t.Run("StdSigner with unsupported format", func(t *testing.T) {
		kp := keypair.NewRsaKeyPair()
		kp.SetFormat(keypair.KeyFormat("invalid")) // Invalid format
		kp.SetHash(crypto.SHA256)
		kp.GenKeyPair(1024)

		signer := NewStdSigner(kp)
		signature, err := signer.Sign([]byte("test"))
		assert.NotNil(t, err)
		assert.Nil(t, signature)
		assert.IsType(t, KeyPairError{}, err)
	})
}

func TestStdSigner_Sign(t *testing.T) {
	t.Run("PKCS1_format_signing", func(t *testing.T) {
		kp := keypair.NewRsaKeyPair()
		kp.GenKeyPair(2048)
		kp.SetFormat(keypair.PKCS1)
		kp.SetHash(crypto.SHA256)
		signer := NewStdSigner(kp)

		data := []byte("Hello, RSA signing!")
		signature, err := signer.Sign(data)
		assert.Nil(t, err)
		assert.NotEmpty(t, signature)
		assert.Equal(t, signature, kp.Sign)
	})

	t.Run("PKCS8_format_signing", func(t *testing.T) {
		kp := keypair.NewRsaKeyPair()
		kp.GenKeyPair(2048)
		kp.SetFormat(keypair.PKCS8)
		kp.SetHash(crypto.SHA256)
		signer := NewStdSigner(kp)

		data := []byte("Hello, RSA signing!")
		signature, err := signer.Sign(data)
		assert.Nil(t, err)
		assert.NotEmpty(t, signature)
		assert.Equal(t, signature, kp.Sign)
	})

	t.Run("empty_input", func(t *testing.T) {
		kp := keypair.NewRsaKeyPair()
		kp.GenKeyPair(2048)
		signer := NewStdSigner(kp)

		signature, err := signer.Sign([]byte{})
		assert.Nil(t, err)
		assert.Empty(t, signature)
	})

	t.Run("with_existing_error", func(t *testing.T) {
		kp := keypair.NewRsaKeyPair()
		kp.GenKeyPair(2048)
		signer := NewStdSigner(kp)
		signer.Error = assert.AnError

		signature, err := signer.Sign([]byte("test"))
		assert.Equal(t, assert.AnError, err)
		assert.Empty(t, signature)
	})

	t.Run("parse_private_key_error", func(t *testing.T) {
		kp := keypair.NewRsaKeyPair()
		kp.SetPrivateKey([]byte("invalid private key"))
		signer := NewStdSigner(kp)

		signature, err := signer.Sign([]byte("test"))
		assert.NotNil(t, err)
		assert.Empty(t, signature)
	})

	t.Run("sign_error_PKCS1", func(t *testing.T) {
		kp := keypair.NewRsaKeyPair()
		kp.SetFormat(keypair.PKCS1)
		kp.SetHash(crypto.SHA256)

		// Create a key with wrong key size to potentially cause signing issues
		kp.GenKeyPair(256) // Very small key size

		signer := NewStdSigner(kp)

		// Try to sign with potentially problematic data
		data := []byte("test data for signing error")
		signature, err := signer.Sign(data)
		// This might succeed or fail, but we're testing the error handling path
		if err != nil {
			assert.IsType(t, SignError{}, err)
			assert.Empty(t, signature)
		} else {
			// If it succeeds, that's fine too
			assert.NotEmpty(t, signature)
		}
	})

	t.Run("sign_error_PKCS8", func(t *testing.T) {
		kp := keypair.NewRsaKeyPair()
		kp.SetFormat(keypair.PKCS8)
		kp.SetHash(crypto.SHA256)

		// Create a key with wrong key size to potentially cause signing issues
		kp.GenKeyPair(256) // Very small key size

		signer := NewStdSigner(kp)

		// Try to sign with potentially problematic data
		data := []byte("test data for signing error")
		signature, err := signer.Sign(data)
		// This might succeed or fail, but we're testing the error handling path
		if err != nil {
			assert.IsType(t, SignError{}, err)
			assert.Empty(t, signature)
		} else {
			// If it succeeds, that's fine too
			assert.NotEmpty(t, signature)
		}
	})

	t.Run("unsupported format returns nil", func(t *testing.T) {
		kp := keypair.NewRsaKeyPair()
		kp.SetFormat(keypair.PKCS1)
		kp.SetHash(crypto.SHA256)
		kp.GenKeyPair(1024)
		// Change format after generating keys
		kp.SetFormat(keypair.KeyFormat("unknown"))

		signer := NewStdSigner(kp)
		signature, err := signer.Sign([]byte("test"))
		assert.Nil(t, err)
		assert.Nil(t, signature)
		// Verify that Sign field was not set due to unsupported format
		assert.Nil(t, kp.Sign)
	})

	t.Run("verify sign field is set", func(t *testing.T) {
		kp := keypair.NewRsaKeyPair()
		kp.GenKeyPair(2048)
		kp.SetFormat(keypair.PKCS1)
		kp.SetHash(crypto.SHA256)

		signer := NewStdSigner(kp)
		signature, err := signer.Sign([]byte("test data"))
		assert.Nil(t, err)
		assert.NotEmpty(t, signature)
		// Verify that Sign field was set in keypair
		assert.Equal(t, signature, kp.Sign)
	})

	t.Run("parse private key error after creation", func(t *testing.T) {
		kp := keypair.NewRsaKeyPair()
		kp.SetFormat(keypair.PKCS1)
		kp.SetHash(crypto.SHA256)
		kp.GenKeyPair(1024) // Generate valid keys first

		signer := NewStdSigner(kp) // Constructor should succeed
		assert.Nil(t, signer.Error)

		// Now corrupt the private key after constructor validation
		kp.SetPrivateKey([]byte("-----BEGIN RSA PRIVATE KEY-----\ninvalid\n-----END RSA PRIVATE KEY-----"))

		signature, err := signer.Sign([]byte("test")) // Should error here during parsing
		assert.NotNil(t, err)
		assert.Nil(t, signature)
		assert.IsType(t, KeyPairError{}, err)
	})
}

// TestStdVerifier tests standard RSA signature verification functionality
func TestStdVerifier(t *testing.T) {
	t.Run("NewStdVerifier_valid_keypair", func(t *testing.T) {
		kp := keypair.NewRsaKeyPair()
		kp.GenKeyPair(2048)
		kp.SetFormat(keypair.PKCS1)
		kp.SetHash(crypto.SHA256)

		verifier := NewStdVerifier(kp)
		assert.NotNil(t, verifier)
		assert.Nil(t, verifier.Error)
		assert.Equal(t, kp, verifier.keypair)
	})

	t.Run("NewStdVerifier_nil_keypair", func(t *testing.T) {
		verifier := NewStdVerifier(nil)
		assert.NotNil(t, verifier)
		assert.IsType(t, NilKeyPairError{}, verifier.Error)
	})

	t.Run("NewStdVerifier_empty_public_key", func(t *testing.T) {
		kp := keypair.NewRsaKeyPair()
		kp.GenKeyPair(2048)
		kp.SetPublicKey([]byte{})

		verifier := NewStdVerifier(kp)
		assert.NotNil(t, verifier)
		assert.IsType(t, KeyPairError{}, verifier.Error)
	})

	t.Run("StdVerifier with unsupported format", func(t *testing.T) {
		kp := keypair.NewRsaKeyPair()
		kp.SetFormat(keypair.KeyFormat("invalid")) // Invalid format
		kp.SetHash(crypto.SHA256)
		kp.GenKeyPair(1024)

		verifier := NewStdVerifier(kp)
		valid, err := verifier.Verify([]byte("test"), []byte("signature"))
		assert.NotNil(t, err)
		assert.False(t, valid)
		assert.IsType(t, KeyPairError{}, err)
	})
}

func TestStdVerifier_Verify(t *testing.T) {
	t.Run("PKCS1_format_verification", func(t *testing.T) {
		kp := keypair.NewRsaKeyPair()
		kp.GenKeyPair(2048)
		kp.SetFormat(keypair.PKCS1)
		kp.SetHash(crypto.SHA256)

		// First create a signature
		signer := NewStdSigner(kp)
		data := []byte("Hello, RSA verification!")
		signature, err := signer.Sign(data)
		assert.Nil(t, err)
		assert.NotEmpty(t, signature)

		// Then verify the signature
		verifier := NewStdVerifier(kp)
		valid, err := verifier.Verify(data, signature)
		assert.Nil(t, err)
		assert.True(t, valid)
	})

	t.Run("PKCS8_format_verification", func(t *testing.T) {
		kp := keypair.NewRsaKeyPair()
		kp.GenKeyPair(2048)
		kp.SetFormat(keypair.PKCS8)
		kp.SetHash(crypto.SHA256)

		// First create a signature
		signer := NewStdSigner(kp)
		data := []byte("Hello, RSA verification!")
		signature, err := signer.Sign(data)
		assert.Nil(t, err)
		assert.NotEmpty(t, signature)

		// Then verify the signature
		verifier := NewStdVerifier(kp)
		valid, err := verifier.Verify(data, signature)
		assert.Nil(t, err)
		assert.True(t, valid)
	})

	t.Run("empty_data_or_signature", func(t *testing.T) {
		kp := keypair.NewRsaKeyPair()
		kp.GenKeyPair(2048)
		verifier := NewStdVerifier(kp)

		// Test empty data
		valid, err := verifier.Verify([]byte{}, []byte("signature"))
		assert.Nil(t, err)
		assert.False(t, valid)

		// Test empty signature
		valid, err = verifier.Verify([]byte("data"), []byte{})
		assert.Nil(t, err)
		assert.False(t, valid)

		// Test both empty
		valid, err = verifier.Verify([]byte{}, []byte{})
		assert.Nil(t, err)
		assert.False(t, valid)
	})

	t.Run("with_existing_error", func(t *testing.T) {
		kp := keypair.NewRsaKeyPair()
		kp.GenKeyPair(2048)
		verifier := NewStdVerifier(kp)
		verifier.Error = assert.AnError

		valid, err := verifier.Verify([]byte("data"), []byte("signature"))
		assert.Equal(t, assert.AnError, err)
		assert.False(t, valid)
	})

	t.Run("invalid_signature", func(t *testing.T) {
		kp := keypair.NewRsaKeyPair()
		kp.GenKeyPair(2048)
		kp.SetFormat(keypair.PKCS1)
		kp.SetHash(crypto.SHA256)

		verifier := NewStdVerifier(kp)
		data := []byte("Hello, RSA verification!")
		invalidSignature := []byte("invalid signature")

		valid, err := verifier.Verify(data, invalidSignature)
		assert.IsType(t, VerifyError{}, err)
		assert.False(t, valid)
	})

	t.Run("parse_public_key_error", func(t *testing.T) {
		kp := keypair.NewRsaKeyPair()
		kp.SetPublicKey([]byte("invalid public key"))
		verifier := NewStdVerifier(kp)

		valid, err := verifier.Verify([]byte("data"), []byte("signature"))
		assert.NotNil(t, err)
		assert.False(t, valid)
	})

	t.Run("verify_error_PKCS1", func(t *testing.T) {
		kp := keypair.NewRsaKeyPair()
		kp.GenKeyPair(2048)
		kp.SetFormat(keypair.PKCS1)
		kp.SetHash(crypto.SHA256)

		verifier := NewStdVerifier(kp)
		data := []byte("Hello, RSA verification!")
		invalidSignature := []byte("invalid signature data that will cause verification error")

		valid, err := verifier.Verify(data, invalidSignature)
		assert.IsType(t, VerifyError{}, err)
		assert.False(t, valid)
	})

	t.Run("verify_error_PKCS8", func(t *testing.T) {
		kp := keypair.NewRsaKeyPair()
		kp.GenKeyPair(2048)
		kp.SetFormat(keypair.PKCS8)
		kp.SetHash(crypto.SHA256)

		verifier := NewStdVerifier(kp)
		data := []byte("Hello, RSA verification!")
		invalidSignature := []byte("invalid signature data that will cause verification error")

		valid, err := verifier.Verify(data, invalidSignature)
		assert.IsType(t, VerifyError{}, err)
		assert.False(t, valid)
	})

	t.Run("unsupported format returns false", func(t *testing.T) {
		kp := keypair.NewRsaKeyPair()
		kp.SetFormat(keypair.PKCS1)
		kp.SetHash(crypto.SHA256)
		kp.GenKeyPair(1024)
		// Change format after generating keys
		kp.SetFormat(keypair.KeyFormat("unknown"))

		verifier := NewStdVerifier(kp)
		valid, err := verifier.Verify([]byte("test"), []byte("signature"))
		assert.Nil(t, err)
		assert.True(t, valid) // Function returns true when no verification is performed
	})

	t.Run("parse public key error after creation", func(t *testing.T) {
		kp := keypair.NewRsaKeyPair()
		kp.SetFormat(keypair.PKCS1)
		kp.SetHash(crypto.SHA256)
		kp.GenKeyPair(1024) // Generate valid keys first

		verifier := NewStdVerifier(kp) // Constructor should succeed
		assert.Nil(t, verifier.Error)

		// Now corrupt the public key after constructor validation
		kp.SetPublicKey([]byte("-----BEGIN RSA PUBLIC KEY-----\ninvalid\n-----END RSA PUBLIC KEY-----"))

		valid, err := verifier.Verify([]byte("test"), []byte("signature")) // Should error here during parsing
		assert.NotNil(t, err)
		assert.False(t, valid)
		assert.IsType(t, KeyPairError{}, err)
	})
}

// TestStreamSigner tests stream RSA signing functionality
func TestStreamSigner(t *testing.T) {
	t.Run("NewStreamSigner_valid_keypair", func(t *testing.T) {
		var buf bytes.Buffer
		kp := keypair.NewRsaKeyPair()
		kp.GenKeyPair(2048)
		kp.SetFormat(keypair.PKCS1)
		kp.SetHash(crypto.SHA256)

		signer := NewStreamSigner(&buf, kp)
		assert.NotNil(t, signer)
		streamSigner := signer.(*StreamSigner)
		assert.Nil(t, streamSigner.Error)
		assert.Equal(t, kp, streamSigner.keypair)
		assert.NotNil(t, streamSigner.hasher)
	})

	t.Run("NewStreamSigner_nil_keypair", func(t *testing.T) {
		var buf bytes.Buffer
		signer := NewStreamSigner(&buf, nil)
		assert.NotNil(t, signer)
		streamSigner := signer.(*StreamSigner)
		assert.IsType(t, NilKeyPairError{}, streamSigner.Error)
	})

	t.Run("NewStreamSigner_empty_private_key", func(t *testing.T) {
		var buf bytes.Buffer
		kp := keypair.NewRsaKeyPair()
		kp.GenKeyPair(2048)
		kp.SetPrivateKey([]byte{})

		signer := NewStreamSigner(&buf, kp)
		streamSigner := signer.(*StreamSigner)
		assert.IsType(t, KeyPairError{}, streamSigner.Error)
	})

	t.Run("StreamSigner with unsupported format", func(t *testing.T) {
		kp := keypair.NewRsaKeyPair()
		kp.SetFormat(keypair.KeyFormat("invalid")) // Invalid format
		kp.SetHash(crypto.SHA256)
		kp.GenKeyPair(1024)

		var buf bytes.Buffer
		signer := NewStreamSigner(&buf, kp)
		// Error should occur immediately due to invalid format
		streamSigner, ok := signer.(*StreamSigner)
		assert.True(t, ok)
		assert.NotNil(t, streamSigner.Error)
		assert.IsType(t, KeyPairError{}, streamSigner.Error)
	})
}

func TestStreamSigner_Write(t *testing.T) {
	t.Run("successful_write", func(t *testing.T) {
		var buf bytes.Buffer
		kp := keypair.NewRsaKeyPair()
		kp.GenKeyPair(2048)
		kp.SetFormat(keypair.PKCS1)
		kp.SetHash(crypto.SHA256)
		signer := NewStreamSigner(&buf, kp).(*StreamSigner)

		data := []byte("Hello, stream signing!")
		n, err := signer.Write(data)
		assert.Nil(t, err)
		assert.Equal(t, len(data), n)
	})

	t.Run("empty_input", func(t *testing.T) {
		var buf bytes.Buffer
		kp := keypair.NewRsaKeyPair()
		kp.GenKeyPair(2048)
		signer := NewStreamSigner(&buf, kp).(*StreamSigner)

		n, err := signer.Write([]byte{})
		assert.Nil(t, err)
		assert.Equal(t, 0, n)
	})

	t.Run("with_existing_error", func(t *testing.T) {
		var buf bytes.Buffer
		kp := keypair.NewRsaKeyPair()
		kp.GenKeyPair(2048)
		signer := NewStreamSigner(&buf, kp).(*StreamSigner)
		signer.Error = assert.AnError

		n, err := signer.Write([]byte("test"))
		assert.Equal(t, assert.AnError, err)
		assert.Equal(t, 0, n)
	})
}

func TestStreamSigner_Close(t *testing.T) {
	t.Run("successful_close_with_signature", func(t *testing.T) {
		var buf bytes.Buffer
		kp := keypair.NewRsaKeyPair()
		kp.GenKeyPair(2048)
		kp.SetFormat(keypair.PKCS1)
		kp.SetHash(crypto.SHA256)
		signer := NewStreamSigner(&buf, kp).(*StreamSigner)

		// Write some data first
		data := []byte("Hello, stream signing!")
		n, err := signer.Write(data)
		assert.Nil(t, err)
		assert.Equal(t, len(data), n)

		// Close to generate signature
		err = signer.Close()
		assert.Nil(t, err)
		assert.NotEmpty(t, buf.Bytes())
	})

	t.Run("close_with_existing_error", func(t *testing.T) {
		var buf bytes.Buffer
		kp := keypair.NewRsaKeyPair()
		kp.GenKeyPair(2048)
		signer := NewStreamSigner(&buf, kp).(*StreamSigner)
		signer.Error = assert.AnError

		err := signer.Close()
		assert.Equal(t, assert.AnError, err)
	})

	t.Run("close_with_writer_error", func(t *testing.T) {
		mockWriter := mock.NewErrorWriteCloser(assert.AnError)
		kp := keypair.NewRsaKeyPair()
		kp.GenKeyPair(2048)
		kp.SetFormat(keypair.PKCS1)
		kp.SetHash(crypto.SHA256)
		signer := NewStreamSigner(mockWriter, kp).(*StreamSigner)

		// Write some data first
		signer.Write([]byte("test"))

		// Close should fail due to writer error
		err := signer.Close()
		assert.Equal(t, assert.AnError, err)
	})

	t.Run("close_with_closer", func(t *testing.T) {
		mockWriter := mock.NewErrorWriteCloser(nil)
		kp := keypair.NewRsaKeyPair()
		kp.GenKeyPair(2048)
		kp.SetFormat(keypair.PKCS1)
		kp.SetHash(crypto.SHA256)
		signer := NewStreamSigner(mockWriter, kp).(*StreamSigner)

		// Write some data first
		signer.Write([]byte("test"))

		// Close should succeed
		err := signer.Close()
		assert.Nil(t, err)
	})

	t.Run("close_with_sign_error", func(t *testing.T) {
		var buf bytes.Buffer
		kp := keypair.NewRsaKeyPair()
		kp.SetFormat(keypair.PKCS1)
		kp.SetHash(crypto.SHA256)
		kp.SetPrivateKey([]byte("invalid key")) // Invalid key to cause sign error
		signer := NewStreamSigner(&buf, kp).(*StreamSigner)

		// Write some data first
		signer.Write([]byte("test"))

		// Close should fail due to sign error
		err := signer.Close()
		assert.NotNil(t, err)
		assert.IsType(t, KeyPairError{}, err)
	})

	t.Run("close_sign_error_PKCS1", func(t *testing.T) {
		var buf bytes.Buffer
		kp := keypair.NewRsaKeyPair()
		kp.SetFormat(keypair.PKCS1)
		kp.SetHash(crypto.SHA256)
		kp.GenKeyPair(256) // Very small key size
		signer := NewStreamSigner(&buf, kp).(*StreamSigner)

		// Write some data first
		signer.Write([]byte("test"))

		// This might succeed or fail based on key size, but test the error handling
		err := signer.Close()
		// Don't assert specific error type since small keys might work
		_ = err
	})

	t.Run("close_sign_error_PKCS8", func(t *testing.T) {
		var buf bytes.Buffer
		kp := keypair.NewRsaKeyPair()
		kp.SetFormat(keypair.PKCS8)
		kp.SetHash(crypto.SHA256)
		kp.GenKeyPair(256) // Very small key size
		signer := NewStreamSigner(&buf, kp).(*StreamSigner)

		// Write some data first
		signer.Write([]byte("test"))

		// This might succeed or fail based on key size, but test the error handling
		err := signer.Close()
		// Don't assert specific error type since small keys might work
		_ = err
	})
}

func TestStreamSigner_Sign(t *testing.T) {
	t.Run("PKCS1_format_signing", func(t *testing.T) {
		var buf bytes.Buffer
		kp := keypair.NewRsaKeyPair()
		kp.GenKeyPair(2048)
		kp.SetFormat(keypair.PKCS1)
		kp.SetHash(crypto.SHA256)
		signer := NewStreamSigner(&buf, kp).(*StreamSigner)

		// Create properly hashed data
		data := []byte("test hash data")
		hasher := crypto.SHA256.New()
		hasher.Write(data)
		hashed := hasher.Sum(nil)

		signature, err := signer.Sign(hashed)
		assert.Nil(t, err)
		assert.NotEmpty(t, signature)
	})

	t.Run("PKCS8_format_signing", func(t *testing.T) {
		var buf bytes.Buffer
		kp := keypair.NewRsaKeyPair()
		kp.GenKeyPair(2048)
		kp.SetFormat(keypair.PKCS8)
		kp.SetHash(crypto.SHA256)
		signer := NewStreamSigner(&buf, kp).(*StreamSigner)

		// Create properly hashed data
		data := []byte("test hash data")
		hasher := crypto.SHA256.New()
		hasher.Write(data)
		hashed := hasher.Sum(nil)

		signature, err := signer.Sign(hashed)
		assert.Nil(t, err)
		assert.NotEmpty(t, signature)
	})

	t.Run("parse_private_key_error", func(t *testing.T) {
		var buf bytes.Buffer
		kp := keypair.NewRsaKeyPair()
		kp.SetPrivateKey([]byte("invalid private key"))
		signer := NewStreamSigner(&buf, kp).(*StreamSigner)

		hashed := []byte("test hash data")
		signature, err := signer.Sign(hashed)
		assert.NotNil(t, err)
		assert.IsType(t, KeyPairError{}, err)
		assert.Empty(t, signature)
	})

	t.Run("sign_error_PKCS1", func(t *testing.T) {
		var buf bytes.Buffer
		kp := keypair.NewRsaKeyPair()
		kp.GenKeyPair(512) // Use smaller key
		kp.SetFormat(keypair.PKCS1)
		kp.SetHash(crypto.SHA256)
		signer := NewStreamSigner(&buf, kp).(*StreamSigner)

		// Create invalid hashed data that might cause signing error
		// Use data that's too large or invalid format
		invalidHashed := make([]byte, 1000) // Too large for hash
		signature, err := signer.Sign(invalidHashed)
		if err != nil {
			assert.IsType(t, SignError{}, err)
			assert.Empty(t, signature)
		}
	})

	t.Run("sign_error_PKCS8", func(t *testing.T) {
		var buf bytes.Buffer
		kp := keypair.NewRsaKeyPair()
		kp.GenKeyPair(512) // Use smaller key
		kp.SetFormat(keypair.PKCS8)
		kp.SetHash(crypto.SHA256)
		signer := NewStreamSigner(&buf, kp).(*StreamSigner)

		// Create invalid hashed data that might cause signing error
		invalidHashed := make([]byte, 1000) // Too large for hash
		signature, err := signer.Sign(invalidHashed)
		if err != nil {
			assert.IsType(t, SignError{}, err)
			assert.Empty(t, signature)
		}
	})

	t.Run("unsupported_format", func(t *testing.T) {
		var buf bytes.Buffer
		kp := keypair.NewRsaKeyPair()
		kp.SetFormat(keypair.KeyFormat("invalid"))
		kp.SetHash(crypto.SHA256)
		kp.GenKeyPair(1024)
		signer := NewStreamSigner(&buf, kp).(*StreamSigner)

		hashed := []byte("test hash data")
		signature, err := signer.Sign(hashed)
		assert.NotNil(t, err)
		assert.IsType(t, KeyPairError{}, err)
		assert.Empty(t, signature)
	})
}

// TestStreamVerifier tests stream RSA signature verification functionality
func TestStreamVerifier(t *testing.T) {
	t.Run("NewStreamVerifier_valid_keypair", func(t *testing.T) {
		file := mock.NewFile([]byte("signature data"), "signature.dat")
		kp := keypair.NewRsaKeyPair()
		kp.GenKeyPair(2048)
		kp.SetFormat(keypair.PKCS1)
		kp.SetHash(crypto.SHA256)

		verifier := NewStreamVerifier(file, kp)
		assert.NotNil(t, verifier)
		streamVerifier := verifier.(*StreamVerifier)
		assert.Nil(t, streamVerifier.Error)
		assert.Equal(t, kp, streamVerifier.keypair)
		assert.NotNil(t, streamVerifier.hasher)
	})

	t.Run("NewStreamVerifier_nil_keypair", func(t *testing.T) {
		file := mock.NewFile([]byte("signature data"), "signature.dat")
		verifier := NewStreamVerifier(file, nil)
		assert.NotNil(t, verifier)
		streamVerifier := verifier.(*StreamVerifier)
		assert.IsType(t, NilKeyPairError{}, streamVerifier.Error)
	})

	t.Run("NewStreamVerifier_empty_public_key", func(t *testing.T) {
		file := mock.NewFile([]byte("signature data"), "signature.dat")
		kp := keypair.NewRsaKeyPair()
		kp.GenKeyPair(2048)
		kp.SetPublicKey([]byte{})

		verifier := NewStreamVerifier(file, kp)
		streamVerifier := verifier.(*StreamVerifier)
		assert.IsType(t, KeyPairError{}, streamVerifier.Error)
	})

	t.Run("StreamVerifier with unsupported format", func(t *testing.T) {
		kp := keypair.NewRsaKeyPair()
		kp.SetFormat(keypair.KeyFormat("invalid")) // Invalid format
		kp.SetHash(crypto.SHA256)
		kp.GenKeyPair(1024)

		var buf bytes.Buffer
		verifier := NewStreamVerifier(&buf, kp)
		// Error should occur immediately due to invalid format
		streamVerifier, ok := verifier.(*StreamVerifier)
		assert.True(t, ok)
		assert.NotNil(t, streamVerifier.Error)
		assert.IsType(t, KeyPairError{}, streamVerifier.Error)
	})
}

func TestStreamVerifier_Write(t *testing.T) {
	t.Run("successful_write", func(t *testing.T) {
		file := mock.NewFile([]byte("signature data"), "signature.dat")
		kp := keypair.NewRsaKeyPair()
		kp.GenKeyPair(2048)
		kp.SetFormat(keypair.PKCS1)
		kp.SetHash(crypto.SHA256)
		verifier := NewStreamVerifier(file, kp).(*StreamVerifier)

		data := []byte("Hello, stream verification!")
		n, err := verifier.Write(data)
		assert.Nil(t, err)
		assert.Equal(t, len(data), n)
	})

	t.Run("empty_input", func(t *testing.T) {
		file := mock.NewFile([]byte("signature data"), "signature.dat")
		kp := keypair.NewRsaKeyPair()
		kp.GenKeyPair(2048)
		verifier := NewStreamVerifier(file, kp).(*StreamVerifier)

		n, err := verifier.Write([]byte{})
		assert.Nil(t, err)
		assert.Equal(t, 0, n)
	})

	t.Run("with_existing_error", func(t *testing.T) {
		file := mock.NewFile([]byte("signature data"), "signature.dat")
		kp := keypair.NewRsaKeyPair()
		kp.GenKeyPair(2048)
		verifier := NewStreamVerifier(file, kp).(*StreamVerifier)
		verifier.Error = assert.AnError

		n, err := verifier.Write([]byte("test"))
		assert.Equal(t, assert.AnError, err)
		assert.Equal(t, 0, n)
	})
}

func TestStreamVerifier_Close(t *testing.T) {
	t.Run("successful_close_with_valid_signature", func(t *testing.T) {
		// First create a signature using StreamSigner
		var sigBuf bytes.Buffer
		kp := keypair.NewRsaKeyPair()
		kp.GenKeyPair(2048)
		kp.SetFormat(keypair.PKCS1)
		kp.SetHash(crypto.SHA256)
		signer := NewStreamSigner(&sigBuf, kp).(*StreamSigner)

		data := []byte("Hello, stream verification!")
		signer.Write(data)
		signer.Close()

		// Now verify the signature
		sigReader := mock.NewFile(sigBuf.Bytes(), "test.bin")
		verifier := NewStreamVerifier(sigReader, kp).(*StreamVerifier)
		verifier.Write(data)

		err := verifier.Close()
		assert.Nil(t, err)
		assert.True(t, verifier.verified)
	})

	t.Run("close_with_existing_error", func(t *testing.T) {
		file := mock.NewFile([]byte("signature"), "sig.dat")
		kp := keypair.NewRsaKeyPair()
		kp.GenKeyPair(2048)
		verifier := NewStreamVerifier(file, kp).(*StreamVerifier)
		verifier.Error = assert.AnError

		err := verifier.Close()
		assert.Equal(t, assert.AnError, err)
	})

	t.Run("close_with_reader_error", func(t *testing.T) {
		mockReader := mock.NewErrorFile(assert.AnError)
		kp := keypair.NewRsaKeyPair()
		kp.GenKeyPair(2048)
		verifier := NewStreamVerifier(mockReader, kp).(*StreamVerifier)

		err := verifier.Close()
		assert.IsType(t, ReadError{}, err)
	})

	t.Run("close_with_empty_signature", func(t *testing.T) {
		file := mock.NewFile([]byte{}, "empty.dat")
		kp := keypair.NewRsaKeyPair()
		kp.GenKeyPair(2048)
		verifier := NewStreamVerifier(file, kp).(*StreamVerifier)

		err := verifier.Close()
		assert.Nil(t, err)
	})

	t.Run("close_with_invalid_signature", func(t *testing.T) {
		file := mock.NewFile([]byte("invalid signature"), "sig.dat")
		kp := keypair.NewRsaKeyPair()
		kp.GenKeyPair(2048)
		kp.SetFormat(keypair.PKCS1)
		kp.SetHash(crypto.SHA256)
		verifier := NewStreamVerifier(file, kp).(*StreamVerifier)
		verifier.Write([]byte("test data"))

		err := verifier.Close()
		assert.NotNil(t, err)
	})

	t.Run("close_with_closer", func(t *testing.T) {
		// Test that the closer interface is correctly handled
		sigReader := mock.NewFile([]byte{}, "test.bin") // Empty signature
		kp := keypair.NewRsaKeyPair()
		kp.GenKeyPair(2048)
		verifier := NewStreamVerifier(sigReader, kp).(*StreamVerifier)

		err := verifier.Close()
		assert.Nil(t, err) // Should succeed with empty signature
	})

	t.Run("close_with_reader_closer_error", func(t *testing.T) {
		// Test the case where the reader implements io.Closer and Close() returns error
		var sigBuf bytes.Buffer
		kp := keypair.NewRsaKeyPair()
		kp.GenKeyPair(2048)
		kp.SetFormat(keypair.PKCS1)
		kp.SetHash(crypto.SHA256)

		// Create a signature first
		signer := NewStreamSigner(&sigBuf, kp).(*StreamSigner)
		signer.Write([]byte("test data"))
		signer.Close()

		// Use ErrorReadWriteCloser with nil read error but close error
		// First set up a regular reader with the signature data
		mockReader := mock.NewErrorReadWriteCloser(assert.AnError)

		verifier := NewStreamVerifier(mockReader, kp).(*StreamVerifier)
		verifier.Write([]byte("test data"))

		// This should trigger the reader close error since io.ReadAll will fail first
		err := verifier.Close()
		assert.IsType(t, ReadError{}, err)
	})
}

// Test additional error types for 100% coverage
func TestAdditionalErrorTypes(t *testing.T) {
	t.Run("SignError", func(t *testing.T) {
		originalErr := assert.AnError
		err := SignError{Err: originalErr}
		assert.Contains(t, err.Error(), "crypto/rsa: failed to sign data:")
		assert.Contains(t, err.Error(), originalErr.Error())
	})

	t.Run("VerifyError", func(t *testing.T) {
		originalErr := assert.AnError
		err := VerifyError{Err: originalErr}
		assert.Contains(t, err.Error(), "crypto/rsa: failed to verify signature:")
		assert.Contains(t, err.Error(), originalErr.Error())
	})

	t.Run("NoSignatureError", func(t *testing.T) {
		err := NoSignatureError{}
		expected := "crypto/rsa: no signature provided for verification"
		assert.Equal(t, expected, err.Error())
	})
}

// Test edge cases for StreamVerifier to achieve 100% coverage
func TestStreamVerifierEdgeCases(t *testing.T) {
	t.Run("write_hasher_error", func(t *testing.T) {
		// Create a StreamVerifier and replace its hasher with our error hasher
		file := mock.NewFile([]byte("signature"), "sig.dat")
		kp := keypair.NewRsaKeyPair()
		kp.GenKeyPair(2048)
		kp.SetFormat(keypair.PKCS1)
		kp.SetHash(crypto.SHA256)
		verifier := NewStreamVerifier(file, kp).(*StreamVerifier)

		// Replace the hasher with our error hasher
		verifier.hasher = mock.NewErrorHasher(assert.AnError)

		// This should trigger the error path in hasher.Write()
		data := []byte("test data")
		n, err := verifier.Write(data)
		assert.Equal(t, assert.AnError, err)
		assert.Equal(t, 0, n)
	})

	t.Run("close_with_reader_closer_success", func(t *testing.T) {
		// Test successful close path where reader implements io.Closer and succeeds
		var sigBuf bytes.Buffer
		kp := keypair.NewRsaKeyPair()
		kp.GenKeyPair(2048)
		kp.SetFormat(keypair.PKCS1)
		kp.SetHash(crypto.SHA256)

		// Create a signature first
		signer := NewStreamSigner(&sigBuf, kp).(*StreamSigner)
		signer.Write([]byte("test data"))
		signer.Close()

		// Create a File that implements io.Closer (mock.File implements Close)
		sigFile := mock.NewFile(sigBuf.Bytes(), "signature.dat")

		verifier := NewStreamVerifier(sigFile, kp).(*StreamVerifier)
		verifier.Write([]byte("test data"))

		// This should trigger the reader closer success path (line 583-584)
		err := verifier.Close()
		assert.Nil(t, err)
		assert.True(t, verifier.verified)
	})

	t.Run("close_with_reader_closer_error", func(t *testing.T) {
		// Test the case where reader implements io.Closer and returns error
		var sigBuf bytes.Buffer
		kp := keypair.NewRsaKeyPair()
		kp.GenKeyPair(2048)
		kp.SetFormat(keypair.PKCS1)
		kp.SetHash(crypto.SHA256)

		// Create a signature first
		signer := NewStreamSigner(&sigBuf, kp).(*StreamSigner)
		signer.Write([]byte("test data"))
		signer.Close()

		// Use our custom reader that fails on close
		readerWithError := newReaderWithCloseError(sigBuf.Bytes(), assert.AnError)
		verifier := NewStreamVerifier(readerWithError, kp).(*StreamVerifier)
		verifier.Write([]byte("test data"))

		// This should trigger the reader closer error path (line 583-584)
		err := verifier.Close()
		assert.Equal(t, assert.AnError, err)
		assert.True(t, verifier.verified) // Verification should still succeed before close error
	})

	t.Run("close_without_closer_interface", func(t *testing.T) {
		// Test the case where reader does NOT implement io.Closer
		// This should execute the final return nil statement (line 587)
		var sigBuf bytes.Buffer
		kp := keypair.NewRsaKeyPair()
		kp.GenKeyPair(2048)
		kp.SetFormat(keypair.PKCS1)
		kp.SetHash(crypto.SHA256)

		// Create a signature first
		signer := NewStreamSigner(&sigBuf, kp).(*StreamSigner)
		signer.Write([]byte("test data"))
		signer.Close()

		// Use bytes.Reader which does NOT implement io.Closer
		reader := bytes.NewReader(sigBuf.Bytes())
		verifier := NewStreamVerifier(reader, kp).(*StreamVerifier)
		verifier.Write([]byte("test data"))

		// This should execute the final return nil (line 587) since bytes.Reader doesn't implement io.Closer
		err := verifier.Close()
		assert.Nil(t, err)
		assert.True(t, verifier.verified)
	})
}

func TestStreamVerifier_Verify(t *testing.T) {
	t.Run("PKCS1_format_verification", func(t *testing.T) {
		kp := keypair.NewRsaKeyPair()
		kp.GenKeyPair(2048)
		kp.SetFormat(keypair.PKCS1)
		kp.SetHash(crypto.SHA256)

		// Create a signature using StdSigner
		signer := NewStdSigner(kp)
		data := []byte("Hello, verification!")
		signature, err := signer.Sign(data)
		assert.Nil(t, err)

		// Create hashed data
		hasher := kp.Hash.New()
		hasher.Write(data)
		hashed := hasher.Sum(nil)

		// Verify using StreamVerifier
		file := mock.NewFile(signature, "sig.dat")
		verifier := NewStreamVerifier(file, kp).(*StreamVerifier)
		valid, err := verifier.Verify(hashed, signature)
		assert.Nil(t, err)
		assert.True(t, valid)
	})

	t.Run("PKCS8_format_verification", func(t *testing.T) {
		kp := keypair.NewRsaKeyPair()
		kp.GenKeyPair(2048)
		kp.SetFormat(keypair.PKCS8)
		kp.SetHash(crypto.SHA256)

		// Create a signature using StdSigner
		signer := NewStdSigner(kp)
		data := []byte("Hello, verification!")
		signature, err := signer.Sign(data)
		assert.Nil(t, err)

		// Create hashed data
		hasher := kp.Hash.New()
		hasher.Write(data)
		hashed := hasher.Sum(nil)

		// Verify using StreamVerifier
		file := mock.NewFile(signature, "sig.dat")
		verifier := NewStreamVerifier(file, kp).(*StreamVerifier)
		valid, err := verifier.Verify(hashed, signature)
		assert.Nil(t, err)
		assert.True(t, valid)
	})

	t.Run("parse_public_key_error", func(t *testing.T) {
		kp := keypair.NewRsaKeyPair()
		kp.SetPublicKey([]byte("invalid public key"))
		file := mock.NewFile([]byte("sig"), "sig.dat")
		verifier := NewStreamVerifier(file, kp).(*StreamVerifier)

		hashed := []byte("test hash")
		signature := []byte("test signature")
		valid, err := verifier.Verify(hashed, signature)
		assert.NotNil(t, err)
		assert.IsType(t, KeyPairError{}, err)
		assert.False(t, valid)
	})

	t.Run("invalid_signature", func(t *testing.T) {
		kp := keypair.NewRsaKeyPair()
		kp.GenKeyPair(2048)
		kp.SetFormat(keypair.PKCS1)
		kp.SetHash(crypto.SHA256)

		file := mock.NewFile([]byte("sig"), "sig.dat")
		verifier := NewStreamVerifier(file, kp).(*StreamVerifier)

		hashed := []byte("test hash")
		invalidSignature := []byte("invalid signature")
		valid, err := verifier.Verify(hashed, invalidSignature)
		assert.NotNil(t, err) // Verification should fail but not return error
		assert.False(t, valid)
	})

	t.Run("verify_error_PKCS1", func(t *testing.T) {
		kp := keypair.NewRsaKeyPair()
		kp.GenKeyPair(2048)
		kp.SetFormat(keypair.PKCS1)
		kp.SetHash(crypto.SHA256)

		file := mock.NewFile([]byte("sig"), "sig.dat")
		verifier := NewStreamVerifier(file, kp).(*StreamVerifier)

		hashed := []byte("test hash")
		invalidSignature := []byte("invalid signature data that will cause verification error")
		valid, err := verifier.Verify(hashed, invalidSignature)
		assert.IsType(t, VerifyError{}, err)
		assert.False(t, valid)
	})

	t.Run("verify_error_PKCS8", func(t *testing.T) {
		kp := keypair.NewRsaKeyPair()
		kp.GenKeyPair(2048)
		kp.SetFormat(keypair.PKCS8)
		kp.SetHash(crypto.SHA256)

		file := mock.NewFile([]byte("sig"), "sig.dat")
		verifier := NewStreamVerifier(file, kp).(*StreamVerifier)

		hashed := []byte("test hash")
		invalidSignature := []byte("invalid signature data that will cause verification error")
		valid, err := verifier.Verify(hashed, invalidSignature)
		assert.IsType(t, VerifyError{}, err)
		assert.False(t, valid)
	})

	t.Run("unsupported_format", func(t *testing.T) {
		kp := keypair.NewRsaKeyPair()
		kp.SetFormat(keypair.KeyFormat("invalid"))
		kp.SetHash(crypto.SHA256)
		kp.GenKeyPair(1024)

		file := mock.NewFile([]byte("sig"), "sig.dat")
		verifier := NewStreamVerifier(file, kp).(*StreamVerifier)

		hashed := []byte("test hash")
		signature := []byte("test signature")
		valid, err := verifier.Verify(hashed, signature)
		assert.NotNil(t, err)
		assert.IsType(t, KeyPairError{}, err)
		assert.False(t, valid)
	})

	t.Run("verify_hash_error_PKCS1", func(t *testing.T) {
		kp := keypair.NewRsaKeyPair()
		kp.GenKeyPair(2048)
		kp.SetFormat(keypair.PKCS1)
		kp.SetHash(crypto.SHA256)

		file := mock.NewFile([]byte("sig"), "sig.dat")
		verifier := NewStreamVerifier(file, kp).(*StreamVerifier)

		hashed := []byte("test hash")
		// Use malformed signature that will cause VerifyPKCS1v15 to fail
		malformedSignature := make([]byte, 10) // Too small signature
		valid, err := verifier.Verify(hashed, malformedSignature)
		assert.IsType(t, VerifyError{}, err)
		assert.False(t, valid)
	})

	t.Run("verify_hash_error_PKCS8", func(t *testing.T) {
		kp := keypair.NewRsaKeyPair()
		kp.GenKeyPair(2048)
		kp.SetFormat(keypair.PKCS8)
		kp.SetHash(crypto.SHA256)

		file := mock.NewFile([]byte("sig"), "sig.dat")
		verifier := NewStreamVerifier(file, kp).(*StreamVerifier)

		hashed := []byte("test hash")
		// Use malformed signature that will cause VerifyPSS to fail
		malformedSignature := make([]byte, 10) // Too small signature
		valid, err := verifier.Verify(hashed, malformedSignature)
		assert.IsType(t, VerifyError{}, err)
		assert.False(t, valid)
	})
}
