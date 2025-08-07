package des

import (
	"bytes"
	stdcipher "crypto/cipher"
	"io"
	"testing"

	"github.com/dromara/dongle/crypto/cipher"
	"github.com/dromara/dongle/mock"
	"github.com/stretchr/testify/assert"
)

// mk is a mock implementation of cipher.CipherInterface for testing
type mk struct {
	encryptError error
	decryptError error
}

func (m *mk) Encrypt(src []byte, block stdcipher.Block) ([]byte, error) {
	if m.encryptError != nil {
		return nil, m.encryptError
	}
	return []byte("encrypted"), nil
}

func (m *mk) Decrypt(src []byte, block stdcipher.Block) ([]byte, error) {
	if m.decryptError != nil {
		return nil, m.decryptError
	}
	return []byte("decrypted"), nil
}

// TestDESPadding tests DES encryption with various padding modes including PKCS7
func TestDESPadding(t *testing.T) {
	tests := []struct {
		name      string
		key       []byte
		iv        []byte
		plaintext []byte
		mode      func() cipher.CipherInterface
	}{
		{
			name:      "CBC with PKCS7 padding",
			key:       []byte("12345678"),
			iv:        []byte("87654321"),
			plaintext: []byte("hello world"),
			mode: func() cipher.CipherInterface {
				c := cipher.NewCBCCipher()
				c.SetKey([]byte("12345678"))
				c.SetIV([]byte("87654321"))
				c.SetPadding(cipher.PKCS7)
				return c
			},
		},
		{
			name:      "CBC with No padding",
			key:       []byte("12345678"),
			iv:        []byte("87654321"),
			plaintext: []byte("12345678"), // 8 bytes, exact block size
			mode: func() cipher.CipherInterface {
				c := cipher.NewCBCCipher()
				c.SetKey([]byte("12345678"))
				c.SetIV([]byte("87654321"))
				c.SetPadding(cipher.No)
				return c
			},
		},
		{
			name:      "CBC with Empty padding",
			key:       []byte("12345678"),
			iv:        []byte("87654321"),
			plaintext: []byte("hello world"),
			mode: func() cipher.CipherInterface {
				c := cipher.NewCBCCipher()
				c.SetKey([]byte("12345678"))
				c.SetIV([]byte("87654321"))
				c.SetPadding(cipher.Empty)
				return c
			},
		},
		{
			name:      "CBC with Zero padding",
			key:       []byte("12345678"),
			iv:        []byte("87654321"),
			plaintext: []byte("hello world"),
			mode: func() cipher.CipherInterface {
				c := cipher.NewCBCCipher()
				c.SetKey([]byte("12345678"))
				c.SetIV([]byte("87654321"))
				c.SetPadding(cipher.Zero)
				return c
			},
		},
		{
			name:      "CBC with ANSI X.923 padding",
			key:       []byte("12345678"),
			iv:        []byte("87654321"),
			plaintext: []byte("hello world"),
			mode: func() cipher.CipherInterface {
				c := cipher.NewCBCCipher()
				c.SetKey([]byte("12345678"))
				c.SetIV([]byte("87654321"))
				c.SetPadding(cipher.AnsiX923)
				return c
			},
		},
		{
			name:      "CBC with ISO9797-1 padding",
			key:       []byte("12345678"),
			iv:        []byte("87654321"),
			plaintext: []byte("hello world"),
			mode: func() cipher.CipherInterface {
				c := cipher.NewCBCCipher()
				c.SetKey([]byte("12345678"))
				c.SetIV([]byte("87654321"))
				c.SetPadding(cipher.ISO97971)
				return c
			},
		},
		{
			name:      "CBC with ISO10126 padding",
			key:       []byte("12345678"),
			iv:        []byte("87654321"),
			plaintext: []byte("hello world"),
			mode: func() cipher.CipherInterface {
				c := cipher.NewCBCCipher()
				c.SetKey([]byte("12345678"))
				c.SetIV([]byte("87654321"))
				c.SetPadding(cipher.ISO10126)
				return c
			},
		},
		{
			name:      "CBC with ISO7816-4 padding",
			key:       []byte("12345678"),
			iv:        []byte("87654321"),
			plaintext: []byte("hello world"),
			mode: func() cipher.CipherInterface {
				c := cipher.NewCBCCipher()
				c.SetKey([]byte("12345678"))
				c.SetIV([]byte("87654321"))
				c.SetPadding(cipher.ISO78164)
				return c
			},
		},
		{
			name:      "CBC with Bit padding",
			key:       []byte("12345678"),
			iv:        []byte("87654321"),
			plaintext: []byte("hello world"),
			mode: func() cipher.CipherInterface {
				c := cipher.NewCBCCipher()
				c.SetKey([]byte("12345678"))
				c.SetIV([]byte("87654321"))
				c.SetPadding(cipher.Bit)
				return c
			},
		},
		{
			name:      "ECB with PKCS7 padding",
			key:       []byte("12345678"),
			plaintext: []byte("hello world"),
			mode: func() cipher.CipherInterface {
				c := cipher.NewECBCipher()
				c.SetKey([]byte("12345678"))
				c.SetPadding(cipher.PKCS7)
				return c
			},
		},
		{
			name:      "ECB with No padding",
			key:       []byte("12345678"),
			plaintext: []byte("12345678"), // 8 bytes, exact block size
			mode: func() cipher.CipherInterface {
				c := cipher.NewECBCipher()
				c.SetKey([]byte("12345678"))
				c.SetPadding(cipher.No)
				return c
			},
		},
		{
			name:      "ECB with Empty padding",
			key:       []byte("12345678"),
			plaintext: []byte("hello world"),
			mode: func() cipher.CipherInterface {
				c := cipher.NewECBCipher()
				c.SetKey([]byte("12345678"))
				c.SetPadding(cipher.Empty)
				return c
			},
		},
		{
			name:      "ECB with Zero padding",
			key:       []byte("12345678"),
			plaintext: []byte("hello world"),
			mode: func() cipher.CipherInterface {
				c := cipher.NewECBCipher()
				c.SetKey([]byte("12345678"))
				c.SetPadding(cipher.Zero)
				return c
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := tt.mode()
			enc := NewStdEncrypter(c, tt.key)
			assert.Nil(t, enc.Error)

			encrypted, err := enc.Encrypt(tt.plaintext)
			assert.Nil(t, err)
			assert.NotEmpty(t, encrypted)

			dec := NewStdDecrypter(c, tt.key)
			assert.Nil(t, dec.Error)

			decrypted, err := dec.Decrypt(encrypted)
			assert.Nil(t, err)
			assert.Equal(t, tt.plaintext, decrypted)
		})
	}
}

func TestNewStdEncrypter(t *testing.T) {
	t.Run("valid 8-byte key", func(t *testing.T) {
		c := cipher.NewCBCCipher()
		c.SetKey([]byte("12345678"))
		c.SetIV([]byte("87654321"))
		c.SetPadding(cipher.PKCS7)

		enc := NewStdEncrypter(c, []byte("12345678"))
		assert.Nil(t, enc.Error)
		assert.Equal(t, []byte("12345678"), enc.key)
		assert.Equal(t, c, enc.cipher)
	})

	t.Run("invalid key length", func(t *testing.T) {
		c := cipher.NewCBCCipher()
		enc := NewStdEncrypter(c, []byte("1234567")) // 7 bytes
		assert.NotNil(t, enc.Error)
		assert.Equal(t, enc.Error, KeySizeError(7))
	})
}

func TestStdEncrypter_Encrypt(t *testing.T) {
	t.Run("CBC mode encryption", func(t *testing.T) {
		c := cipher.NewCBCCipher()
		c.SetKey([]byte("12345678"))
		c.SetIV([]byte("87654321"))
		c.SetPadding(cipher.PKCS7)

		enc := NewStdEncrypter(c, []byte("12345678"))
		encrypted, err := enc.Encrypt([]byte("Hello, DES!"))
		assert.Nil(t, err)
		assert.NotEmpty(t, encrypted)
	})

	t.Run("CTR mode encryption", func(t *testing.T) {
		c := cipher.NewCTRCipher()
		c.SetKey([]byte("12345678"))
		c.SetIV([]byte("87654321"))

		enc := NewStdEncrypter(c, []byte("12345678"))
		encrypted, err := enc.Encrypt([]byte("Hello, DES CTR!"))
		assert.Nil(t, err)
		assert.NotEmpty(t, encrypted)
	})

	t.Run("ECB mode encryption", func(t *testing.T) {
		c := cipher.NewECBCipher()
		c.SetKey([]byte("12345678"))
		c.SetPadding(cipher.PKCS7)

		enc := NewStdEncrypter(c, []byte("12345678"))
		encrypted, err := enc.Encrypt([]byte("Hello, DES ECB!"))
		assert.Nil(t, err)
		assert.NotEmpty(t, encrypted)
	})

	t.Run("empty input", func(t *testing.T) {
		c := cipher.NewCBCCipher()
		c.SetKey([]byte("12345678"))
		c.SetIV([]byte("87654321"))
		c.SetPadding(cipher.PKCS7)

		enc := NewStdEncrypter(c, []byte("12345678"))
		encrypted, err := enc.Encrypt([]byte{})
		assert.Nil(t, err)
		// DES with empty input returns nil
		assert.Nil(t, encrypted)
	})

	t.Run("with error", func(t *testing.T) {
		c := cipher.NewCBCCipher()
		enc := NewStdEncrypter(c, []byte("1234567")) // Invalid key
		encrypted, err := enc.Encrypt([]byte("test"))
		assert.NotNil(t, err)
		assert.Nil(t, encrypted)
		assert.Equal(t, err, KeySizeError(7))
	})

	t.Run("with cipher error", func(t *testing.T) {
		// Create a mock cipher that returns error
		mc := &mk{encryptError: assert.AnError}
		enc := NewStdEncrypter(mc, []byte("12345678"))
		encrypted, err := enc.Encrypt([]byte("test"))
		assert.NotNil(t, err)
		assert.Nil(t, encrypted)
		assert.IsType(t, EncryptError{}, err)
	})
}

func TestNewStdDecrypter(t *testing.T) {
	t.Run("valid 8-byte key", func(t *testing.T) {
		c := cipher.NewCBCCipher()
		c.SetKey([]byte("12345678"))
		c.SetIV([]byte("87654321"))
		c.SetPadding(cipher.PKCS7)

		dec := NewStdDecrypter(c, []byte("12345678"))
		assert.Nil(t, dec.Error)
		assert.Equal(t, []byte("12345678"), dec.key)
		assert.Equal(t, c, dec.cipher)
	})

	t.Run("invalid key length", func(t *testing.T) {
		c := cipher.NewCBCCipher()
		dec := NewStdDecrypter(c, []byte("1234567")) // 7 bytes
		assert.NotNil(t, dec.Error)
		assert.Equal(t, dec.Error, KeySizeError(7))
	})
}

func TestStdDecrypter_Decrypt(t *testing.T) {
	t.Run("CBC mode decryption", func(t *testing.T) {
		c := cipher.NewCBCCipher()
		c.SetKey([]byte("12345678"))
		c.SetIV([]byte("87654321"))
		c.SetPadding(cipher.PKCS7)

		// First encrypt
		enc := NewStdEncrypter(c, []byte("12345678"))
		encrypted, err := enc.Encrypt([]byte("Hello, DES!"))
		assert.Nil(t, err)

		// Then decrypt
		dec := NewStdDecrypter(c, []byte("12345678"))
		decrypted, err := dec.Decrypt(encrypted)
		assert.Nil(t, err)
		assert.Equal(t, "Hello, DES!", string(decrypted))
	})

	t.Run("CTR mode decryption", func(t *testing.T) {
		c := cipher.NewCTRCipher()
		c.SetKey([]byte("12345678"))
		c.SetIV([]byte("87654321"))

		// First encrypt
		enc := NewStdEncrypter(c, []byte("12345678"))
		encrypted, err := enc.Encrypt([]byte("Hello, DES CTR!"))
		assert.Nil(t, err)

		// Then decrypt
		dec := NewStdDecrypter(c, []byte("12345678"))
		decrypted, err := dec.Decrypt(encrypted)
		assert.Nil(t, err)
		assert.Equal(t, "Hello, DES CTR!", string(decrypted))
	})

	t.Run("ECB mode decryption", func(t *testing.T) {
		c := cipher.NewECBCipher()
		c.SetKey([]byte("12345678"))
		c.SetPadding(cipher.PKCS7)

		// First encrypt
		enc := NewStdEncrypter(c, []byte("12345678"))
		encrypted, err := enc.Encrypt([]byte("Hello, DES ECB!"))
		assert.Nil(t, err)

		// Then decrypt
		dec := NewStdDecrypter(c, []byte("12345678"))
		decrypted, err := dec.Decrypt(encrypted)
		assert.Nil(t, err)
		assert.Equal(t, "Hello, DES ECB!", string(decrypted))
	})

	t.Run("empty input", func(t *testing.T) {
		c := cipher.NewCBCCipher()
		c.SetKey([]byte("12345678"))
		c.SetIV([]byte("87654321"))
		c.SetPadding(cipher.PKCS7)

		dec := NewStdDecrypter(c, []byte("12345678"))
		decrypted, err := dec.Decrypt([]byte{})
		assert.Nil(t, err)
		// Empty input should return nil
		assert.Nil(t, decrypted)
	})

	t.Run("with error", func(t *testing.T) {
		c := cipher.NewCBCCipher()
		dec := NewStdDecrypter(c, []byte("1234567")) // Invalid key
		decrypted, err := dec.Decrypt([]byte("test"))
		assert.NotNil(t, err)
		assert.Nil(t, decrypted)
		assert.Equal(t, err, KeySizeError(7))
	})

	t.Run("with cipher error", func(t *testing.T) {
		// Create a mock cipher that returns error
		mc := &mk{decryptError: assert.AnError}
		dec := NewStdDecrypter(mc, []byte("12345678"))
		decrypted, err := dec.Decrypt([]byte("test"))
		assert.NotNil(t, err)
		assert.Nil(t, decrypted)
		assert.IsType(t, DecryptError{}, err)
	})
}

func TestNewStreamEncrypter(t *testing.T) {
	t.Run("valid 8-byte key", func(t *testing.T) {
		c := cipher.NewCBCCipher()
		c.SetKey([]byte("12345678"))
		c.SetIV([]byte("87654321"))
		c.SetPadding(cipher.PKCS7)

		var buf bytes.Buffer
		enc := NewStreamEncrypter(&buf, c, []byte("12345678"))
		// Test that we can write to it
		n, err := enc.Write([]byte("test"))
		assert.Nil(t, err)
		assert.Greater(t, n, 0)
	})

	t.Run("invalid key length", func(t *testing.T) {
		c := cipher.NewCBCCipher()
		var buf bytes.Buffer
		enc := NewStreamEncrypter(&buf, c, []byte("1234567")) // 7 bytes
		// Test that we get an error when writing
		n, err := enc.Write([]byte("test"))
		assert.NotNil(t, err)
		assert.Equal(t, 0, n)
		assert.Equal(t, err, KeySizeError(7))
	})
}

func TestStreamEncrypter_Write(t *testing.T) {
	t.Run("CTR mode streaming", func(t *testing.T) {
		c := cipher.NewCTRCipher()
		c.SetKey([]byte("12345678"))
		c.SetIV([]byte("87654321"))

		var buf bytes.Buffer
		enc := NewStreamEncrypter(&buf, c, []byte("12345678"))
		n, err := enc.Write([]byte("Hello, streaming!"))
		assert.Nil(t, err)
		assert.Greater(t, n, 0)
		assert.NotEmpty(t, buf.Bytes())
	})

	t.Run("CBC mode streaming", func(t *testing.T) {
		c := cipher.NewCBCCipher()
		c.SetKey([]byte("12345678"))
		c.SetIV([]byte("87654321"))
		c.SetPadding(cipher.PKCS7)

		var buf bytes.Buffer
		enc := NewStreamEncrypter(&buf, c, []byte("12345678"))
		n, err := enc.Write([]byte("Hello, streaming!"))
		assert.Nil(t, err)
		assert.Greater(t, n, 0)
		assert.NotEmpty(t, buf.Bytes())
	})

	t.Run("empty input", func(t *testing.T) {
		c := cipher.NewCTRCipher()
		c.SetKey([]byte("12345678"))
		c.SetIV([]byte("87654321"))

		var buf bytes.Buffer
		enc := NewStreamEncrypter(&buf, c, []byte("12345678"))
		n, err := enc.Write([]byte{})
		assert.Nil(t, err)
		assert.Equal(t, 0, n)
	})

	t.Run("with error", func(t *testing.T) {
		c := cipher.NewCBCCipher()
		var buf bytes.Buffer
		enc := NewStreamEncrypter(&buf, c, []byte("1234567")) // Invalid key
		n, err := enc.Write([]byte("test"))
		assert.NotNil(t, err)
		assert.Equal(t, 0, n)
		assert.Equal(t, err, KeySizeError(7))
	})

	t.Run("with writer error", func(t *testing.T) {
		c := cipher.NewCTRCipher()
		c.SetKey([]byte("12345678"))
		c.SetIV([]byte("87654321"))

		// Use mock writer that returns error on write
		mockWriter := mock.NewErrorWriteCloser(assert.AnError)
		enc := NewStreamEncrypter(mockWriter, c, []byte("12345678"))
		n, err := enc.Write([]byte("test"))
		assert.Equal(t, assert.AnError, err)
		assert.Equal(t, 0, n)
	})

	t.Run("with encrypt error", func(t *testing.T) {
		// Create a mock cipher that returns error on encrypt
		mc := &mk{encryptError: assert.AnError}
		var buf bytes.Buffer
		enc := NewStreamEncrypter(&buf, mc, []byte("12345678"))
		n, err := enc.Write([]byte("test"))
		assert.NotNil(t, err)
		assert.Equal(t, 0, n)
		assert.IsType(t, EncryptError{}, err)
		assert.Contains(t, err.Error(), assert.AnError.Error())
	})
}

func TestStreamEncrypter_Close(t *testing.T) {
	t.Run("with closer", func(t *testing.T) {
		c := cipher.NewCTRCipher()
		c.SetKey([]byte("12345678"))
		c.SetIV([]byte("87654321"))

		// Use mock writer that implements io.Closer
		mockWriter := mock.NewErrorWriteCloser(nil)
		enc := NewStreamEncrypter(mockWriter, c, []byte("12345678"))
		err := enc.Close()
		assert.Nil(t, err)
	})

	t.Run("without closer", func(t *testing.T) {
		c := cipher.NewCTRCipher()
		c.SetKey([]byte("12345678"))
		c.SetIV([]byte("87654321"))

		var buf bytes.Buffer
		enc := NewStreamEncrypter(&buf, c, []byte("12345678"))
		err := enc.Close()
		assert.Nil(t, err)
	})

	t.Run("with closer error", func(t *testing.T) {
		c := cipher.NewCTRCipher()
		c.SetKey([]byte("12345678"))
		c.SetIV([]byte("87654321"))

		// Use mock writer that returns error on close
		mockWriter := mock.NewErrorWriteCloser(assert.AnError)
		enc := NewStreamEncrypter(mockWriter, c, []byte("12345678"))
		err := enc.Close()
		assert.Equal(t, assert.AnError, err)
	})
}

func TestNewStreamDecrypter(t *testing.T) {
	t.Run("valid 8-byte key", func(t *testing.T) {
		c := cipher.NewCBCCipher()
		c.SetKey([]byte("12345678"))
		c.SetIV([]byte("87654321"))
		c.SetPadding(cipher.PKCS7)

		file := mock.NewFile([]byte("test"), "test.txt")
		dec := NewStreamDecrypter(file, c, []byte("12345678"))
		// Test that we can read from it (will fail due to invalid data, but that's expected)
		result := make([]byte, 100)
		_, err := dec.Read(result)
		assert.NotNil(t, err) // Expected to fail due to invalid encrypted data
	})

	t.Run("invalid key length", func(t *testing.T) {
		c := cipher.NewCBCCipher()
		file := mock.NewFile([]byte("test"), "test.txt")
		dec := NewStreamDecrypter(file, c, []byte("1234567")) // 7 bytes
		// Test that we get an error when reading
		result := make([]byte, 100)
		_, err := dec.Read(result)
		assert.NotNil(t, err)
		assert.Equal(t, err, KeySizeError(7))
	})
}

func TestStreamDecrypter_Read(t *testing.T) {
	t.Run("CTR mode streaming", func(t *testing.T) {
		c := cipher.NewCTRCipher()
		c.SetKey([]byte("12345678"))
		c.SetIV([]byte("87654321"))

		// First encrypt some data
		var buf bytes.Buffer
		enc := NewStreamEncrypter(&buf, c, []byte("12345678"))
		_, err := enc.Write([]byte("Hello, streaming!"))
		assert.Nil(t, err)

		// Then decrypt it
		file := mock.NewFile(buf.Bytes(), "test.txt")
		dec := NewStreamDecrypter(file, c, []byte("12345678"))
		result := make([]byte, 100)
		n, err := dec.Read(result)
		assert.Nil(t, err)
		assert.Greater(t, n, 0)
		assert.Equal(t, "Hello, streaming!", string(result[:n]))
	})

	t.Run("empty input", func(t *testing.T) {
		c := cipher.NewCTRCipher()
		c.SetKey([]byte("12345678"))
		c.SetIV([]byte("87654321"))

		file := mock.NewFile([]byte{}, "test.txt")
		dec := NewStreamDecrypter(file, c, []byte("12345678"))
		result := make([]byte, 100)
		n, err := dec.Read(result)
		assert.Equal(t, io.EOF, err)
		assert.Equal(t, 0, n)
	})

	t.Run("with error", func(t *testing.T) {
		c := cipher.NewCBCCipher()
		file := mock.NewFile([]byte("test"), "test.txt")
		dec := NewStreamDecrypter(file, c, []byte("1234567")) // Invalid key
		result := make([]byte, 100)
		n, err := dec.Read(result)
		assert.NotNil(t, err)
		assert.Equal(t, 0, n)
		assert.Equal(t, err, KeySizeError(7))
	})

	t.Run("with reader error", func(t *testing.T) {
		c := cipher.NewCTRCipher()
		c.SetKey([]byte("12345678"))
		c.SetIV([]byte("87654321"))

		// Use mock reader that returns error on read
		mockReader := mock.NewErrorFile(assert.AnError)
		dec := NewStreamDecrypter(mockReader, c, []byte("12345678"))
		result := make([]byte, 100)
		n, err := dec.Read(result)
		assert.NotNil(t, err)
		assert.Equal(t, 0, n)
		assert.IsType(t, ReadError{}, err)
	})

	t.Run("with decrypt error", func(t *testing.T) {
		// Create a mock cipher that returns error on decrypt
		mk := &mk{decryptError: assert.AnError}
		file := mock.NewFile([]byte("test data"), "test.txt")
		dec := NewStreamDecrypter(file, mk, []byte("12345678"))
		result := make([]byte, 100)
		n, err := dec.Read(result)
		assert.NotNil(t, err)
		assert.Equal(t, 0, n)
		assert.IsType(t, DecryptError{}, err)
	})
}

func TestErrorTypes(t *testing.T) {
	t.Run("buffer too small", func(t *testing.T) {
		c := cipher.NewCTRCipher()
		c.SetKey([]byte("12345678"))
		c.SetIV([]byte("87654321"))

		// First encrypt some data
		var buf bytes.Buffer
		enc := NewStreamEncrypter(&buf, c, []byte("12345678"))
		_, err := enc.Write([]byte("Hello, streaming!"))
		assert.Nil(t, err)

		// Then decrypt it with a small buffer
		file := mock.NewFile(buf.Bytes(), "test.txt")
		dec := NewStreamDecrypter(file, c, []byte("12345678"))
		result := make([]byte, 5) // Small buffer
		n, err := dec.Read(result)
		assert.IsType(t, BufferError{}, err)
		assert.Equal(t, 5, n)

		// Test BufferError fields
		if be, ok := err.(BufferError); ok {
			assert.Equal(t, 5, be.bufferSize)
			assert.Greater(t, be.dataSize, 5)
			// Test BufferError.Error() method for coverage
			assert.Contains(t, be.Error(), "crypto/des: : buffer size 5 is too small for data size")
		}
	})

	t.Run("KeyUnsetError", func(t *testing.T) {
		err := KeyUnsetError{}
		assert.Equal(t, "crypto/des: key not set, please use SetKey() method", err.Error())
	})

	t.Run("KeySizeError", func(t *testing.T) {
		err := KeySizeError(7)
		assert.Equal(t, "crypto/des: invalid key size 7, must be 8 bytes", err.Error())
	})

	t.Run("EncryptError with nil", func(t *testing.T) {
		err := EncryptError{}
		assert.Contains(t, err.Error(), "crypto/des: failed to encrypt data: <nil>")
	})

	t.Run("EncryptError with error", func(t *testing.T) {
		err := EncryptError{Err: assert.AnError}
		assert.Contains(t, err.Error(), "crypto/des: failed to encrypt data: assert.AnError general error for testing")
	})

	t.Run("DecryptError with nil", func(t *testing.T) {
		err := DecryptError{}
		assert.Contains(t, err.Error(), "crypto/des: failed to decrypt data: <nil>")
	})

	t.Run("DecryptError with error", func(t *testing.T) {
		err := DecryptError{Err: assert.AnError}
		assert.Contains(t, err.Error(), "crypto/des: failed to decrypt data: assert.AnError general error for testing")
	})

	t.Run("ReadError with nil", func(t *testing.T) {
		err := ReadError{}
		assert.Contains(t, err.Error(), "crypto/des: failed to read encrypted data: <nil>")
	})

	t.Run("ReadError with error", func(t *testing.T) {
		err := ReadError{Err: assert.AnError}
		assert.Contains(t, err.Error(), "crypto/des: failed to read encrypted data: assert.AnError general error for testing")
	})

}
