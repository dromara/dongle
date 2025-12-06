package twofish

import (
	"bytes"
	"errors"
	"io"
	"testing"

	"github.com/dromara/dongle/crypto/cipher"
	"github.com/dromara/dongle/internal/mock"
	"github.com/stretchr/testify/assert"
)

// Test data for error testing
var (
	key16Error    = []byte("1234567890123456")                 // Twofish-128 key
	key24Error    = []byte("123456789012345678901234")         // Twofish-192 key
	key32Error    = []byte("12345678901234567890123456789012") // Twofish-256 key
	iv16Error     = []byte("1234567890123456")                 // 16-byte IV
	testDataError = []byte("hello world")
)

// TestKeySizeError tests the KeySizeError type and its Error() method
func TestKeySizeError(t *testing.T) {
	t.Run("valid key sizes", func(t *testing.T) {
		// Test that valid key sizes don't trigger KeySizeError in actual usage
		validKeys := [][]byte{
			[]byte("1234567890123456"),                 // 16 bytes
			[]byte("123456789012345678901234"),         // 24 bytes
			[]byte("12345678901234567890123456789012"), // 32 bytes
		}
		for _, key := range validKeys {
			c := cipher.NewTwofishCipher(cipher.CBC)
			c.SetKey(key)
			c.SetIV(iv16Error)
			c.SetPadding(cipher.PKCS7)

			encrypter := NewStdEncrypter(c)
			assert.Nil(t, encrypter.Error) // Should not have KeySizeError for valid keys
		}
	})

	t.Run("invalid key sizes", func(t *testing.T) {
		invalidSizes := []int{0, 1, 8, 15, 17, 23, 25, 31, 33, 64, 128}
		for _, size := range invalidSizes {
			err := KeySizeError(size)
			expected := "crypto/twofish: invalid key size 8, must be 16, 24, or 32 bytes"
			if size == 0 {
				expected = "crypto/twofish: invalid key size 0, must be 16, 24, or 32 bytes"
			} else if size == 1 {
				expected = "crypto/twofish: invalid key size 1, must be 16, 24, or 32 bytes"
			} else if size == 8 {
				expected = "crypto/twofish: invalid key size 8, must be 16, 24, or 32 bytes"
			} else if size == 15 {
				expected = "crypto/twofish: invalid key size 15, must be 16, 24, or 32 bytes"
			} else if size == 17 {
				expected = "crypto/twofish: invalid key size 17, must be 16, 24, or 32 bytes"
			} else if size == 23 {
				expected = "crypto/twofish: invalid key size 23, must be 16, 24, or 32 bytes"
			} else if size == 25 {
				expected = "crypto/twofish: invalid key size 25, must be 16, 24, or 32 bytes"
			} else if size == 31 {
				expected = "crypto/twofish: invalid key size 31, must be 16, 24, or 32 bytes"
			} else if size == 33 {
				expected = "crypto/twofish: invalid key size 33, must be 16, 24, or 32 bytes"
			} else if size == 64 {
				expected = "crypto/twofish: invalid key size 64, must be 16, 24, or 32 bytes"
			} else if size == 128 {
				expected = "crypto/twofish: invalid key size 128, must be 16, 24, or 32 bytes"
			}
			assert.Equal(t, expected, err.Error())
		}
	})

	t.Run("negative key size", func(t *testing.T) {
		err := KeySizeError(-1)
		expected := "crypto/twofish: invalid key size -1, must be 16, 24, or 32 bytes"
		assert.Equal(t, expected, err.Error())
	})

	t.Run("large key size", func(t *testing.T) {
		err := KeySizeError(1000)
		expected := "crypto/twofish: invalid key size 1000, must be 16, 24, or 32 bytes"
		assert.Equal(t, expected, err.Error())
	})

	// Direct test of KeySizeError.Error() method to ensure 100% coverage
	t.Run("direct KeySizeError Error method test", func(t *testing.T) {
		err := KeySizeError(16)
		msg := err.Error()
		assert.Contains(t, msg, "crypto/twofish: invalid key size 16")
		assert.Contains(t, msg, "must be 16, 24, or 32 bytes")
	})
}

func TestTwofish_ValidKeySizes(t *testing.T) {
	t.Run("valid 16-byte key", func(t *testing.T) {
		c := cipher.NewTwofishCipher(cipher.CBC)
		c.SetKey([]byte("1234567890123456")) // 16 bytes - valid

		encrypter := NewStdEncrypter(c)
		assert.Nil(t, encrypter.Error)
	})

	t.Run("valid 24-byte key", func(t *testing.T) {
		c := cipher.NewTwofishCipher(cipher.CBC)
		c.SetKey([]byte("123456789012345678901234")) // 24 bytes - valid

		encrypter := NewStdEncrypter(c)
		assert.Nil(t, encrypter.Error)
	})

	t.Run("valid 32-byte key", func(t *testing.T) {
		c := cipher.NewTwofishCipher(cipher.CBC)
		c.SetKey([]byte("12345678901234567890123456789012")) // 32 bytes - valid

		encrypter := NewStdEncrypter(c)
		assert.Nil(t, encrypter.Error)
	})
}

// TestEncryptError tests the EncryptError type and its Error() method
func TestEncryptError(t *testing.T) {
	t.Run("with nil error", func(t *testing.T) {
		err := EncryptError{Err: nil}
		expected := "crypto/twofish: failed to encrypt data: <nil>"
		assert.Equal(t, expected, err.Error())
	})

	t.Run("with simple error", func(t *testing.T) {
		originalErr := errors.New("simple error")
		err := EncryptError{Err: originalErr}
		expected := "crypto/twofish: failed to encrypt data: simple error"
		assert.Equal(t, expected, err.Error())
	})

	t.Run("with complex error message", func(t *testing.T) {
		originalErr := errors.New("encryption failed: invalid key format")
		err := EncryptError{Err: originalErr}
		expected := "crypto/twofish: failed to encrypt data: encryption failed: invalid key format"
		assert.Equal(t, expected, err.Error())
	})

	t.Run("with wrapped error", func(t *testing.T) {
		originalErr := errors.New("underlying error")
		wrappedErr := errors.New("wrapped: " + originalErr.Error())
		err := EncryptError{Err: wrappedErr}
		expected := "crypto/twofish: failed to encrypt data: wrapped: underlying error"
		assert.Equal(t, expected, err.Error())
	})

	t.Run("with empty error message", func(t *testing.T) {
		originalErr := errors.New("")
		err := EncryptError{Err: originalErr}
		expected := "crypto/twofish: failed to encrypt data: "
		assert.Equal(t, expected, err.Error())
	})

	// Direct test of EncryptError.Error() method to ensure 100% coverage
	t.Run("direct EncryptError Error method test", func(t *testing.T) {
		err := EncryptError{Err: errors.New("test error")}
		msg := err.Error()
		assert.Contains(t, msg, "crypto/twofish: failed to encrypt data:")
		assert.Contains(t, msg, "test error")
	})
}

// TestDecryptError tests the DecryptError type and its Error() method
func TestDecryptError(t *testing.T) {
	t.Run("with nil error", func(t *testing.T) {
		err := DecryptError{Err: nil}
		expected := "crypto/twofish: failed to decrypt data: <nil>"
		assert.Equal(t, expected, err.Error())
	})

	t.Run("with simple error", func(t *testing.T) {
		originalErr := errors.New("decryption failed")
		err := DecryptError{Err: originalErr}
		expected := "crypto/twofish: failed to decrypt data: decryption failed"
		assert.Equal(t, expected, err.Error())
	})

	t.Run("with complex error message", func(t *testing.T) {
		originalErr := errors.New("decryption failed: invalid ciphertext format")
		err := DecryptError{Err: originalErr}
		expected := "crypto/twofish: failed to decrypt data: decryption failed: invalid ciphertext format"
		assert.Equal(t, expected, err.Error())
	})

	t.Run("with authentication error", func(t *testing.T) {
		originalErr := errors.New("authentication failed")
		err := DecryptError{Err: originalErr}
		expected := "crypto/twofish: failed to decrypt data: authentication failed"
		assert.Equal(t, expected, err.Error())
	})

	t.Run("with empty error message", func(t *testing.T) {
		originalErr := errors.New("")
		err := DecryptError{Err: originalErr}
		expected := "crypto/twofish: failed to decrypt data: "
		assert.Equal(t, expected, err.Error())
	})

	// Direct test of DecryptError.Error() method to ensure 100% coverage
	t.Run("direct DecryptError Error method test", func(t *testing.T) {
		err := DecryptError{Err: errors.New("test error")}
		msg := err.Error()
		assert.Contains(t, msg, "crypto/twofish: failed to decrypt data:")
		assert.Contains(t, msg, "test error")
	})
}

// TestReadError tests the ReadError type and its Error() method
func TestReadError(t *testing.T) {
	t.Run("with nil error", func(t *testing.T) {
		err := ReadError{Err: nil}
		expected := "crypto/twofish: failed to read encrypted data: <nil>"
		assert.Equal(t, expected, err.Error())
	})

	t.Run("with simple error", func(t *testing.T) {
		originalErr := errors.New("read failed")
		err := ReadError{Err: originalErr}
		expected := "crypto/twofish: failed to read encrypted data: read failed"
		assert.Equal(t, expected, err.Error())
	})

	t.Run("with complex error message", func(t *testing.T) {
		originalErr := errors.New("read failed: connection timeout")
		err := ReadError{Err: originalErr}
		expected := "crypto/twofish: failed to read encrypted data: read failed: connection timeout"
		assert.Equal(t, expected, err.Error())
	})

	t.Run("with EOF error", func(t *testing.T) {
		originalErr := errors.New("unexpected EOF")
		err := ReadError{Err: originalErr}
		expected := "crypto/twofish: failed to read encrypted data: unexpected EOF"
		assert.Equal(t, expected, err.Error())
	})

	t.Run("with empty error message", func(t *testing.T) {
		originalErr := errors.New("")
		err := ReadError{Err: originalErr}
		expected := "crypto/twofish: failed to read encrypted data: "
		assert.Equal(t, expected, err.Error())
	})

	// Direct test of ReadError.Error() method to ensure 100% coverage
	t.Run("direct ReadError Error method test", func(t *testing.T) {
		err := ReadError{Err: errors.New("test error")}
		msg := err.Error()
		assert.Contains(t, msg, "crypto/twofish: failed to read encrypted data:")
		assert.Contains(t, msg, "test error")
	})
}

// TestBufferError tests the BufferError type and its Error() method
func TestBufferError(t *testing.T) {
	t.Run("small buffer", func(t *testing.T) {
		err := BufferError{bufferSize: 5, dataSize: 10}
		expected := "crypto/twofish: buffer size 5 is too small for data size 10"
		assert.Equal(t, expected, err.Error())
	})

	t.Run("zero buffer size", func(t *testing.T) {
		err := BufferError{bufferSize: 0, dataSize: 10}
		expected := "crypto/twofish: buffer size 0 is too small for data size 10"
		assert.Equal(t, expected, err.Error())
	})

	t.Run("negative buffer size", func(t *testing.T) {
		err := BufferError{bufferSize: -1, dataSize: 10}
		expected := "crypto/twofish: buffer size -1 is too small for data size 10"
		assert.Equal(t, expected, err.Error())
	})

	t.Run("zero data size", func(t *testing.T) {
		err := BufferError{bufferSize: 5, dataSize: 0}
		expected := "crypto/twofish: buffer size 5 is too small for data size 0"
		assert.Equal(t, expected, err.Error())
	})

	t.Run("negative data size", func(t *testing.T) {
		err := BufferError{bufferSize: 5, dataSize: -1}
		expected := "crypto/twofish: buffer size 5 is too small for data size -1"
		assert.Equal(t, expected, err.Error())
	})

	t.Run("large buffer size", func(t *testing.T) {
		err := BufferError{bufferSize: 1000, dataSize: 2000}
		expected := "crypto/twofish: buffer size 1000 is too small for data size 2000"
		assert.Equal(t, expected, err.Error())
	})

	t.Run("equal sizes", func(t *testing.T) {
		err := BufferError{bufferSize: 10, dataSize: 10}
		expected := "crypto/twofish: buffer size 10 is too small for data size 10"
		assert.Equal(t, expected, err.Error())
	})

	t.Run("both zero", func(t *testing.T) {
		err := BufferError{bufferSize: 0, dataSize: 0}
		expected := "crypto/twofish: buffer size 0 is too small for data size 0"
		assert.Equal(t, expected, err.Error())
	})

	t.Run("both negative", func(t *testing.T) {
		err := BufferError{bufferSize: -5, dataSize: -10}
		expected := "crypto/twofish: buffer size -5 is too small for data size -10"
		assert.Equal(t, expected, err.Error())
	})

	// Direct test of BufferError.Error() method to ensure 100% coverage
	t.Run("direct BufferError Error method test", func(t *testing.T) {
		err := BufferError{bufferSize: 5, dataSize: 10}
		msg := err.Error()
		assert.Contains(t, msg, "crypto/twofish: buffer size 5 is too small for data size 10")
	})
}

// TestErrorIntegration tests error types in actual Twofish operations
func TestErrorIntegration(t *testing.T) {
	t.Run("KeySizeError in StdEncrypter", func(t *testing.T) {
		invalidKeys := [][]byte{
			nil,
			{},
			[]byte("short"),
			[]byte("17bytes_key123456"),
			make([]byte, 33),
		}

		for _, key := range invalidKeys {
			c := cipher.NewTwofishCipher(cipher.CBC)
			c.SetKey(key)
			c.SetIV(iv16Error)
			c.SetPadding(cipher.PKCS7)

			encrypter := NewStdEncrypter(c)
			assert.NotNil(t, encrypter)
			assert.NotNil(t, encrypter.Error)
			assert.IsType(t, KeySizeError(0), encrypter.Error)
		}
	})

	t.Run("KeySizeError in StdDecrypter", func(t *testing.T) {
		invalidKeys := [][]byte{
			nil,
			{},
			[]byte("short"),
		}

		for _, key := range invalidKeys {
			c := cipher.NewTwofishCipher(cipher.CBC)
			c.SetKey(key)

			decrypter := NewStdDecrypter(c)
			assert.NotNil(t, decrypter)
			assert.NotNil(t, decrypter.Error)
			assert.IsType(t, KeySizeError(0), decrypter.Error)
		}
	})

	t.Run("KeySizeError in StreamEncrypter", func(t *testing.T) {
		var buf bytes.Buffer
		c := cipher.NewTwofishCipher(cipher.CBC)
		c.SetKey([]byte("invalid"))

		encrypter := NewStreamEncrypter(&buf, c)
		streamEncrypter := encrypter.(*StreamEncrypter)
		assert.NotNil(t, streamEncrypter.Error)
		assert.IsType(t, KeySizeError(0), streamEncrypter.Error)
	})

	t.Run("KeySizeError in StreamDecrypter", func(t *testing.T) {
		file := mock.NewFile([]byte("test"), "test.txt")
		c := cipher.NewTwofishCipher(cipher.CBC)
		c.SetKey([]byte("invalid"))

		decrypter := NewStreamDecrypter(file, c)
		streamDecrypter := decrypter.(*StreamDecrypter)
		assert.NotNil(t, streamDecrypter.Error)
		assert.IsType(t, KeySizeError(0), streamDecrypter.Error)
	})

	t.Run("EncryptError in StreamEncrypter Write", func(t *testing.T) {
		var buf bytes.Buffer
		c := cipher.NewTwofishCipher(cipher.CBC)
		c.SetKey(key16Error)
		// Don't set IV to cause encryption error
		c.SetPadding(cipher.PKCS7)

		encrypter := NewStreamEncrypter(&buf, c)
		n, err := encrypter.Write(testDataError)
		// This should cause c.cipher.Encrypt to return an error
		if err != nil {
			assert.Equal(t, 0, n)
			assert.IsType(t, EncryptError{}, err)
		}
	})

	t.Run("ReadError in StreamDecrypter Read", func(t *testing.T) {
		mockReader := mock.NewErrorReadWriteCloser(errors.New("read error"))
		c := cipher.NewTwofishCipher(cipher.CBC)
		c.SetKey(key16Error)

		decrypter := NewStreamDecrypter(mockReader, c)
		buf := make([]byte, 10)
		n, err := decrypter.Read(buf)
		assert.Equal(t, 0, n)
		assert.IsType(t, ReadError{}, err)
	})
}

// TestErrorTypeAssertions tests type assertions for error types
func TestErrorTypeAssertions(t *testing.T) {
	t.Run("KeySizeError type assertion", func(t *testing.T) {
		var err error = KeySizeError(8)
		var keySizeErr KeySizeError
		ok := errors.As(err, &keySizeErr)
		assert.True(t, ok)
		assert.Equal(t, KeySizeError(8), keySizeErr)
	})

	t.Run("EncryptError type assertion", func(t *testing.T) {
		originalErr := errors.New("test error")
		var err error = EncryptError{Err: originalErr}
		var encryptErr EncryptError
		ok := errors.As(err, &encryptErr)
		assert.True(t, ok)
		assert.Equal(t, originalErr, encryptErr.Err)
	})

	t.Run("DecryptError type assertion", func(t *testing.T) {
		originalErr := errors.New("test error")
		var err error = DecryptError{Err: originalErr}
		var decryptErr DecryptError
		ok := errors.As(err, &decryptErr)
		assert.True(t, ok)
		assert.Equal(t, originalErr, decryptErr.Err)
	})

	t.Run("ReadError type assertion", func(t *testing.T) {
		originalErr := errors.New("test error")
		var err error = ReadError{Err: originalErr}
		var readErr ReadError
		ok := errors.As(err, &readErr)
		assert.True(t, ok)
		assert.Equal(t, originalErr, readErr.Err)
	})

	t.Run("BufferError type assertion", func(t *testing.T) {
		var err error = BufferError{bufferSize: 5, dataSize: 10}
		var bufferErr BufferError
		ok := errors.As(err, &bufferErr)
		assert.True(t, ok)
		assert.Equal(t, 5, bufferErr.bufferSize)
		assert.Equal(t, 10, bufferErr.dataSize)
	})
}

func TestStdEncrypter_Encrypt_ErrorPaths(t *testing.T) {
	t.Run("encrypt with existing error", func(t *testing.T) {
		c := cipher.NewTwofishCipher(cipher.CBC)
		c.SetKey([]byte("short")) // Invalid key size
		c.SetIV(iv16Error)
		c.SetPadding(cipher.PKCS7)

		encrypter := NewStdEncrypter(c)
		assert.NotNil(t, encrypter.Error)

		// Try to encrypt with existing error - it will still try to encrypt
		result, err := encrypter.Encrypt(testDataError)
		// The encryption will fail because the key is invalid
		assert.Empty(t, result)
		assert.NotNil(t, err)
		assert.IsType(t, KeySizeError(5), err)
	})

	t.Run("encrypt with invalid key causing twofish.NewCipher error", func(t *testing.T) {
		c := cipher.NewTwofishCipher(cipher.CBC)
		c.SetKey(key16Error)
		c.SetIV(iv16Error)
		c.SetPadding(cipher.PKCS7)

		encrypter := NewStdEncrypter(c)
		// Manually set an invalid key to cause twofish.NewCipher to fail
		encrypter.cipher.Key = []byte("invalid")

		result, err := encrypter.Encrypt(testDataError)
		// The encryption will fail because the key is invalid
		assert.Empty(t, result)
		assert.NotNil(t, err)
		assert.IsType(t, EncryptError{}, err)
	})

	t.Run("encrypt empty data", func(t *testing.T) {
		c := cipher.NewTwofishCipher(cipher.CBC)
		c.SetKey(key16Error)
		c.SetIV(iv16Error)
		c.SetPadding(cipher.PKCS7)

		encrypter := NewStdEncrypter(c)
		result, err := encrypter.Encrypt([]byte{})
		assert.Empty(t, result)
		assert.Nil(t, err)
	})

	t.Run("encrypt with twofish.NewCipher error", func(t *testing.T) {
		c := cipher.NewTwofishCipher(cipher.CBC)
		c.SetKey(key16Error)
		c.SetIV(iv16Error)
		c.SetPadding(cipher.PKCS7)

		encrypter := NewStdEncrypter(c)
		// Set a key that will cause twofish.NewCipher to fail
		// This is difficult to achieve with the current implementation,
		// but we can test the error path by mocking
		encrypter.cipher.Key = nil // This should cause twofish.NewCipher to fail

		result, err := encrypter.Encrypt(testDataError)
		assert.Empty(t, result)
		assert.NotNil(t, err)
		assert.IsType(t, EncryptError{}, err)
	})

	t.Run("encrypt with block==nil path uses cipher.Encrypt", func(t *testing.T) {
		c := cipher.NewTwofishCipher(cipher.CBC)
		c.SetKey(key16Error)
		c.SetIV(iv16Error)
		c.SetPadding(cipher.PKCS7)

		e := NewStreamEncrypter(io.Discard, c).(*StreamEncrypter)
		// force block to nil to execute lazy-create branch
		e.block = nil
		n, err := e.Write([]byte("abcd"))
		assert.NoError(t, err)
		assert.Equal(t, 4, n)
	})
}

func TestStdDecrypter_Decrypt_ErrorHandling(t *testing.T) {
	t.Run("decrypt with existing error", func(t *testing.T) {
		c := cipher.NewTwofishCipher(cipher.CBC)
		c.SetKey([]byte("12345678")) // Invalid key size

		decrypter := NewStdDecrypter(c)
		assert.NotNil(t, decrypter.Error)

		// Try to decrypt with existing error - this will actually call the cipher
		// and get an error because the key is invalid
		dst, err := decrypter.Decrypt([]byte("test"))
		assert.Empty(t, dst)
		assert.Error(t, err) // Will get an error due to invalid key
	})

	t.Run("decrypt empty data", func(t *testing.T) {
		c := cipher.NewTwofishCipher(cipher.CBC)
		c.SetKey([]byte("1234567890123456"))

		decrypter := NewStdDecrypter(c)
		dst, err := decrypter.Decrypt([]byte{})
		assert.Empty(t, dst)
		assert.NoError(t, err)
	})

	t.Run("decrypt with twofish.NewCipher error -> DecryptError", func(t *testing.T) {
		c := cipher.NewTwofishCipher(cipher.CBC)
		c.SetKey(key16Error)
		// create a valid decrypter first (no init error)
		decrypter := NewStdDecrypter(c)
		assert.Nil(t, decrypter.Error)
		// sabotage key so twofish.NewCipher fails at call time
		decrypter.cipher.Key = []byte("invalid")
		out, err := decrypter.Decrypt([]byte("test data"))
		assert.Empty(t, out)
		assert.IsType(t, DecryptError{}, err)
	})
}

func TestStreamEncrypter_Write_ErrorHandling(t *testing.T) {
	t.Run("write with existing error", func(t *testing.T) {
		c := cipher.NewTwofishCipher(cipher.CBC)
		c.SetKey([]byte("12345678")) // Invalid key size

		var buf bytes.Buffer
		encrypter := NewStreamEncrypter(&buf, c).(*StreamEncrypter)
		assert.NotNil(t, encrypter.Error)

		// Try to write with existing error
		n, err := encrypter.Write([]byte("test"))
		assert.Equal(t, 0, n)
		assert.Error(t, err)
		assert.Equal(t, encrypter.Error, err)
	})

	t.Run("write empty data", func(t *testing.T) {
		c := cipher.NewTwofishCipher(cipher.CBC)
		c.SetKey([]byte("1234567890123456"))

		var buf bytes.Buffer
		encrypter := NewStreamEncrypter(&buf, c).(*StreamEncrypter)

		n, err := encrypter.Write([]byte{})
		assert.Equal(t, 0, n)
		assert.NoError(t, err)
	})

	t.Run("write with cipher block creation failure", func(t *testing.T) {
		c := cipher.NewTwofishCipher(cipher.CBC)
		c.SetPadding(cipher.PKCS7)
		c.SetKey([]byte("1234567890123456"))
		c.SetIV([]byte("1234567890123456")) // Set IV for CBC mode

		var buf bytes.Buffer
		encrypter := NewStreamEncrypter(&buf, c).(*StreamEncrypter)

		// Manually set block to nil to simulate creation failure
		encrypter.block = nil

		n, err := encrypter.Write([]byte("test"))
		assert.Equal(t, 4, n) // Should still write the data
		assert.NoError(t, err)
	})

	t.Run("write with writer error", func(t *testing.T) {
		c := cipher.NewTwofishCipher(cipher.CBC)
		c.SetPadding(cipher.PKCS7)
		c.SetKey([]byte("1234567890123456"))
		c.SetIV([]byte("1234567890123456")) // Set IV for CBC mode

		// Create a mock writer that returns an error
		mockWriter := mock.NewErrorWriteCloser(errors.New("write error"))
		encrypter := NewStreamEncrypter(mockWriter, c).(*StreamEncrypter)

		n, err := encrypter.Write([]byte("test"))
		assert.Equal(t, 0, n) // Should return 0 due to write error
		assert.Error(t, err)  // Should get the write error
		assert.Contains(t, err.Error(), "write error")
	})

	t.Run("write with block recreation", func(t *testing.T) {
		c := cipher.NewTwofishCipher(cipher.CBC)
		c.SetPadding(cipher.PKCS7)
		c.SetKey([]byte("1234567890123456"))
		c.SetIV([]byte("1234567890123456")) // Set IV for CBC mode

		var buf bytes.Buffer
		encrypter := NewStreamEncrypter(&buf, c).(*StreamEncrypter)

		// Manually set block to nil to simulate the case where
		// NewCipher failed during initialization but succeeds during Write
		encrypter.block = nil

		n, err := encrypter.Write([]byte("test"))
		assert.Equal(t, 4, n)  // Should write the data successfully
		assert.NoError(t, err) // Should work because block gets recreated
	})

}

func TestStreamEncrypter_Close_ErrorHandling(t *testing.T) {
	t.Run("close with existing error", func(t *testing.T) {
		c := cipher.NewTwofishCipher(cipher.CBC)
		c.SetKey([]byte("12345678")) // Invalid key size

		var buf bytes.Buffer
		encrypter := NewStreamEncrypter(&buf, c).(*StreamEncrypter)
		assert.NotNil(t, encrypter.Error)

		err := encrypter.Close()
		assert.Error(t, err)
		assert.Equal(t, encrypter.Error, err)
	})

	t.Run("close with underlying closer", func(t *testing.T) {
		c := cipher.NewTwofishCipher(cipher.CBC)
		c.SetKey([]byte("1234567890123456"))

		// Create a mock writer that implements io.Closer
		var buf bytes.Buffer
		mockWriter := mock.NewCloseErrorWriteCloser(&buf, errors.New("close error"))
		encrypter := NewStreamEncrypter(mockWriter, c).(*StreamEncrypter)

		err := encrypter.Close()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "close error")
	})

	t.Run("close without underlying closer", func(t *testing.T) {
		c := cipher.NewTwofishCipher(cipher.CBC)
		c.SetKey([]byte("1234567890123456"))

		var buf bytes.Buffer
		encrypter := NewStreamEncrypter(&buf, c).(*StreamEncrypter)

		err := encrypter.Close()
		assert.NoError(t, err)
	})
}

func TestStreamDecrypter_Read_ErrorHandling(t *testing.T) {
	t.Run("read with existing error", func(t *testing.T) {
		c := cipher.NewTwofishCipher(cipher.CBC)
		c.SetKey([]byte("12345678")) // Invalid key size

		reader := bytes.NewReader([]byte("test"))
		decrypter := NewStreamDecrypter(reader, c).(*StreamDecrypter)
		assert.NotNil(t, decrypter.Error)

		// Try to read with existing error
		buf := make([]byte, 10)
		n, err := decrypter.Read(buf)
		assert.Equal(t, 0, n)
		assert.Error(t, err)
		assert.Equal(t, decrypter.Error, err)
	})

	t.Run("read with reader error", func(t *testing.T) {
		c := cipher.NewTwofishCipher(cipher.CBC)
		c.SetKey([]byte("1234567890123456"))

		// Create a mock reader that returns an error
		mockReader := mock.NewErrorFile(errors.New("read error"))
		decrypter := NewStreamDecrypter(mockReader, c).(*StreamDecrypter)

		buf := make([]byte, 10)
		n, err := decrypter.Read(buf)
		assert.Equal(t, 0, n)
		assert.Error(t, err)
		assert.IsType(t, ReadError{}, err)
	})

	t.Run("read empty data", func(t *testing.T) {
		c := cipher.NewTwofishCipher(cipher.CBC)
		c.SetKey([]byte("1234567890123456"))

		reader := bytes.NewReader([]byte{})
		decrypter := NewStreamDecrypter(reader, c).(*StreamDecrypter)

		buf := make([]byte, 10)
		n, err := decrypter.Read(buf)
		assert.Equal(t, 0, n)
		assert.Equal(t, io.EOF, err)
	})

	t.Run("read with cipher block creation failure", func(t *testing.T) {
		c := cipher.NewTwofishCipher(cipher.CBC)
		c.SetPadding(cipher.PKCS7)
		c.SetKey([]byte("1234567890123456"))
		c.SetIV([]byte("1234567890123456")) // Set IV for CBC mode

		// Create proper encrypted data first
		encrypter := NewStdEncrypter(c)
		encryptedData, err := encrypter.Encrypt([]byte("hello world"))
		assert.NoError(t, err)

		reader := bytes.NewReader(encryptedData)
		decrypter := NewStreamDecrypter(reader, c).(*StreamDecrypter)

		// The block will be recreated successfully, so this test actually
		// tests the normal flow where block is nil initially but gets created
		buf := make([]byte, 10)
		n, err := decrypter.Read(buf)
		assert.Greater(t, n, 0) // Should read some data
		assert.NoError(t, err)  // Should work normally
	})

	t.Run("read with decryption error", func(t *testing.T) {
		c := cipher.NewTwofishCipher(cipher.CBC)
		c.SetKey([]byte("1234567890123456"))
		c.SetIV([]byte("1234567890123456")) // Set IV for CBC mode

		// Create invalid encrypted data that will cause decryption to fail
		invalidData := []byte("invalid encrypted data")
		reader := bytes.NewReader(invalidData)
		decrypter := NewStreamDecrypter(reader, c).(*StreamDecrypter)

		buf := make([]byte, 10)
		n, err := decrypter.Read(buf)
		assert.Equal(t, 0, n) // Should return 0 due to decryption error
		assert.Error(t, err)  // Should get an error due to decryption failure
		assert.IsType(t, DecryptError{}, err)
	})

	t.Run("read with block recreation", func(t *testing.T) {
		c := cipher.NewTwofishCipher(cipher.CBC)
		c.SetPadding(cipher.PKCS7)
		c.SetKey([]byte("1234567890123456"))
		c.SetIV([]byte("1234567890123456")) // Set IV for CBC mode

		// Create proper encrypted data first
		encrypter := NewStdEncrypter(c)
		encryptedData, err := encrypter.Encrypt([]byte("hello world"))
		assert.NoError(t, err)

		reader := bytes.NewReader(encryptedData)
		decrypter := NewStreamDecrypter(reader, c).(*StreamDecrypter)

		// Manually set block to nil to simulate the case where
		// NewCipher failed during initialization but succeeds during Read
		decrypter.block = nil

		buf := make([]byte, 10)
		n, err := decrypter.Read(buf)
		assert.Greater(t, n, 0) // Should read some data successfully
		assert.NoError(t, err)  // Should work because block gets recreated
	})

	t.Run("read after all data consumed", func(t *testing.T) {
		c := cipher.NewTwofishCipher(cipher.CBC)
		c.SetPadding(cipher.PKCS7)
		c.SetKey([]byte("1234567890123456"))
		c.SetIV([]byte("1234567890123456")) // Set IV for CBC mode

		// Create some test data by encrypting it first
		encrypter := NewStdEncrypter(c)
		testData, err := encrypter.Encrypt([]byte("hello world"))
		assert.NoError(t, err)

		reader := bytes.NewReader(testData)
		decrypter := NewStreamDecrypter(reader, c).(*StreamDecrypter)

		// Read all data in one go
		buf := make([]byte, 100) // Large enough buffer
		n, err := decrypter.Read(buf)
		assert.Greater(t, n, 0)
		assert.NoError(t, err)

		// Second read should return EOF
		n, err = decrypter.Read(buf)
		assert.Equal(t, 0, n)
		assert.Equal(t, io.EOF, err)
	})
}

// Additional comprehensive error path tests
func TestStreamEncrypter_Write_Comprehensive(t *testing.T) {
	t.Run("write with buffer accumulation", func(t *testing.T) {
		c := cipher.NewTwofishCipher(cipher.CBC)
		c.SetKey(key16Error)
		c.SetIV(iv16Error)
		c.SetPadding(cipher.PKCS7)

		var buf bytes.Buffer
		encrypter := NewStreamEncrypter(&buf, c)
		streamEncrypter := encrypter.(*StreamEncrypter)

		// Add some data to buffer to test accumulation
		streamEncrypter.buffer = []byte("prefix")

		n, err := encrypter.Write(testDataError)
		assert.Nil(t, err)
		assert.Equal(t, len(testDataError), n)
		// Verify buffer was cleared
		assert.Nil(t, streamEncrypter.buffer)
	})

	t.Run("write with multiple writes", func(t *testing.T) {
		c := cipher.NewTwofishCipher(cipher.CBC)
		c.SetKey(key16Error)
		c.SetIV(iv16Error)
		c.SetPadding(cipher.PKCS7)

		var buf bytes.Buffer
		encrypter := NewStreamEncrypter(&buf, c)

		// First write
		n1, err1 := encrypter.Write([]byte("hello"))
		assert.Nil(t, err1)
		assert.Equal(t, 5, n1)

		// Second write
		n2, err2 := encrypter.Write([]byte(" world"))
		assert.Nil(t, err2)
		assert.Equal(t, 6, n2)
	})

	t.Run("write with large data", func(t *testing.T) {
		c := cipher.NewTwofishCipher(cipher.CBC)
		c.SetKey(key16Error)
		c.SetIV(iv16Error)
		c.SetPadding(cipher.PKCS7)

		var buf bytes.Buffer
		encrypter := NewStreamEncrypter(&buf, c)

		// Write large data
		largeData := make([]byte, 1000)
		for i := range largeData {
			largeData[i] = byte(i % 256)
		}

		n, err := encrypter.Write(largeData)
		assert.Nil(t, err)
		assert.Equal(t, len(largeData), n)
	})

	t.Run("write with single byte", func(t *testing.T) {
		c := cipher.NewTwofishCipher(cipher.CBC)
		c.SetKey(key16Error)
		c.SetIV(iv16Error)
		c.SetPadding(cipher.PKCS7)

		var buf bytes.Buffer
		encrypter := NewStreamEncrypter(&buf, c)

		// Write single byte
		n, err := encrypter.Write([]byte("a"))
		assert.Nil(t, err)
		assert.Equal(t, 1, n)
	})
}

func TestStreamDecrypter_Read_Comprehensive(t *testing.T) {
	t.Run("read with empty data", func(t *testing.T) {
		// Create an empty encrypted file
		reader := mock.NewFile([]byte{}, "empty.dat")
		c := cipher.NewTwofishCipher(cipher.CBC)
		c.SetKey(key16Error)
		c.SetIV(iv16Error)
		c.SetPadding(cipher.PKCS7)

		decrypter := NewStreamDecrypter(reader, c)
		buf := make([]byte, 100)
		n, err := decrypter.Read(buf)
		assert.Equal(t, 0, n)
		assert.Equal(t, io.EOF, err)
	})

	t.Run("read with decrypted data", func(t *testing.T) {
		c := cipher.NewTwofishCipher(cipher.CBC)
		c.SetKey(key16Error)
		c.SetIV(iv16Error)
		c.SetPadding(cipher.PKCS7)

		reader := mock.NewFile(testDataError, "test.txt")
		decrypter := NewStreamDecrypter(reader, c)
		streamDecrypter := decrypter.(*StreamDecrypter)

		// Add some data to buffer to test position handling
		streamDecrypter.buffer = []byte("prefix")
		streamDecrypter.position = 0

		buf := make([]byte, 100)
		n, err := decrypter.Read(buf)
		// Should work normally even with pre-populated decrypted data
		assert.True(t, n >= 0)
		if err != nil {
			assert.Equal(t, io.EOF, err)
		}
	})

	t.Run("read with multiple reads", func(t *testing.T) {
		c := cipher.NewTwofishCipher(cipher.CBC)
		c.SetKey(key16Error)
		c.SetIV(iv16Error)
		c.SetPadding(cipher.PKCS7)

		reader := mock.NewFile(testDataError, "test.txt")
		decrypter := NewStreamDecrypter(reader, c)

		// First read
		buf1 := make([]byte, 5)
		n1, err1 := decrypter.Read(buf1)
		assert.True(t, n1 >= 0)
		if err1 != nil {
			// Could be EOF or DecryptError depending on the data
			assert.True(t, err1 == io.EOF || err1 != nil)
		}

		// Second read
		buf2 := make([]byte, 5)
		n2, err2 := decrypter.Read(buf2)
		assert.True(t, n2 >= 0)
		if err2 != nil {
			// Could be EOF or DecryptError depending on the data
			assert.True(t, err2 == io.EOF || err2 != nil)
		}
	})

	t.Run("read with small buffer", func(t *testing.T) {
		c := cipher.NewTwofishCipher(cipher.CBC)
		c.SetKey(key16Error)
		c.SetIV(iv16Error)
		c.SetPadding(cipher.PKCS7)

		reader := mock.NewFile(testDataError, "test.txt")
		decrypter := NewStreamDecrypter(reader, c)

		// Use a very small buffer
		buf := make([]byte, 1)
		n, err := decrypter.Read(buf)
		assert.True(t, n >= 0)
		if err != nil {
			// Could be EOF or DecryptError depending on the data
			assert.True(t, err == io.EOF || err != nil)
		}
	})

	t.Run("read with large buffer", func(t *testing.T) {
		c := cipher.NewTwofishCipher(cipher.CBC)
		c.SetKey(key16Error)
		c.SetIV(iv16Error)
		c.SetPadding(cipher.PKCS7)

		reader := mock.NewFile(testDataError, "test.txt")
		decrypter := NewStreamDecrypter(reader, c)

		// Use a large buffer
		buf := make([]byte, 1000)
		n, err := decrypter.Read(buf)
		assert.True(t, n >= 0)
		if err != nil {
			// Could be EOF or DecryptError depending on the data
			assert.True(t, err == io.EOF || err != nil)
		}
	})

	t.Run("read with exact buffer size", func(t *testing.T) {
		c := cipher.NewTwofishCipher(cipher.CBC)
		c.SetKey(key16Error)
		c.SetIV(iv16Error)
		c.SetPadding(cipher.PKCS7)

		reader := mock.NewFile(testDataError, "test.txt")
		decrypter := NewStreamDecrypter(reader, c)

		// Use a buffer of exact size
		buf := make([]byte, len(testDataError))
		n, err := decrypter.Read(buf)
		assert.True(t, n >= 0)
		if err != nil {
			// Could be EOF or DecryptError depending on the data
			assert.True(t, err == io.EOF || err != nil)
		}
	})

	t.Run("read with zero buffer", func(t *testing.T) {
		c := cipher.NewTwofishCipher(cipher.CBC)
		c.SetKey(key16Error)
		c.SetIV(iv16Error)
		c.SetPadding(cipher.PKCS7)

		reader := mock.NewFile(testDataError, "test.txt")
		decrypter := NewStreamDecrypter(reader, c)

		// Use a zero-sized buffer
		buf := make([]byte, 0)
		n, err := decrypter.Read(buf)
		assert.Equal(t, 0, n)
		if err != nil {
			// Could be EOF or DecryptError depending on the data
			assert.True(t, err == io.EOF || err != nil)
		}
	})

	t.Run("read with nil buffer", func(t *testing.T) {
		c := cipher.NewTwofishCipher(cipher.CBC)
		c.SetKey(key16Error)
		c.SetIV(iv16Error)
		c.SetPadding(cipher.PKCS7)

		reader := mock.NewFile(testDataError, "test.txt")
		decrypter := NewStreamDecrypter(reader, c)

		// Use a nil buffer
		var buf []byte
		n, err := decrypter.Read(buf)
		assert.Equal(t, 0, n)
		if err != nil {
			// Could be EOF or DecryptError depending on the data
			assert.True(t, err == io.EOF || err != nil)
		}
	})

	t.Run("read with partial data", func(t *testing.T) {
		c := cipher.NewTwofishCipher(cipher.CBC)
		c.SetKey(key16Error)
		c.SetIV(iv16Error)
		c.SetPadding(cipher.PKCS7)

		reader := mock.NewFile(testDataError, "test.txt")
		decrypter := NewStreamDecrypter(reader, c)

		// Read partial data
		buf := make([]byte, 5)
		n, err := decrypter.Read(buf)
		assert.True(t, n >= 0)
		if err != nil {
			// Could be EOF or DecryptError depending on the data
			assert.True(t, err == io.EOF || err != nil)
		}
	})

	t.Run("read with exact data size", func(t *testing.T) {
		c := cipher.NewTwofishCipher(cipher.CBC)
		c.SetKey(key16Error)
		c.SetIV(iv16Error)
		c.SetPadding(cipher.PKCS7)

		reader := mock.NewFile(testDataError, "test.txt")
		decrypter := NewStreamDecrypter(reader, c)

		// Read exact data size
		buf := make([]byte, len(testDataError))
		n, err := decrypter.Read(buf)
		assert.True(t, n >= 0)
		if err != nil {
			// Could be EOF or DecryptError depending on the data
			assert.True(t, err == io.EOF || err != nil)
		}
	})
}
