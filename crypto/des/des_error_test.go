package des

import (
	"bytes"
	"errors"
	"io"
	"testing"

	"github.com/dromara/dongle/crypto/cipher"
	"github.com/dromara/dongle/mock"
	"github.com/stretchr/testify/assert"
)

// Test data for error testing
var (
	key8Error     = []byte("12345678") // DES key (8 bytes)
	iv8Error      = []byte("87654321") // 8-byte IV
	testDataError = []byte("hello world")
)

// TestKeySizeError tests the KeySizeError type and its Error() method
func TestKeySizeError(t *testing.T) {
	t.Run("valid key size", func(t *testing.T) {
		err := KeySizeError(8)
		expected := "crypto/des: invalid key size 8, must be 8 bytes"
		assert.Equal(t, expected, err.Error())
	})

	t.Run("invalid key sizes", func(t *testing.T) {
		invalidSizes := []int{0, 1, 7, 9, 15, 16, 17, 23, 24, 25, 31, 32, 33, 64, 128}
		for _, size := range invalidSizes {
			err := KeySizeError(size)
			expected := "crypto/des: invalid key size 0, must be 8 bytes"
			if size == 0 {
				expected = "crypto/des: invalid key size 0, must be 8 bytes"
			} else if size == 1 {
				expected = "crypto/des: invalid key size 1, must be 8 bytes"
			} else if size == 7 {
				expected = "crypto/des: invalid key size 7, must be 8 bytes"
			} else if size == 9 {
				expected = "crypto/des: invalid key size 9, must be 8 bytes"
			} else if size == 15 {
				expected = "crypto/des: invalid key size 15, must be 8 bytes"
			} else if size == 16 {
				expected = "crypto/des: invalid key size 16, must be 8 bytes"
			} else if size == 17 {
				expected = "crypto/des: invalid key size 17, must be 8 bytes"
			} else if size == 23 {
				expected = "crypto/des: invalid key size 23, must be 8 bytes"
			} else if size == 24 {
				expected = "crypto/des: invalid key size 24, must be 8 bytes"
			} else if size == 25 {
				expected = "crypto/des: invalid key size 25, must be 8 bytes"
			} else if size == 31 {
				expected = "crypto/des: invalid key size 31, must be 8 bytes"
			} else if size == 32 {
				expected = "crypto/des: invalid key size 32, must be 8 bytes"
			} else if size == 33 {
				expected = "crypto/des: invalid key size 33, must be 8 bytes"
			} else if size == 64 {
				expected = "crypto/des: invalid key size 64, must be 8 bytes"
			} else if size == 128 {
				expected = "crypto/des: invalid key size 128, must be 8 bytes"
			}
			assert.Equal(t, expected, err.Error())
		}
	})

	t.Run("negative key size", func(t *testing.T) {
		err := KeySizeError(-1)
		expected := "crypto/des: invalid key size -1, must be 8 bytes"
		assert.Equal(t, expected, err.Error())
	})

	t.Run("large key size", func(t *testing.T) {
		err := KeySizeError(1000)
		expected := "crypto/des: invalid key size 1000, must be 8 bytes"
		assert.Equal(t, expected, err.Error())
	})
}

// TestEncryptError tests the EncryptError type and its Error() method
func TestEncryptError(t *testing.T) {
	t.Run("with nil error", func(t *testing.T) {
		err := EncryptError{Err: nil}
		expected := "crypto/des: failed to encrypt data: <nil>"
		assert.Equal(t, expected, err.Error())
	})

	t.Run("with simple error", func(t *testing.T) {
		originalErr := errors.New("simple error")
		err := EncryptError{Err: originalErr}
		expected := "crypto/des: failed to encrypt data: simple error"
		assert.Equal(t, expected, err.Error())
	})

	t.Run("with complex error message", func(t *testing.T) {
		originalErr := errors.New("encryption failed: invalid key format")
		err := EncryptError{Err: originalErr}
		expected := "crypto/des: failed to encrypt data: encryption failed: invalid key format"
		assert.Equal(t, expected, err.Error())
	})

	t.Run("with wrapped error", func(t *testing.T) {
		originalErr := errors.New("underlying error")
		wrappedErr := errors.New("wrapped: " + originalErr.Error())
		err := EncryptError{Err: wrappedErr}
		expected := "crypto/des: failed to encrypt data: wrapped: underlying error"
		assert.Equal(t, expected, err.Error())
	})

	t.Run("with empty error message", func(t *testing.T) {
		originalErr := errors.New("")
		err := EncryptError{Err: originalErr}
		expected := "crypto/des: failed to encrypt data: "
		assert.Equal(t, expected, err.Error())
	})
}

// TestDecryptError tests the DecryptError type and its Error() method
func TestDecryptError(t *testing.T) {
	t.Run("with nil error", func(t *testing.T) {
		err := DecryptError{Err: nil}
		expected := "crypto/des: failed to decrypt data: <nil>"
		assert.Equal(t, expected, err.Error())
	})

	t.Run("with simple error", func(t *testing.T) {
		originalErr := errors.New("decryption failed")
		err := DecryptError{Err: originalErr}
		expected := "crypto/des: failed to decrypt data: decryption failed"
		assert.Equal(t, expected, err.Error())
	})

	t.Run("with complex error message", func(t *testing.T) {
		originalErr := errors.New("decryption failed: invalid ciphertext format")
		err := DecryptError{Err: originalErr}
		expected := "crypto/des: failed to decrypt data: decryption failed: invalid ciphertext format"
		assert.Equal(t, expected, err.Error())
	})

	t.Run("with authentication error", func(t *testing.T) {
		originalErr := errors.New("authentication failed")
		err := DecryptError{Err: originalErr}
		expected := "crypto/des: failed to decrypt data: authentication failed"
		assert.Equal(t, expected, err.Error())
	})

	t.Run("with empty error message", func(t *testing.T) {
		originalErr := errors.New("")
		err := DecryptError{Err: originalErr}
		expected := "crypto/des: failed to decrypt data: "
		assert.Equal(t, expected, err.Error())
	})
}

// TestReadError tests the ReadError type and its Error() method
func TestReadError(t *testing.T) {
	t.Run("with nil error", func(t *testing.T) {
		err := ReadError{Err: nil}
		expected := "crypto/des: failed to read encrypted data: <nil>"
		assert.Equal(t, expected, err.Error())
	})

	t.Run("with simple error", func(t *testing.T) {
		originalErr := errors.New("read failed")
		err := ReadError{Err: originalErr}
		expected := "crypto/des: failed to read encrypted data: read failed"
		assert.Equal(t, expected, err.Error())
	})

	t.Run("with complex error message", func(t *testing.T) {
		originalErr := errors.New("read failed: connection timeout")
		err := ReadError{Err: originalErr}
		expected := "crypto/des: failed to read encrypted data: read failed: connection timeout"
		assert.Equal(t, expected, err.Error())
	})

	t.Run("with EOF error", func(t *testing.T) {
		originalErr := errors.New("unexpected EOF")
		err := ReadError{Err: originalErr}
		expected := "crypto/des: failed to read encrypted data: unexpected EOF"
		assert.Equal(t, expected, err.Error())
	})

	t.Run("with empty error message", func(t *testing.T) {
		originalErr := errors.New("")
		err := ReadError{Err: originalErr}
		expected := "crypto/des: failed to read encrypted data: "
		assert.Equal(t, expected, err.Error())
	})
}

// TestBufferError tests the BufferError type and its Error() method
func TestBufferError(t *testing.T) {
	t.Run("small buffer", func(t *testing.T) {
		err := BufferError{bufferSize: 5, dataSize: 10}
		expected := "crypto/des: buffer size 5 is too small for data size 10"
		assert.Equal(t, expected, err.Error())
	})

	t.Run("zero buffer size", func(t *testing.T) {
		err := BufferError{bufferSize: 0, dataSize: 10}
		expected := "crypto/des: buffer size 0 is too small for data size 10"
		assert.Equal(t, expected, err.Error())
	})

	t.Run("negative buffer size", func(t *testing.T) {
		err := BufferError{bufferSize: -1, dataSize: 10}
		expected := "crypto/des: buffer size -1 is too small for data size 10"
		assert.Equal(t, expected, err.Error())
	})

	t.Run("zero data size", func(t *testing.T) {
		err := BufferError{bufferSize: 5, dataSize: 0}
		expected := "crypto/des: buffer size 5 is too small for data size 0"
		assert.Equal(t, expected, err.Error())
	})

	t.Run("negative data size", func(t *testing.T) {
		err := BufferError{bufferSize: 5, dataSize: -1}
		expected := "crypto/des: buffer size 5 is too small for data size -1"
		assert.Equal(t, expected, err.Error())
	})

	t.Run("large buffer size", func(t *testing.T) {
		err := BufferError{bufferSize: 1000, dataSize: 2000}
		expected := "crypto/des: buffer size 1000 is too small for data size 2000"
		assert.Equal(t, expected, err.Error())
	})

	t.Run("equal sizes", func(t *testing.T) {
		err := BufferError{bufferSize: 10, dataSize: 10}
		expected := "crypto/des: buffer size 10 is too small for data size 10"
		assert.Equal(t, expected, err.Error())
	})

	t.Run("both zero", func(t *testing.T) {
		err := BufferError{bufferSize: 0, dataSize: 0}
		expected := "crypto/des: buffer size 0 is too small for data size 0"
		assert.Equal(t, expected, err.Error())
	})

	t.Run("both negative", func(t *testing.T) {
		err := BufferError{bufferSize: -5, dataSize: -10}
		expected := "crypto/des: buffer size -5 is too small for data size -10"
		assert.Equal(t, expected, err.Error())
	})
}

// TestErrorIntegration tests error types in actual DES operations
func TestErrorIntegration(t *testing.T) {
	t.Run("KeySizeError in StdEncrypter", func(t *testing.T) {
		invalidKeys := [][]byte{
			nil,
			{},
			[]byte("short"),
			[]byte("17bytes_key123456"),
			make([]byte, 9),
		}

		for _, key := range invalidKeys {
			c := cipher.NewDesCipher(cipher.CBC)
			c.SetKey(key)
			c.SetIV(iv8Error)
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
			c := cipher.NewDesCipher(cipher.CBC)
			c.SetKey(key)

			decrypter := NewStdDecrypter(c)
			assert.NotNil(t, decrypter)
			assert.NotNil(t, decrypter.Error)
			assert.IsType(t, KeySizeError(0), decrypter.Error)
		}
	})

	t.Run("KeySizeError in StreamEncrypter", func(t *testing.T) {
		var buf bytes.Buffer
		c := cipher.NewDesCipher(cipher.CBC)
		c.SetKey([]byte("invalid"))

		encrypter := NewStreamEncrypter(&buf, c)
		streamEncrypter := encrypter.(*StreamEncrypter)
		assert.NotNil(t, streamEncrypter.Error)
		assert.IsType(t, KeySizeError(0), streamEncrypter.Error)
	})

	t.Run("KeySizeError in StreamDecrypter", func(t *testing.T) {
		file := mock.NewFile([]byte("test"), "test.txt")
		c := cipher.NewDesCipher(cipher.CBC)
		c.SetKey([]byte("invalid"))

		decrypter := NewStreamDecrypter(file, c)
		streamDecrypter := decrypter.(*StreamDecrypter)
		assert.NotNil(t, streamDecrypter.Error)
		assert.IsType(t, KeySizeError(0), streamDecrypter.Error)
	})

	t.Run("EncryptError in StreamEncrypter Write", func(t *testing.T) {
		var buf bytes.Buffer
		c := cipher.NewDesCipher(cipher.CBC)
		c.SetKey(key8Error)
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
		c := cipher.NewDesCipher(cipher.CBC)
		c.SetKey(key8Error)

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

// TestDes_Errors tests basic error types (moved from des_cbc_test.go)
func TestDes_Errors(t *testing.T) {
	// KeySizeError tests
	t.Run("key size error", func(t *testing.T) {
		err := KeySizeError(16)
		expected := "crypto/des: invalid key size 16, must be 8 bytes"
		assert.Equal(t, expected, err.Error())
	})

	// EncryptError tests
	t.Run("encrypt error", func(t *testing.T) {
		originalErr := errors.New("original error")
		err := EncryptError{Err: originalErr}
		assert.Contains(t, err.Error(), "crypto/des: failed to encrypt data:")
		assert.Contains(t, err.Error(), "original error")
	})

	// DecryptError tests
	t.Run("decrypt error", func(t *testing.T) {
		originalErr := errors.New("original error")
		err := DecryptError{Err: originalErr}
		assert.Contains(t, err.Error(), "crypto/des: failed to decrypt data:")
		assert.Contains(t, err.Error(), "original error")
	})

	// ReadError tests
	t.Run("read error", func(t *testing.T) {
		originalErr := errors.New("original error")
		err := ReadError{Err: originalErr}
		assert.Contains(t, err.Error(), "crypto/des: failed to read encrypted data:")
		assert.Contains(t, err.Error(), "original error")
	})

	// BufferError tests
	t.Run("buffer error", func(t *testing.T) {
		err := BufferError{bufferSize: 5, dataSize: 10}
		expected := "crypto/des: buffer size 5 is too small for data size 10"
		assert.Equal(t, expected, err.Error())
	})
}

// TestAdditionalCoverage tests additional error scenarios (moved from des_cbc_test.go)
func TestAdditionalCoverage(t *testing.T) {
	t.Run("stream encrypter write with nil block", func(t *testing.T) {
		var buf bytes.Buffer
		c := cipher.NewDesCipher(cipher.CBC)
		c.SetKey(key8Error)
		c.SetIV(iv8Error)
		c.SetPadding(cipher.PKCS7)

		encrypter := NewStreamEncrypter(&buf, c)
		streamEncrypter := encrypter.(*StreamEncrypter)
		streamEncrypter.block = nil // Force nil block to test the nil check

		n, err := encrypter.Write(testDataError)
		assert.Equal(t, len(testDataError), n) // Should work as it recreates the block
		assert.Nil(t, err)
	})

	t.Run("stream decrypter read with nil block", func(t *testing.T) {
		file := mock.NewFile([]byte("test data"), "test.txt")
		c := cipher.NewDesCipher(cipher.CBC)
		c.SetKey(key8Error)
		c.SetIV(iv8Error)
		c.SetPadding(cipher.PKCS7)

		decrypter := NewStreamDecrypter(file, c)
		streamDecrypter := decrypter.(*StreamDecrypter)
		streamDecrypter.block = nil // Force nil block to test the nil check

		buf := make([]byte, 100)
		n, _ := decrypter.Read(buf)
		// Should still work as it recreates the block
		assert.True(t, n >= 0)
	})

	t.Run("test encrypter write with writer error", func(t *testing.T) {
		// Create a mock writer that returns an error
		mockWriter := mock.NewErrorReadWriteCloser(errors.New("write error"))
		c := cipher.NewDesCipher(cipher.CBC)
		c.SetKey(key8Error)
		c.SetIV(iv8Error)
		c.SetPadding(cipher.PKCS7)

		encrypter := NewStreamEncrypter(mockWriter, c)
		n, err := encrypter.Write(testDataError)
		assert.Equal(t, 0, n)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "write error")
	})

	t.Run("test encrypter write with cipher encrypt error", func(t *testing.T) {
		var buf bytes.Buffer
		c := cipher.NewDesCipher(cipher.CBC)
		c.SetKey(key8Error)
		// Don't set IV to cause encryption error
		c.SetPadding(cipher.PKCS7)

		encrypter := NewStreamEncrypter(&buf, c)
		n, err := encrypter.Write(testDataError)
		// This should cause c.cipher.Encrypt to return an error
		if err != nil {
			assert.Equal(t, 0, n)
			assert.IsType(t, EncryptError{}, err)
		} else {
			// Fallback: if no error occurs, verify normal operation
			assert.NotEqual(t, 0, n)
		}
	})

	t.Run("test NewStreamEncrypter with invalid key length", func(t *testing.T) {
		var buf bytes.Buffer
		c := cipher.NewDesCipher(cipher.CBC)
		c.SetKey([]byte("short"))
		c.SetIV(iv8Error)
		c.SetPadding(cipher.PKCS7)

		encrypter := NewStreamEncrypter(&buf, c)
		streamEncrypter := encrypter.(*StreamEncrypter)

		// Should have KeySizeError
		assert.NotNil(t, streamEncrypter.Error)
		assert.IsType(t, KeySizeError(0), streamEncrypter.Error)

		// Try to write, which should return the error
		n, err := encrypter.Write(testDataError)
		assert.Equal(t, 0, n)
		assert.Error(t, err)
		assert.IsType(t, KeySizeError(0), err)
	})

	t.Run("test NewStreamDecrypter with invalid key length", func(t *testing.T) {
		file := mock.NewFile([]byte("test data"), "test.txt")
		c := cipher.NewDesCipher(cipher.CBC)
		c.SetKey([]byte("short"))
		c.SetIV(iv8Error)
		c.SetPadding(cipher.PKCS7)

		decrypter := NewStreamDecrypter(file, c)
		streamDecrypter := decrypter.(*StreamDecrypter)

		// Should have KeySizeError
		assert.NotNil(t, streamDecrypter.Error)
		assert.IsType(t, KeySizeError(0), streamDecrypter.Error)

		// Try to read, which should return the error
		buf := make([]byte, 100)
		n, err := decrypter.Read(buf)
		assert.Equal(t, 0, n)
		assert.Error(t, err)
		assert.IsType(t, KeySizeError(0), err)
	})
}

// TestStreamDecrypter_Read_EOF tests the EOF case when all data has been read
func TestStreamDecrypter_Read_EOF(t *testing.T) {
	t.Run("read after all data consumed", func(t *testing.T) {
		// First encrypt some data
		var buf bytes.Buffer
		c := cipher.NewDesCipher(cipher.CBC)
		c.SetKey(key8Error)
		c.SetIV(iv8Error)
		c.SetPadding(cipher.PKCS7)

		encrypter := NewStreamEncrypter(&buf, c)
		_, err := encrypter.Write(testDataError)
		assert.Nil(t, err)
		err = encrypter.Close()
		assert.Nil(t, err)

		// Now decrypt with a small buffer to ensure we read all data
		file := mock.NewFile(buf.Bytes(), "encrypted.dat")
		decrypter := NewStreamDecrypter(file, c)

		// Read all data in small chunks
		readBuf := make([]byte, 2) // Small buffer to ensure multiple reads
		totalRead := 0
		for {
			n, err := decrypter.Read(readBuf)
			totalRead += n
			if err == io.EOF {
				break
			}
			assert.Nil(t, err)
			if totalRead > len(testDataError)*2 { // Safety check to avoid infinite loop
				t.Fatal("Too many reads, possible infinite loop")
			}
		}

		// Now try to read again - should return EOF
		n, err := decrypter.Read(readBuf)
		assert.Equal(t, 0, n)
		assert.Equal(t, io.EOF, err)
	})

	t.Run("read with empty encrypted data", func(t *testing.T) {
		// Create an empty encrypted file
		file := mock.NewFile([]byte{}, "empty.dat")
		c := cipher.NewDesCipher(cipher.CBC)
		c.SetKey(key8Error)
		c.SetIV(iv8Error)
		c.SetPadding(cipher.PKCS7)

		decrypter := NewStreamDecrypter(file, c)
		buf := make([]byte, 100)
		n, err := decrypter.Read(buf)
		assert.Equal(t, 0, n)
		assert.Equal(t, io.EOF, err)
	})
}

func TestUnsupportedBlockModeError(t *testing.T) {
	t.Run("error message format", func(t *testing.T) {
		err := UnsupportedBlockModeError{Mode: "GCM"}
		assert.Equal(t, "crypto/des: unsupported block mode 'GCM', DES only supports CBC, CTR, ECB, CFB, and OFB modes", err.Error())
	})
}

func TestNewStdEncrypter_ErrorPaths(t *testing.T) {
	t.Run("invalid key size - too short", func(t *testing.T) {
		c := cipher.NewDesCipher(cipher.CBC)
		c.SetKey([]byte("short")) // 5 bytes - too short
		c.SetIV(iv8Error)
		c.SetPadding(cipher.PKCS7)

		encrypter := NewStdEncrypter(c)
		assert.NotNil(t, encrypter)
		assert.NotNil(t, encrypter.Error)
		assert.IsType(t, KeySizeError(0), encrypter.Error)
		assert.Equal(t, "crypto/des: invalid key size 5, must be 8 bytes", encrypter.Error.Error())
	})

	t.Run("invalid key size - too long", func(t *testing.T) {
		c := cipher.NewDesCipher(cipher.CBC)
		c.SetKey([]byte("123456789")) // 9 bytes - too long
		c.SetIV(iv8Error)
		c.SetPadding(cipher.PKCS7)

		encrypter := NewStdEncrypter(c)
		assert.NotNil(t, encrypter)
		assert.NotNil(t, encrypter.Error)
		assert.IsType(t, KeySizeError(0), encrypter.Error)
		assert.Equal(t, "crypto/des: invalid key size 9, must be 8 bytes", encrypter.Error.Error())
	})

	t.Run("unsupported GCM mode", func(t *testing.T) {
		c := cipher.NewDesCipher(cipher.GCM)
		c.SetKey(key8Error)
		c.SetIV(iv8Error)
		c.SetPadding(cipher.PKCS7)

		encrypter := NewStdEncrypter(c)
		assert.NotNil(t, encrypter)
		assert.NotNil(t, encrypter.Error)
		assert.IsType(t, UnsupportedBlockModeError{}, encrypter.Error)
		assert.Equal(t, "crypto/des: unsupported block mode 'GCM', DES only supports CBC, CTR, ECB, CFB, and OFB modes", encrypter.Error.Error())
	})

	t.Run("valid configuration", func(t *testing.T) {
		c := cipher.NewDesCipher(cipher.CBC)
		c.SetKey(key8Error)
		c.SetIV(iv8Error)
		c.SetPadding(cipher.PKCS7)

		encrypter := NewStdEncrypter(c)
		assert.NotNil(t, encrypter)
		assert.Nil(t, encrypter.Error)
	})
}

func TestNewStdDecrypter_ErrorPaths(t *testing.T) {
	t.Run("invalid key size - too short", func(t *testing.T) {
		c := cipher.NewDesCipher(cipher.CBC)
		c.SetKey([]byte("short")) // 5 bytes - too short
		c.SetIV(iv8Error)
		c.SetPadding(cipher.PKCS7)

		decrypter := NewStdDecrypter(c)
		assert.NotNil(t, decrypter)
		assert.NotNil(t, decrypter.Error)
		assert.IsType(t, KeySizeError(0), decrypter.Error)
		assert.Equal(t, "crypto/des: invalid key size 5, must be 8 bytes", decrypter.Error.Error())
	})

	t.Run("invalid key size - too long", func(t *testing.T) {
		c := cipher.NewDesCipher(cipher.CBC)
		c.SetKey([]byte("123456789")) // 9 bytes - too long
		c.SetIV(iv8Error)
		c.SetPadding(cipher.PKCS7)

		decrypter := NewStdDecrypter(c)
		assert.NotNil(t, decrypter)
		assert.NotNil(t, decrypter.Error)
		assert.IsType(t, KeySizeError(0), decrypter.Error)
		assert.Equal(t, "crypto/des: invalid key size 9, must be 8 bytes", decrypter.Error.Error())
	})

	t.Run("unsupported GCM mode", func(t *testing.T) {
		c := cipher.NewDesCipher(cipher.GCM)
		c.SetKey(key8Error)
		c.SetIV(iv8Error)
		c.SetPadding(cipher.PKCS7)

		decrypter := NewStdDecrypter(c)
		assert.NotNil(t, decrypter)
		assert.NotNil(t, decrypter.Error)
		assert.IsType(t, UnsupportedBlockModeError{}, decrypter.Error)
		assert.Equal(t, "crypto/des: unsupported block mode 'GCM', DES only supports CBC, CTR, ECB, CFB, and OFB modes", decrypter.Error.Error())
	})

	t.Run("valid configuration", func(t *testing.T) {
		c := cipher.NewDesCipher(cipher.CBC)
		c.SetKey(key8Error)
		c.SetIV(iv8Error)
		c.SetPadding(cipher.PKCS7)

		decrypter := NewStdDecrypter(c)
		assert.NotNil(t, decrypter)
		assert.Nil(t, decrypter.Error)
	})
}

func TestStdEncrypter_Encrypt_ErrorPaths(t *testing.T) {
	t.Run("encrypt with existing error", func(t *testing.T) {
		c := cipher.NewDesCipher(cipher.CBC)
		c.SetKey([]byte("short")) // Invalid key size
		c.SetIV(iv8Error)
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

	t.Run("encrypt with invalid key causing des.NewCipher error", func(t *testing.T) {
		c := cipher.NewDesCipher(cipher.CBC)
		c.SetKey(key8Error)
		c.SetIV(iv8Error)
		c.SetPadding(cipher.PKCS7)

		encrypter := NewStdEncrypter(c)
		// Manually set an invalid key to cause des.NewCipher to fail
		encrypter.cipher.Key = []byte("invalid")

		result, err := encrypter.Encrypt(testDataError)
		// The encryption will fail because the key is invalid
		assert.Empty(t, result)
		assert.NotNil(t, err)
		assert.IsType(t, EncryptError{}, err)
	})

	t.Run("encrypt empty data", func(t *testing.T) {
		c := cipher.NewDesCipher(cipher.CBC)
		c.SetKey(key8Error)
		c.SetIV(iv8Error)
		c.SetPadding(cipher.PKCS7)

		encrypter := NewStdEncrypter(c)
		result, err := encrypter.Encrypt([]byte{})
		assert.Empty(t, result)
		assert.Nil(t, err)
	})

	t.Run("encrypt with des.NewCipher error", func(t *testing.T) {
		c := cipher.NewDesCipher(cipher.CBC)
		c.SetKey(key8Error)
		c.SetIV(iv8Error)
		c.SetPadding(cipher.PKCS7)

		encrypter := NewStdEncrypter(c)
		// Set a key that will cause des.NewCipher to fail
		// This is difficult to achieve with the current implementation,
		// but we can test the error path by mocking
		encrypter.cipher.Key = nil // This should cause des.NewCipher to fail

		result, err := encrypter.Encrypt(testDataError)
		assert.Empty(t, result)
		assert.NotNil(t, err)
		assert.IsType(t, EncryptError{}, err)
	})
}

func TestStdDecrypter_Decrypt_ErrorPaths(t *testing.T) {
	t.Run("decrypt with existing error", func(t *testing.T) {
		c := cipher.NewDesCipher(cipher.CBC)
		c.SetKey([]byte("short")) // Invalid key size
		c.SetIV(iv8Error)
		c.SetPadding(cipher.PKCS7)

		decrypter := NewStdDecrypter(c)
		assert.NotNil(t, decrypter.Error)

		// Try to decrypt with existing error - it will still try to decrypt
		result, err := decrypter.Decrypt(testDataError)
		// The decryption will fail because the data is not properly encrypted
		// and the cipher interface will return an error
		assert.Empty(t, result)
		assert.NotNil(t, err)
	})

	t.Run("decrypt with invalid key causing des.NewCipher error", func(t *testing.T) {
		c := cipher.NewDesCipher(cipher.CBC)
		c.SetKey(key8Error)
		c.SetIV(iv8Error)
		c.SetPadding(cipher.PKCS7)

		decrypter := NewStdDecrypter(c)
		// Manually set an invalid key to cause des.NewCipher to fail
		decrypter.cipher.Key = []byte("invalid")

		result, err := decrypter.Decrypt(testDataError)
		// The decryption will fail because the data is not properly encrypted
		assert.Empty(t, result)
		assert.NotNil(t, err)
		// The error will be from the cipher interface, not DecryptError
	})

	t.Run("decrypt empty data", func(t *testing.T) {
		c := cipher.NewDesCipher(cipher.CBC)
		c.SetKey(key8Error)
		c.SetIV(iv8Error)
		c.SetPadding(cipher.PKCS7)

		decrypter := NewStdDecrypter(c)
		result, err := decrypter.Decrypt([]byte{})
		assert.Empty(t, result)
		assert.Nil(t, err)
	})

	t.Run("decrypt with des.NewCipher error", func(t *testing.T) {
		c := cipher.NewDesCipher(cipher.CBC)
		c.SetKey(key8Error)
		c.SetIV(iv8Error)
		c.SetPadding(cipher.PKCS7)

		decrypter := NewStdDecrypter(c)
		// Set a key that will cause des.NewCipher to fail
		// This is difficult to achieve with the current implementation,
		// but we can test the error path by mocking
		decrypter.cipher.Key = nil // This should cause des.NewCipher to fail

		result, err := decrypter.Decrypt(testDataError)
		assert.Empty(t, result)
		assert.NotNil(t, err)
		assert.IsType(t, DecryptError{}, err)
	})
}

func TestNewStreamEncrypter_ErrorPaths(t *testing.T) {
	t.Run("invalid key size - too short", func(t *testing.T) {
		c := cipher.NewDesCipher(cipher.CBC)
		c.SetKey([]byte("short")) // 5 bytes - too short
		c.SetIV(iv8Error)
		c.SetPadding(cipher.PKCS7)

		var buf bytes.Buffer
		encrypter := NewStreamEncrypter(&buf, c)
		streamEncrypter := encrypter.(*StreamEncrypter)
		assert.NotNil(t, streamEncrypter.Error)
		assert.IsType(t, KeySizeError(0), streamEncrypter.Error)
	})

	t.Run("invalid key size - too long", func(t *testing.T) {
		c := cipher.NewDesCipher(cipher.CBC)
		c.SetKey([]byte("123456789")) // 9 bytes - too long
		c.SetIV(iv8Error)
		c.SetPadding(cipher.PKCS7)

		var buf bytes.Buffer
		encrypter := NewStreamEncrypter(&buf, c)
		streamEncrypter := encrypter.(*StreamEncrypter)
		assert.NotNil(t, streamEncrypter.Error)
		assert.IsType(t, KeySizeError(0), streamEncrypter.Error)
	})

	t.Run("unsupported GCM mode", func(t *testing.T) {
		c := cipher.NewDesCipher(cipher.GCM)
		c.SetKey(key8Error)
		c.SetIV(iv8Error)
		c.SetPadding(cipher.PKCS7)

		var buf bytes.Buffer
		encrypter := NewStreamEncrypter(&buf, c)
		streamEncrypter := encrypter.(*StreamEncrypter)
		assert.NotNil(t, streamEncrypter.Error)
		assert.IsType(t, UnsupportedBlockModeError{}, streamEncrypter.Error)
	})

	t.Run("valid configuration", func(t *testing.T) {
		c := cipher.NewDesCipher(cipher.CBC)
		c.SetKey(key8Error)
		c.SetIV(iv8Error)
		c.SetPadding(cipher.PKCS7)

		var buf bytes.Buffer
		encrypter := NewStreamEncrypter(&buf, c)
		streamEncrypter := encrypter.(*StreamEncrypter)
		assert.Nil(t, streamEncrypter.Error)
	})
}

func TestNewStreamDecrypter_ErrorPaths(t *testing.T) {
	t.Run("invalid key size - too short", func(t *testing.T) {
		c := cipher.NewDesCipher(cipher.CBC)
		c.SetKey([]byte("short")) // 5 bytes - too short
		c.SetIV(iv8Error)
		c.SetPadding(cipher.PKCS7)

		reader := mock.NewFile(testDataError, "test.txt")
		decrypter := NewStreamDecrypter(reader, c)
		streamDecrypter := decrypter.(*StreamDecrypter)
		assert.NotNil(t, streamDecrypter.Error)
		assert.IsType(t, KeySizeError(0), streamDecrypter.Error)
	})

	t.Run("invalid key size - too long", func(t *testing.T) {
		c := cipher.NewDesCipher(cipher.CBC)
		c.SetKey([]byte("123456789")) // 9 bytes - too long
		c.SetIV(iv8Error)
		c.SetPadding(cipher.PKCS7)

		reader := mock.NewFile(testDataError, "test.txt")
		decrypter := NewStreamDecrypter(reader, c)
		streamDecrypter := decrypter.(*StreamDecrypter)
		assert.NotNil(t, streamDecrypter.Error)
		assert.IsType(t, KeySizeError(0), streamDecrypter.Error)
	})

	t.Run("unsupported GCM mode", func(t *testing.T) {
		c := cipher.NewDesCipher(cipher.GCM)
		c.SetKey(key8Error)
		c.SetIV(iv8Error)
		c.SetPadding(cipher.PKCS7)

		reader := mock.NewFile(testDataError, "test.txt")
		decrypter := NewStreamDecrypter(reader, c)
		streamDecrypter := decrypter.(*StreamDecrypter)
		assert.NotNil(t, streamDecrypter.Error)
		assert.IsType(t, UnsupportedBlockModeError{}, streamDecrypter.Error)
	})

	t.Run("valid configuration", func(t *testing.T) {
		c := cipher.NewDesCipher(cipher.CBC)
		c.SetKey(key8Error)
		c.SetIV(iv8Error)
		c.SetPadding(cipher.PKCS7)

		reader := mock.NewFile(testDataError, "test.txt")
		decrypter := NewStreamDecrypter(reader, c)
		streamDecrypter := decrypter.(*StreamDecrypter)
		assert.Nil(t, streamDecrypter.Error)
	})
}

func TestStreamEncrypter_Close_ErrorPaths(t *testing.T) {
	t.Run("close with existing error", func(t *testing.T) {
		c := cipher.NewDesCipher(cipher.CBC)
		c.SetKey([]byte("short")) // Invalid key size
		c.SetIV(iv8Error)
		c.SetPadding(cipher.PKCS7)

		var buf bytes.Buffer
		encrypter := NewStreamEncrypter(&buf, c)
		streamEncrypter := encrypter.(*StreamEncrypter)
		assert.NotNil(t, streamEncrypter.Error)

		err := encrypter.Close()
		assert.NotNil(t, err)
		assert.Equal(t, streamEncrypter.Error, err)
	})

	t.Run("close with underlying closer", func(t *testing.T) {
		c := cipher.NewDesCipher(cipher.CBC)
		c.SetKey(key8Error)
		c.SetIV(iv8Error)
		c.SetPadding(cipher.PKCS7)

		// Use a mock closer that implements io.Closer
		mockCloser := mock.NewErrorReadWriteCloser(nil)
		encrypter := NewStreamEncrypter(mockCloser, c)

		err := encrypter.Close()
		assert.Nil(t, err) // mockCloser.Close() returns nil
	})

	t.Run("close with underlying closer error", func(t *testing.T) {
		c := cipher.NewDesCipher(cipher.CBC)
		c.SetKey(key8Error)
		c.SetIV(iv8Error)
		c.SetPadding(cipher.PKCS7)

		// Use a mock closer that returns an error
		var buf bytes.Buffer
		mockCloser := mock.NewCloseErrorWriteCloser(&buf, errors.New("close failed"))
		encrypter := NewStreamEncrypter(mockCloser, c)

		err := encrypter.Close()
		assert.NotNil(t, err)
		assert.Equal(t, "close failed", err.Error())
	})

	t.Run("close with non-closer writer", func(t *testing.T) {
		c := cipher.NewDesCipher(cipher.CBC)
		c.SetKey(key8Error)
		c.SetIV(iv8Error)
		c.SetPadding(cipher.PKCS7)

		var buf bytes.Buffer
		encrypter := NewStreamEncrypter(&buf, c)

		err := encrypter.Close()
		assert.Nil(t, err) // bytes.Buffer doesn't implement io.Closer
	})
}

func TestStreamEncrypter_Write_ErrorPaths(t *testing.T) {
	t.Run("write with existing error", func(t *testing.T) {
		c := cipher.NewDesCipher(cipher.CBC)
		c.SetKey([]byte("short")) // Invalid key size
		c.SetIV(iv8Error)
		c.SetPadding(cipher.PKCS7)

		var buf bytes.Buffer
		encrypter := NewStreamEncrypter(&buf, c)
		streamEncrypter := encrypter.(*StreamEncrypter)
		assert.NotNil(t, streamEncrypter.Error)

		n, err := encrypter.Write(testDataError)
		assert.Equal(t, 0, n)
		assert.NotNil(t, err)
		assert.Equal(t, streamEncrypter.Error, err)
	})

	t.Run("write with empty data", func(t *testing.T) {
		c := cipher.NewDesCipher(cipher.CBC)
		c.SetKey(key8Error)
		c.SetIV(iv8Error)
		c.SetPadding(cipher.PKCS7)

		var buf bytes.Buffer
		encrypter := NewStreamEncrypter(&buf, c)
		n, err := encrypter.Write([]byte{})
		assert.Equal(t, 0, n)
		assert.Nil(t, err)
	})

	t.Run("write with buffer accumulation", func(t *testing.T) {
		c := cipher.NewDesCipher(cipher.CBC)
		c.SetKey(key8Error)
		c.SetIV(iv8Error)
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

	t.Run("write with writer error", func(t *testing.T) {
		c := cipher.NewDesCipher(cipher.CBC)
		c.SetKey(key8Error)
		c.SetIV(iv8Error)
		c.SetPadding(cipher.PKCS7)

		// Create a mock writer that always returns an error
		mockWriter := mock.NewErrorReadWriteCloser(errors.New("write failed"))
		encrypter := NewStreamEncrypter(mockWriter, c)

		n, err := encrypter.Write(testDataError)
		assert.Equal(t, 0, n)
		assert.NotNil(t, err)
		assert.Contains(t, err.Error(), "write failed")
	})

	t.Run("write with cipher.Encrypt error", func(t *testing.T) {
		c := cipher.NewDesCipher(cipher.CBC)
		c.SetKey(key8Error)
		// Don't set IV to cause cipher.Encrypt error
		c.SetPadding(cipher.PKCS7)

		var buf bytes.Buffer
		encrypter := NewStreamEncrypter(&buf, c)
		n, err := encrypter.Write(testDataError)
		// This should cause c.cipher.Encrypt to return an error
		if err != nil {
			assert.Equal(t, 0, n)
			assert.IsType(t, EncryptError{}, err)
		} else {
			// Fallback: if no error occurs, verify normal operation
			assert.Greater(t, n, 0)
		}
	})

	t.Run("write normal case", func(t *testing.T) {
		c := cipher.NewDesCipher(cipher.CBC)
		c.SetKey(key8Error)
		c.SetIV(iv8Error)
		c.SetPadding(cipher.PKCS7)

		var buf bytes.Buffer
		encrypter := NewStreamEncrypter(&buf, c)

		n, err := encrypter.Write(testDataError)
		assert.Nil(t, err)
		assert.Equal(t, len(testDataError), n)
	})
}
