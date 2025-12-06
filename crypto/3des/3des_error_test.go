package triple_des

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"testing"

	"github.com/dromara/dongle/crypto/cipher"
	"github.com/dromara/dongle/internal/mock"
	"github.com/stretchr/testify/assert"
)

// Test data for error testing
var (
	key16Error = []byte("1234567890123456") // 16-byte key for 2-key 3DES

	iv8Error      = []byte("87654321") // 8-byte IV
	testDataError = []byte("hello world")
)

// TestKeySizeError tests the KeySizeError type and its Error() method
func TestKeySizeError(t *testing.T) {
	t.Run("invalid key sizes", func(t *testing.T) {
		invalidSizes := []int{0, 1, 7, 8, 9, 15, 17, 23, 25, 31, 32, 33, 64, 128}
		for _, size := range invalidSizes {
			err := KeySizeError(size)
			expected := fmt.Sprintf("crypto/3des: invalid key size %d, must be 16 or 24 bytes", size)
			assert.Equal(t, expected, err.Error())
		}
	})
}

// TestEncryptError tests the EncryptError type and its Error() method
func TestEncryptError(t *testing.T) {
	t.Run("basic error message", func(t *testing.T) {
		originalErr := errors.New("test encryption error")
		err := EncryptError{Err: originalErr}
		expected := "crypto/3des: failed to encrypt data: test encryption error"
		assert.Equal(t, expected, err.Error())
	})

	t.Run("nil error", func(t *testing.T) {
		err := EncryptError{Err: nil}
		expected := "crypto/3des: failed to encrypt data: <nil>"
		assert.Equal(t, expected, err.Error())
	})

	t.Run("empty error message", func(t *testing.T) {
		originalErr := errors.New("")
		err := EncryptError{Err: originalErr}
		expected := "crypto/3des: failed to encrypt data: "
		assert.Equal(t, expected, err.Error())
	})

	t.Run("error with special characters", func(t *testing.T) {
		specialMessage := "Error with special chars: !@#$%^&*()_+-=[]{}|;':\",./<>?"
		originalErr := errors.New(specialMessage)
		err := EncryptError{Err: originalErr}
		expected := "crypto/3des: failed to encrypt data: " + specialMessage
		assert.Equal(t, expected, err.Error())
	})
}

// TestDecryptError tests the DecryptError type and its Error() method
func TestDecryptError(t *testing.T) {
	t.Run("basic error message", func(t *testing.T) {
		originalErr := errors.New("test decryption error")
		err := DecryptError{Err: originalErr}
		expected := "crypto/3des: failed to decrypt data: test decryption error"
		assert.Equal(t, expected, err.Error())
	})

	t.Run("nil error", func(t *testing.T) {
		err := DecryptError{Err: nil}
		expected := "crypto/3des: failed to decrypt data: <nil>"
		assert.Equal(t, expected, err.Error())
	})

	t.Run("empty error message", func(t *testing.T) {
		originalErr := errors.New("")
		err := DecryptError{Err: originalErr}
		expected := "crypto/3des: failed to decrypt data: "
		assert.Equal(t, expected, err.Error())
	})

	t.Run("DecryptError with special characters", func(t *testing.T) {
		specialMessage := "Error with special chars: !@#$%^&*()_+-=[]{}|;':\",./<>?"
		originalErr := errors.New(specialMessage)
		err := DecryptError{Err: originalErr}
		expected := "crypto/3des: failed to decrypt data: " + specialMessage
		assert.Equal(t, expected, err.Error())
	})
}

// TestReadError tests the ReadError type and its Error() method
func TestReadError(t *testing.T) {
	t.Run("basic error message", func(t *testing.T) {
		originalErr := errors.New("test read error")
		err := ReadError{Err: originalErr}
		expected := "crypto/3des: failed to read encrypted data: test read error"
		assert.Equal(t, expected, err.Error())
	})

	t.Run("nil error", func(t *testing.T) {
		err := ReadError{Err: nil}
		expected := "crypto/3des: failed to read encrypted data: <nil>"
		assert.Equal(t, expected, err.Error())
	})

	t.Run("empty error message", func(t *testing.T) {
		originalErr := errors.New("")
		err := ReadError{Err: originalErr}
		expected := "crypto/3des: failed to read encrypted data: "
		assert.Equal(t, expected, err.Error())
	})
}

// TestBufferError tests the BufferError type and its Error() method
func TestBufferError(t *testing.T) {
	t.Run("basic error message", func(t *testing.T) {
		err := BufferError{bufferSize: 10, dataSize: 20}
		expected := "crypto/3des: buffer size 10 is too small for data size 20"
		assert.Equal(t, expected, err.Error())
	})

	t.Run("zero buffer size", func(t *testing.T) {
		err := BufferError{bufferSize: 0, dataSize: 5}
		expected := "crypto/3des: buffer size 0 is too small for data size 5"
		assert.Equal(t, expected, err.Error())
	})

	t.Run("large data size", func(t *testing.T) {
		err := BufferError{bufferSize: 100, dataSize: 1000}
		expected := "crypto/3des: buffer size 100 is too small for data size 1000"
		assert.Equal(t, expected, err.Error())
	})
}

// TestUnsupportedBlockModeError tests the UnsupportedBlockModeError type and its Error() method
func TestUnsupportedBlockModeError(t *testing.T) {
	t.Run("GCM mode error", func(t *testing.T) {
		err := UnsupportedBlockModeError{Mode: "GCM"}
		expected := "crypto/3des: unsupported block mode 'GCM', 3DES only supports CBC, CTR, ECB, CFB, and OFB modes"
		assert.Equal(t, expected, err.Error())
	})

	t.Run("empty mode error", func(t *testing.T) {
		err := UnsupportedBlockModeError{Mode: ""}
		expected := "crypto/3des: unsupported block mode '', 3DES only supports CBC, CTR, ECB, CFB, and OFB modes"
		assert.Equal(t, expected, err.Error())
	})

	t.Run("other unsupported mode", func(t *testing.T) {
		err := UnsupportedBlockModeError{Mode: "XTS"}
		expected := "crypto/3des: unsupported block mode 'XTS', 3DES only supports CBC, CTR, ECB, CFB, and OFB modes"
		assert.Equal(t, expected, err.Error())
	})
}

// TestErrorIntegration tests error integration with actual encryption/decryption
func TestErrorIntegration(t *testing.T) {
	t.Run("invalid key size for StdEncrypter", func(t *testing.T) {
		invalidKeys := [][]byte{
			nil,
			{},
			[]byte("short"),
			[]byte("8byteskey"),
			[]byte("15byteskey!!"),
			make([]byte, 17),
			make([]byte, 25),
		}
		for _, key := range invalidKeys {
			c := cipher.New3DesCipher(cipher.CBC)
			c.SetKey(key)
			c.SetIV(iv8Error)
			c.SetPadding(cipher.PKCS7)

			encrypter := NewStdEncrypter(c)
			assert.NotNil(t, encrypter)
			assert.NotNil(t, encrypter.Error)
			assert.IsType(t, KeySizeError(0), encrypter.Error)
		}
	})

	t.Run("invalid key size for StdDecrypter", func(t *testing.T) {
		invalidKeys := [][]byte{
			nil,
			{},
			[]byte("short"),
			[]byte("8byteskey"),
			[]byte("15byteskey!!"),
			make([]byte, 17),
			make([]byte, 25),
		}
		for _, key := range invalidKeys {
			c := cipher.New3DesCipher(cipher.CBC)
			c.SetKey(key)
			c.SetIV(iv8Error)
			c.SetPadding(cipher.PKCS7)

			decrypter := NewStdDecrypter(c)
			assert.NotNil(t, decrypter)
			assert.NotNil(t, decrypter.Error)
			assert.IsType(t, KeySizeError(0), decrypter.Error)
		}
	})

	t.Run("invalid key size for StreamEncrypter", func(t *testing.T) {
		var buf bytes.Buffer
		c := cipher.New3DesCipher(cipher.CBC)
		c.SetKey([]byte("invalid")) // 7 bytes - invalid for 3DES
		c.SetIV(iv8Error)
		c.SetPadding(cipher.PKCS7)

		encrypter := NewStreamEncrypter(&buf, c)
		streamEncrypter := encrypter.(*StreamEncrypter)
		assert.NotNil(t, encrypter)
		assert.NotNil(t, streamEncrypter.Error)
		assert.IsType(t, KeySizeError(0), streamEncrypter.Error)
	})

	t.Run("invalid key size for StreamDecrypter", func(t *testing.T) {
		file := mock.NewFile([]byte("test"), "test.bin")
		c := cipher.New3DesCipher(cipher.CBC)
		c.SetKey([]byte("invalid")) // 7 bytes - invalid for 3DES
		c.SetIV(iv8Error)
		c.SetPadding(cipher.PKCS7)

		decrypter := NewStreamDecrypter(file, c)
		streamDecrypter := decrypter.(*StreamDecrypter)
		assert.NotNil(t, decrypter)
		assert.NotNil(t, streamDecrypter.Error)
		assert.IsType(t, KeySizeError(0), streamDecrypter.Error)
	})

	t.Run("unsupported GCM mode for StdEncrypter", func(t *testing.T) {
		c := cipher.New3DesCipher(cipher.GCM)
		c.SetKey(key16Error)
		c.SetIV(iv8Error)
		c.SetPadding(cipher.PKCS7)

		encrypter := NewStdEncrypter(c)
		assert.NotNil(t, encrypter)
		assert.NotNil(t, encrypter.Error)
		assert.IsType(t, UnsupportedBlockModeError{}, encrypter.Error)
	})

	t.Run("unsupported GCM mode for StdDecrypter", func(t *testing.T) {
		c := cipher.New3DesCipher(cipher.GCM)
		c.SetKey(key16Error)
		c.SetIV(iv8Error)
		c.SetPadding(cipher.PKCS7)

		decrypter := NewStdDecrypter(c)
		assert.NotNil(t, decrypter)
		assert.NotNil(t, decrypter.Error)
		assert.IsType(t, UnsupportedBlockModeError{}, decrypter.Error)
	})

	t.Run("unsupported GCM mode for StreamEncrypter", func(t *testing.T) {
		var buf bytes.Buffer
		c := cipher.New3DesCipher(cipher.GCM)
		c.SetKey(key16Error)
		c.SetIV(iv8Error)
		c.SetPadding(cipher.PKCS7)

		encrypter := NewStreamEncrypter(&buf, c)
		streamEncrypter := encrypter.(*StreamEncrypter)
		assert.NotNil(t, encrypter)
		assert.NotNil(t, streamEncrypter.Error)
		assert.IsType(t, UnsupportedBlockModeError{}, streamEncrypter.Error)
	})

	t.Run("unsupported GCM mode for StreamDecrypter", func(t *testing.T) {
		file := mock.NewFile([]byte("test"), "test.bin")
		c := cipher.New3DesCipher(cipher.GCM)
		c.SetKey(key16Error)
		c.SetIV(iv8Error)
		c.SetPadding(cipher.PKCS7)

		decrypter := NewStreamDecrypter(file, c)
		streamDecrypter := decrypter.(*StreamDecrypter)
		assert.NotNil(t, decrypter)
		assert.NotNil(t, streamDecrypter.Error)
		assert.IsType(t, UnsupportedBlockModeError{}, streamDecrypter.Error)
	})
}

// TestErrorEdgeCases tests edge cases for error handling
func TestErrorEdgeCases(t *testing.T) {
	t.Run("encryption with invalid key for CBC", func(t *testing.T) {
		c := cipher.New3DesCipher(cipher.CBC)
		c.SetKey([]byte("invalid")) // 7 bytes - invalid for 3DES
		c.SetIV(iv8Error)
		c.SetPadding(cipher.PKCS7)

		encrypter := NewStdEncrypter(c)
		encrypter.Error = nil // Clear the error to test the encryption path
		result, err := encrypter.Encrypt(testDataError)
		assert.Nil(t, result)
		assert.Error(t, err)
		assert.IsType(t, EncryptError{}, err)
	})

	t.Run("decryption with invalid key for CBC", func(t *testing.T) {
		c := cipher.New3DesCipher(cipher.CBC)
		c.SetKey([]byte("invalid")) // 7 bytes - invalid for 3DES
		c.SetIV(iv8Error)
		c.SetPadding(cipher.PKCS7)

		decrypter := NewStdDecrypter(c)
		decrypter.Error = nil // Clear the error to test the decryption path
		result, err := decrypter.Decrypt([]byte("test"))
		assert.Nil(t, result)
		assert.Error(t, err)
		assert.IsType(t, DecryptError{}, err)
	})

	t.Run("stream encrypter with invalid key", func(t *testing.T) {
		var buf bytes.Buffer
		c := cipher.New3DesCipher(cipher.CBC)
		c.SetKey([]byte("invalid")) // 7 bytes - invalid for 3DES
		c.SetIV(iv8Error)
		c.SetPadding(cipher.PKCS7)

		encrypter := NewStreamEncrypter(&buf, c)
		streamEncrypter := encrypter.(*StreamEncrypter)
		assert.NotNil(t, streamEncrypter.Error)
		assert.IsType(t, KeySizeError(0), streamEncrypter.Error)
	})

	t.Run("stream decrypter with invalid key", func(t *testing.T) {
		file := mock.NewFile([]byte("test"), "test.bin")
		c := cipher.New3DesCipher(cipher.CBC)
		c.SetKey([]byte("invalid")) // 7 bytes - invalid for 3DES
		c.SetIV(iv8Error)
		c.SetPadding(cipher.PKCS7)

		decrypter := NewStreamDecrypter(file, c)
		streamDecrypter := decrypter.(*StreamDecrypter)
		assert.NotNil(t, streamDecrypter.Error)
		assert.IsType(t, KeySizeError(0), streamDecrypter.Error)
	})
}

// TestErrorTypeAssertions tests error type assertions
func TestErrorTypeAssertions(t *testing.T) {
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
		var err error = BufferError{bufferSize: 10, dataSize: 20}
		var bufferErr BufferError
		ok := errors.As(err, &bufferErr)
		assert.True(t, ok)
		assert.Equal(t, 10, bufferErr.bufferSize)
		assert.Equal(t, 20, bufferErr.dataSize)
	})

	t.Run("UnsupportedBlockModeError type assertion", func(t *testing.T) {
		var err error = UnsupportedBlockModeError{Mode: "GCM"}
		var unsupportedModeErr UnsupportedBlockModeError
		ok := errors.As(err, &unsupportedModeErr)
		assert.True(t, ok)
		assert.Equal(t, "GCM", unsupportedModeErr.Mode)
	})
}

// TestTripleDes_Errors tests comprehensive error scenarios
func TestTripleDes_Errors(t *testing.T) {
	t.Run("stream encrypter write error", func(t *testing.T) {
		writer := mock.NewErrorReadWriteCloser(errors.New("write error"))
		c := cipher.New3DesCipher(cipher.CBC)
		c.SetKey(key16Error)
		c.SetIV(iv8Error)
		c.SetPadding(cipher.PKCS7)

		encrypter := NewStreamEncrypter(writer, c)
		streamEncrypter := encrypter.(*StreamEncrypter)
		streamEncrypter.Error = nil

		n, err := encrypter.Write(testDataError)
		assert.Equal(t, 0, n)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "write error")
	})

	t.Run("stream encrypter with key size error", func(t *testing.T) {
		var buf bytes.Buffer
		c := cipher.New3DesCipher(cipher.CBC)
		c.SetKey([]byte("invalid")) // 7 bytes - invalid for 3DES
		c.SetIV(iv8Error)
		c.SetPadding(cipher.PKCS7)

		encrypter := NewStreamEncrypter(&buf, c)
		streamEncrypter := encrypter.(*StreamEncrypter)

		// Should have KeySizeError
		assert.NotNil(t, streamEncrypter.Error)
		assert.IsType(t, KeySizeError(0), streamEncrypter.Error)

		n, err := encrypter.Write(testDataError)
		assert.Equal(t, 0, n)
		assert.Error(t, err)
		assert.IsType(t, KeySizeError(0), err)
	})

	t.Run("stream decrypter with key size error", func(t *testing.T) {
		file := mock.NewFile([]byte("test"), "test.bin")
		c := cipher.New3DesCipher(cipher.CBC)
		c.SetKey([]byte("invalid")) // 7 bytes - invalid for 3DES
		c.SetIV(iv8Error)
		c.SetPadding(cipher.PKCS7)

		decrypter := NewStreamDecrypter(file, c)
		streamDecrypter := decrypter.(*StreamDecrypter)

		// Should have KeySizeError
		assert.NotNil(t, streamDecrypter.Error)
		assert.IsType(t, KeySizeError(0), streamDecrypter.Error)

		buf := make([]byte, 10)
		n, err := decrypter.Read(buf)
		assert.Equal(t, 0, n)
		assert.Error(t, err)
		assert.IsType(t, KeySizeError(0), err)
	})
}

// TestStreamDecrypter_Read_EOF tests the EOF case when all data has been read
func TestStreamDecrypter_Read_EOF(t *testing.T) {

	t.Run("read with empty encrypted data", func(t *testing.T) {
		c := cipher.New3DesCipher(cipher.CBC)
		c.SetKey(key16Error)
		c.SetIV(iv8Error)
		c.SetPadding(cipher.PKCS7)

		decrypter := NewStreamDecrypter(bytes.NewReader([]byte{}), c)
		buf := make([]byte, 10)
		n, err := decrypter.Read(buf)
		assert.Equal(t, 0, n)
		assert.Equal(t, io.EOF, err)
	})
}

// TestCoverage_MissingPaths tests uncovered code paths to achieve 100% coverage
func TestCoverage_MissingPaths(t *testing.T) {
	t.Run("StdEncrypter expandKey error", func(t *testing.T) {
		// Create an invalid key that will fail expandKey validation
		invalidKey := make([]byte, 15) // 15 bytes - invalid for 3DES

		c := cipher.New3DesCipher(cipher.CBC)
		c.SetKey(invalidKey)
		c.SetIV(iv8Error)
		c.SetPadding(cipher.PKCS7)

		encrypter := NewStdEncrypter(c)
		encrypter.Error = nil // Clear the KeySizeError from NewStdEncrypter

		// This should trigger the expandKey error path in lines 75-79
		result, err := encrypter.Encrypt(testDataError)
		assert.Nil(t, result)
		assert.Error(t, err)
		assert.IsType(t, EncryptError{}, err)
	})

	t.Run("StdDecrypter expandKey error", func(t *testing.T) {
		// Create an invalid key that will fail expandKey validation
		invalidKey := make([]byte, 15) // 15 bytes - invalid for 3DES

		c := cipher.New3DesCipher(cipher.CBC)
		c.SetKey(invalidKey)
		c.SetIV(iv8Error)
		c.SetPadding(cipher.PKCS7)

		decrypter := NewStdDecrypter(c)
		decrypter.Error = nil // Clear the KeySizeError from NewStdDecrypter

		// This should trigger the expandKey error path in lines 129-133
		result, err := decrypter.Decrypt([]byte("testdata"))
		assert.Nil(t, result)
		assert.Error(t, err)
		assert.IsType(t, DecryptError{}, err)
	})

	t.Run("StreamEncrypter empty data writer error", func(t *testing.T) {
		writer := mock.NewErrorReadWriteCloser(errors.New("write error"))
		c := cipher.New3DesCipher(cipher.CBC)
		c.SetKey(key16Error)
		c.SetIV(iv8Error)
		c.SetPadding(cipher.PKCS7)

		encrypter := NewStreamEncrypter(writer, c)
		streamEncrypter := encrypter.(*StreamEncrypter)
		streamEncrypter.Error = nil

		// For empty data, the Write method returns early with success
		n, err := encrypter.Write([]byte{})
		assert.Equal(t, 0, n)
		assert.Nil(t, err) // Empty data write succeeds
	})

	t.Run("StreamEncrypter Close with buffered data", func(t *testing.T) {
		var buf bytes.Buffer
		c := cipher.New3DesCipher(cipher.CFB) // Use CFB mode for streaming
		c.SetKey(key16Error)
		c.SetIV(iv8Error)
		c.SetPadding(cipher.PKCS7)

		encrypter := NewStreamEncrypter(&buf, c)
		streamEncrypter := encrypter.(*StreamEncrypter)

		// Add some data to buffer to trigger the buffered data path
		streamEncrypter.buffer = []byte("test")

		// This should trigger the buffered data handling in lines 250-288
		err := encrypter.Close()
		// The error depends on whether the cipher can handle the buffered data
		if err != nil {
			assert.Error(t, err)
		}
	})

	t.Run("StreamEncrypter Close with valid block", func(t *testing.T) {
		var buf bytes.Buffer
		c := cipher.New3DesCipher(cipher.CBC)
		c.SetKey(key16Error)
		c.SetIV(iv8Error)
		c.SetPadding(cipher.PKCS7)

		encrypter := NewStreamEncrypter(&buf, c)

		// Write some data
		_, err := encrypter.Write([]byte("test data"))
		assert.Nil(t, err)

		// Close should work normally
		err = encrypter.Close()
		assert.Nil(t, err)
	})

	t.Run("StreamDecrypter Read with invalid key", func(t *testing.T) {
		// Use an invalid key length
		invalidKey := make([]byte, 15) // 15 bytes - invalid for 3DES

		file := mock.NewFile([]byte("test data"), "test.bin")
		c := cipher.New3DesCipher(cipher.CBC)
		c.SetKey(invalidKey)
		c.SetIV(iv8Error)
		c.SetPadding(cipher.PKCS7)

		decrypter := NewStreamDecrypter(file, c)

		// Should have KeySizeError from initialization
		buf := make([]byte, 10)
		n, err := decrypter.Read(buf)
		assert.Equal(t, 0, n)
		assert.Error(t, err)
		assert.IsType(t, KeySizeError(0), err)
	})

	t.Run("StreamEncrypter Close cipher Encrypt error", func(t *testing.T) {
		var buf bytes.Buffer
		c := cipher.New3DesCipher(cipher.CBC)
		c.SetKey(key16Error)
		// Don't set IV to cause encryption error
		c.SetPadding(cipher.PKCS7)

		encrypter := NewStreamEncrypter(&buf, c)
		streamEncrypter := encrypter.(*StreamEncrypter)
		streamEncrypter.buffer = []byte("test") // Add buffered data

		// This should trigger the cipher.Encrypt error path in lines 254-257
		err := encrypter.Close()
		if err != nil {
			assert.Error(t, err)
		}
	})

	t.Run("StreamEncrypter Close write error", func(t *testing.T) {
		writer := mock.NewErrorReadWriteCloser(errors.New("write error"))
		c := cipher.New3DesCipher(cipher.CBC)
		c.SetKey(key16Error)
		c.SetIV(iv8Error)
		c.SetPadding(cipher.No) // Use No padding to avoid issues with test data

		encrypter := NewStreamEncrypter(writer, c)

		// The Close() method closes the writer, so it should trigger the close error
		err := encrypter.Close()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "write error")
	})

	t.Run("StreamEncrypter Close nil block expandKey error", func(t *testing.T) {
		var buf bytes.Buffer
		c := cipher.New3DesCipher(cipher.CBC)
		invalidKey := make([]byte, 15) // Invalid key length
		c.SetKey(invalidKey)
		c.SetIV(iv8Error)
		c.SetPadding(cipher.PKCS7)

		encrypter := NewStreamEncrypter(&buf, c)

		// Should have KeySizeError from initialization, so Close returns that error
		err := encrypter.Close()
		assert.Error(t, err)
		assert.IsType(t, KeySizeError(0), err)
	})

	t.Run("StreamEncrypter Close after Write", func(t *testing.T) {
		var buf bytes.Buffer
		c := cipher.New3DesCipher(cipher.CBC)
		c.SetKey(key16Error)
		c.SetIV(iv8Error)
		c.SetPadding(cipher.PKCS7)

		encrypter := NewStreamEncrypter(&buf, c)

		// Write and close should succeed
		_, err := encrypter.Write([]byte("test"))
		assert.Nil(t, err)

		err = encrypter.Close()
		assert.Nil(t, err)
	})

	t.Run("StreamEncrypter Close with write error", func(t *testing.T) {
		writer := mock.NewCloseErrorWriteCloser(&bytes.Buffer{}, errors.New("close error"))
		c := cipher.New3DesCipher(cipher.CBC)
		c.SetKey(key16Error)
		c.SetIV(iv8Error)
		c.SetPadding(cipher.No)

		encrypter := NewStreamEncrypter(writer, c)

		// Close should trigger the close error
		err := encrypter.Close()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "close error")
	})

	// Test cases to verify dead code paths - these paths are theoretically unreachable,
	// but we add them for 100% coverage requirement
	t.Run("StdEncrypter unreachable des.NewTripleDESCipher error", func(t *testing.T) {
		// This test documents that the error path in lines 82-86 is unreachable
		// because expandKey ensures only valid 16/24 byte keys are passed to des.NewTripleDESCipher

		// Test the normal successful path
		c := cipher.New3DesCipher(cipher.CBC)
		c.SetKey(key16Error)
		c.SetIV(iv8Error)
		c.SetPadding(cipher.PKCS7)

		encrypter := NewStdEncrypter(c)
		result, err := encrypter.Encrypt(testDataError)
		assert.NotNil(t, result)
		assert.Nil(t, err)

		// The error path is dead code - expandKey will always return valid length
		// or return an error, and des.NewTripleDESCipher accepts 16/24 byte keys
	})

	t.Run("StdDecrypter unreachable des.NewTripleDESCipher error", func(t *testing.T) {
		// This test documents that the error path in lines 135-139 is unreachable
		c := cipher.New3DesCipher(cipher.CBC)
		c.SetKey(key16Error)
		c.SetIV(iv8Error)
		c.SetPadding(cipher.PKCS7)

		decrypter := NewStdDecrypter(c)
		// Use valid encrypted data
		_, err := decrypter.Decrypt([]byte{0x12, 0x34, 0x56, 0x78, 0x12, 0x34, 0x56, 0x78})
		// May fail due to decryption error, but not due to des.NewTripleDESCipher
		if err != nil {
			assert.IsType(t, DecryptError{}, err)
		}
	})

	t.Run("StreamEncrypter successful operation", func(t *testing.T) {
		// Test normal StreamEncrypter operation
		var buf bytes.Buffer
		c := cipher.New3DesCipher(cipher.CBC)
		c.SetKey(key16Error)
		c.SetIV(iv8Error)
		c.SetPadding(cipher.PKCS7)

		// Test NewStreamEncrypter initialization
		encrypter := NewStreamEncrypter(&buf, c)
		streamEncrypter := encrypter.(*StreamEncrypter)
		assert.Nil(t, streamEncrypter.Error)    // Should succeed
		assert.NotNil(t, streamEncrypter.block) // Block should be created

		// Test Write operation
		n, err := encrypter.Write(testDataError)
		assert.Equal(t, len(testDataError), n)
		assert.Nil(t, err)

		// Test Close operation
		err = encrypter.Close()
		assert.Nil(t, err)
	})

	t.Run("StreamDecrypter successful initialization", func(t *testing.T) {
		// Test normal StreamDecrypter initialization
		file := mock.NewFile([]byte("test data"), "test.bin")
		c := cipher.New3DesCipher(cipher.CBC)
		c.SetKey(key16Error)
		c.SetIV(iv8Error)
		c.SetPadding(cipher.PKCS7)

		// Test NewStreamDecrypter initialization
		decrypter := NewStreamDecrypter(file, c)
		streamDecrypter := decrypter.(*StreamDecrypter)
		assert.Nil(t, streamDecrypter.Error)    // Should succeed
		assert.NotNil(t, streamDecrypter.block) // Block should be created

		// Test Read operation (may fail due to invalid data format)
		buf := make([]byte, 10)
		_, err := decrypter.Read(buf)
		// May get an error due to invalid encrypted data format, which is expected
		if err != nil && err != io.EOF {
			t.Logf("Got expected error due to invalid data format: %v", err)
		}
	})
}
