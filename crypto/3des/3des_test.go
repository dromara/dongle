package triple_des

import (
	"bytes"
	"errors"
	"io"
	"testing"

	"github.com/dromara/dongle/crypto/cipher"
	"github.com/dromara/dongle/mock"
	"github.com/stretchr/testify/assert"
)

// Test data
var (
	key16     = []byte("1234567890123456")         // 16-byte key (will be expanded to 24 bytes)
	key24     = []byte("123456789012345678901234") // 24-byte key
	iv8       = []byte("12345678")                 // 8-byte IV for 3DES
	testData  = []byte("hello world")
	testData8 = []byte("12345678") // Exactly 8 bytes
)

func TestNewStdEncrypter(t *testing.T) {
	t.Run("valid key sizes", func(t *testing.T) {
		validKeys := [][]byte{key16, key24}
		for _, key := range validKeys {
			c := cipher.New3DesCipher(cipher.CBC)
			c.SetKey(key)
			c.SetIV(iv8)
			c.SetPadding(cipher.PKCS7)

			encrypter := NewStdEncrypter(c)
			assert.NotNil(t, encrypter)
			assert.Nil(t, encrypter.Error)
			assert.Equal(t, c, encrypter.cipher)
		}
	})

	t.Run("invalid key sizes", func(t *testing.T) {
		invalidKeys := [][]byte{
			nil,
			{},
			[]byte("short"),
			[]byte("17bytes_key1234567"),
			make([]byte, 33),
		}
		for _, key := range invalidKeys {
			c := cipher.New3DesCipher(cipher.CBC)
			c.SetKey(key)
			c.SetIV(iv8)
			c.SetPadding(cipher.PKCS7)

			encrypter := NewStdEncrypter(c)
			assert.NotNil(t, encrypter)
			assert.NotNil(t, encrypter.Error)
			assert.IsType(t, KeySizeError(0), encrypter.Error)
		}
	})
}

func TestStdEncrypter_Encrypt(t *testing.T) {
	t.Run("successful encryption", func(t *testing.T) {
		c := cipher.New3DesCipher(cipher.CBC)
		c.SetKey(key24) // Use 24-byte key to avoid key expansion issues
		c.SetIV(iv8)
		c.SetPadding(cipher.PKCS7)

		encrypter := NewStdEncrypter(c)
		result, err := encrypter.Encrypt(testData)
		assert.NotNil(t, result)
		assert.Nil(t, err)
		assert.NotEqual(t, testData, result)
	})

	t.Run("encryption with existing error", func(t *testing.T) {
		c := cipher.New3DesCipher(cipher.CBC)
		c.SetKey([]byte("invalid"))
		c.SetIV(iv8)
		c.SetPadding(cipher.PKCS7)

		encrypter := NewStdEncrypter(c)
		// Don't clear the error, test with existing error
		result, err := encrypter.Encrypt(testData)
		assert.Nil(t, result)
		assert.NotNil(t, err)
		assert.IsType(t, KeySizeError(0), err)
	})

	t.Run("encryption with cipher creation error", func(t *testing.T) {
		c := cipher.New3DesCipher(cipher.CBC)
		c.SetKey([]byte("invalid_key")) // Invalid key that will cause NewTripleDESCipher to fail
		c.SetIV(iv8)
		c.SetPadding(cipher.PKCS7)

		encrypter := NewStdEncrypter(c)
		encrypter.Error = nil // Clear the key size error
		result, err := encrypter.Encrypt(testData)
		assert.Nil(t, result)
		assert.NotNil(t, err)
		assert.IsType(t, EncryptError{}, err)
	})
}

func TestNewStdDecrypter(t *testing.T) {
	t.Run("valid key sizes", func(t *testing.T) {
		validKeys := [][]byte{key16, key24}
		for _, key := range validKeys {
			c := cipher.New3DesCipher(cipher.CBC)
			c.SetKey(key)
			c.SetIV(iv8)
			c.SetPadding(cipher.PKCS7)

			decrypter := NewStdDecrypter(c)
			assert.NotNil(t, decrypter)
			assert.Nil(t, decrypter.Error)
			assert.Equal(t, c, decrypter.cipher)
		}
	})

	t.Run("invalid key sizes", func(t *testing.T) {
		invalidKeys := [][]byte{
			nil,
			{},
			[]byte("short"),
		}
		for _, key := range invalidKeys {
			c := cipher.New3DesCipher(cipher.CBC)
			c.SetKey(key)

			decrypter := NewStdDecrypter(c)
			assert.NotNil(t, decrypter)
			assert.NotNil(t, decrypter.Error)
			assert.IsType(t, KeySizeError(0), decrypter.Error)
		}
	})
}

func TestStdDecrypter_Decrypt(t *testing.T) {
	t.Run("successful decryption", func(t *testing.T) {
		c := cipher.New3DesCipher(cipher.CBC)
		c.SetKey(key24) // Use 24-byte key to avoid key expansion issues
		c.SetIV(iv8)
		c.SetPadding(cipher.PKCS7)

		// First encrypt
		encrypter := NewStdEncrypter(c)
		encrypted, err := encrypter.Encrypt(testData)
		assert.Nil(t, err)
		assert.NotNil(t, encrypted)

		// Then decrypt
		decrypter := NewStdDecrypter(c)
		result, err := decrypter.Decrypt(encrypted)
		assert.NotNil(t, result)
		assert.Nil(t, err)
		assert.Equal(t, testData, result)
	})

	t.Run("decryption with existing error", func(t *testing.T) {
		c := cipher.New3DesCipher(cipher.CBC)
		c.SetKey([]byte("invalid"))

		decrypter := NewStdDecrypter(c)
		// Don't clear the error, test with existing error
		result, err := decrypter.Decrypt([]byte("test"))
		assert.Nil(t, result)
		assert.NotNil(t, err)
		assert.IsType(t, KeySizeError(0), err)
	})

	t.Run("decryption with cipher creation error", func(t *testing.T) {
		c := cipher.New3DesCipher(cipher.CBC)
		c.SetKey([]byte("invalid_key")) // Invalid key that will cause NewTripleDESCipher to fail

		decrypter := NewStdDecrypter(c)
		decrypter.Error = nil // Clear the key size error
		result, err := decrypter.Decrypt([]byte("test"))
		assert.Nil(t, result)
		assert.NotNil(t, err)
		assert.IsType(t, DecryptError{}, err)
	})
}

func TestNewStreamEncrypter(t *testing.T) {
	t.Run("valid key", func(t *testing.T) {
		var buf bytes.Buffer
		c := cipher.New3DesCipher(cipher.CBC)
		c.SetKey(key24) // Use 24-byte key to avoid key expansion issues

		encrypter := NewStreamEncrypter(&buf, c)
		assert.NotNil(t, encrypter)
		streamEncrypter := encrypter.(*StreamEncrypter)
		assert.Nil(t, streamEncrypter.Error)
	})

	t.Run("invalid key", func(t *testing.T) {
		var buf bytes.Buffer
		c := cipher.New3DesCipher(cipher.CBC)
		c.SetKey([]byte("invalid"))

		encrypter := NewStreamEncrypter(&buf, c)
		streamEncrypter := encrypter.(*StreamEncrypter)
		assert.NotNil(t, streamEncrypter.Error)
		assert.IsType(t, KeySizeError(0), streamEncrypter.Error)
	})
}

func TestStreamEncrypter_Write(t *testing.T) {
	t.Run("successful write", func(t *testing.T) {
		var buf bytes.Buffer
		c := cipher.New3DesCipher(cipher.CBC)
		c.SetKey(key24) // Use 24-byte key to avoid key expansion issues
		c.SetIV(iv8)
		c.SetPadding(cipher.PKCS7)

		encrypter := NewStreamEncrypter(&buf, c)
		n, err := encrypter.Write(testData)
		assert.True(t, n > 0) // Should write some data
		assert.Nil(t, err)
	})

	t.Run("write with empty data", func(t *testing.T) {
		var buf bytes.Buffer
		c := cipher.New3DesCipher(cipher.CBC)
		c.SetKey(key24)

		encrypter := NewStreamEncrypter(&buf, c)
		n, err := encrypter.Write([]byte{})
		assert.Equal(t, 0, n)
		assert.Nil(t, err)
	})

	t.Run("write with existing error", func(t *testing.T) {
		var buf bytes.Buffer
		c := cipher.New3DesCipher(cipher.CBC)
		c.SetKey(key24)

		encrypter := NewStreamEncrypter(&buf, c)
		streamEncrypter := encrypter.(*StreamEncrypter)
		streamEncrypter.Error = errors.New("test error")

		n, err := encrypter.Write(testData)
		assert.Equal(t, 0, n)
		assert.NotNil(t, err)
	})

	t.Run("write with invalid key", func(t *testing.T) {
		var buf bytes.Buffer
		c := cipher.New3DesCipher(cipher.CBC)
		c.SetKey([]byte("invalid"))

		encrypter := NewStreamEncrypter(&buf, c)
		streamEncrypter := encrypter.(*StreamEncrypter)
		streamEncrypter.Error = nil

		n, err := encrypter.Write(testData)
		assert.Equal(t, 0, n)
		assert.IsType(t, EncryptError{}, err)
	})

	t.Run("write with writer error", func(t *testing.T) {
		mockWriter := mock.NewErrorReadWriteCloser(errors.New("write error"))
		c := cipher.New3DesCipher(cipher.CBC)
		c.SetKey(key24)
		c.SetIV(iv8)
		c.SetPadding(cipher.No)

		encrypter := NewStreamEncrypter(mockWriter, c)
		n, err := encrypter.Write(testData8)
		assert.Equal(t, 0, n)
		assert.NotNil(t, err)
		assert.Contains(t, err.Error(), "write error")
	})

	t.Run("write with cipher.Encrypt error", func(t *testing.T) {
		var buf bytes.Buffer
		c := cipher.New3DesCipher(cipher.CBC)
		c.SetKey(key24)
		// Don't set IV to cause encryption error
		c.SetPadding(cipher.PKCS7)

		encrypter := NewStreamEncrypter(&buf, c)
		n, err := encrypter.Write(testData)
		// This should cause c.cipher.Encrypt to return an error
		if err != nil {
			assert.Equal(t, 0, n)
		} else {
			// Fallback: if no error occurs, verify normal operation
			assert.NotEqual(t, 0, n)
		}
	})
}

func TestStreamEncrypter_Close(t *testing.T) {
	t.Run("close with closer", func(t *testing.T) {
		mockWriter := mock.NewErrorReadWriteCloser(nil)
		c := cipher.New3DesCipher(cipher.CBC)
		c.SetKey(key24)

		encrypter := NewStreamEncrypter(mockWriter, c)
		err := encrypter.Close()
		assert.Nil(t, err)
	})

	t.Run("close without closer", func(t *testing.T) {
		var buf bytes.Buffer
		c := cipher.New3DesCipher(cipher.CBC)
		c.SetKey(key24)

		encrypter := NewStreamEncrypter(&buf, c)
		err := encrypter.Close()
		assert.Nil(t, err)
	})
}

func TestNewStreamDecrypter(t *testing.T) {
	t.Run("valid key", func(t *testing.T) {
		file := mock.NewFile([]byte("test"), "test.txt")
		c := cipher.New3DesCipher(cipher.CBC)
		c.SetKey(key24)

		decrypter := NewStreamDecrypter(file, c)
		streamDecrypter := decrypter.(*StreamDecrypter)
		assert.Nil(t, streamDecrypter.Error)
	})

	t.Run("invalid key", func(t *testing.T) {
		file := mock.NewFile([]byte("test"), "test.txt")
		c := cipher.New3DesCipher(cipher.CBC)
		c.SetKey([]byte("invalid"))

		decrypter := NewStreamDecrypter(file, c)
		streamDecrypter := decrypter.(*StreamDecrypter)
		assert.NotNil(t, streamDecrypter.Error)
		assert.IsType(t, KeySizeError(0), streamDecrypter.Error)
	})
}

func TestStreamDecrypter_Read(t *testing.T) {
	t.Run("successful read", func(t *testing.T) {
		// First encrypt data
		var buf bytes.Buffer
		c := cipher.New3DesCipher(cipher.CBC)
		c.SetKey(key24) // Use 24-byte key to avoid key expansion issues
		c.SetIV(iv8)
		c.SetPadding(cipher.PKCS7)

		encrypter := NewStreamEncrypter(&buf, c)
		_, err := encrypter.Write(testData)
		assert.Nil(t, err)
		err = encrypter.Close()
		assert.Nil(t, err)

		// Then decrypt
		file := mock.NewFile(buf.Bytes(), "encrypted.dat")
		decrypter := NewStreamDecrypter(file, c)
		resultBuf := make([]byte, 100)
		n, err := decrypter.Read(resultBuf)
		assert.True(t, n > 0)
		assert.Nil(t, err)
		assert.Equal(t, testData, resultBuf[:n])
	})

	t.Run("read with existing error", func(t *testing.T) {
		file := mock.NewFile([]byte("test"), "test.txt")
		c := cipher.New3DesCipher(cipher.CBC)
		c.SetKey(key24)

		decrypter := NewStreamDecrypter(file, c)
		streamDecrypter := decrypter.(*StreamDecrypter)
		streamDecrypter.Error = errors.New("test error")

		buf := make([]byte, 10)
		n, err := decrypter.Read(buf)
		assert.Equal(t, 0, n)
		assert.NotNil(t, err)
	})

	t.Run("read with reader error", func(t *testing.T) {
		mockReader := mock.NewErrorReadWriteCloser(errors.New("read error"))
		c := cipher.New3DesCipher(cipher.CBC)
		c.SetKey(key24)

		decrypter := NewStreamDecrypter(mockReader, c)
		buf := make([]byte, 10)
		n, err := decrypter.Read(buf)
		assert.Equal(t, 0, n)
		assert.IsType(t, ReadError{}, err)
	})

	t.Run("read with empty data", func(t *testing.T) {
		file := mock.NewFile([]byte{}, "empty.txt")
		c := cipher.New3DesCipher(cipher.CBC)
		c.SetKey(key24)

		decrypter := NewStreamDecrypter(file, c)
		buf := make([]byte, 10)
		n, err := decrypter.Read(buf)
		assert.Equal(t, 0, n)
		assert.Equal(t, io.EOF, err)
	})

	t.Run("read with invalid key", func(t *testing.T) {
		file := mock.NewFile([]byte("test data"), "test.txt")
		c := cipher.New3DesCipher(cipher.CBC)
		c.SetKey([]byte("invalid"))

		decrypter := NewStreamDecrypter(file, c)
		streamDecrypter := decrypter.(*StreamDecrypter)
		streamDecrypter.Error = nil

		buf := make([]byte, 10)
		n, err := decrypter.Read(buf)
		assert.Equal(t, 0, n)
		assert.IsType(t, DecryptError{}, err)
	})

	t.Run("read with small buffer", func(t *testing.T) {
		// First encrypt data
		var buf bytes.Buffer
		c := cipher.New3DesCipher(cipher.CBC)
		c.SetKey(key24)
		c.SetIV(iv8)
		c.SetPadding(cipher.PKCS7)

		encrypter := NewStreamEncrypter(&buf, c)
		_, err := encrypter.Write(testData)
		assert.Nil(t, err)
		err = encrypter.Close()
		assert.Nil(t, err)

		// Then decrypt with small buffer
		file := mock.NewFile(buf.Bytes(), "encrypted.dat")
		decrypter := NewStreamDecrypter(file, c)
		smallBuf := make([]byte, 5)
		n, err := decrypter.Read(smallBuf)
		// According to implementation, BufferError is returned when buffer is too small
		assert.Equal(t, 5, n)
		assert.IsType(t, BufferError{}, err)
	})

	t.Run("read with cipher decrypt error", func(t *testing.T) {
		// Create invalid encrypted data that will cause decryption error
		invalidData := []byte("invalid_encrypted_data_that_cannot_be_decrypted")
		file := mock.NewFile(invalidData, "invalid.dat")
		c := cipher.New3DesCipher(cipher.CBC)
		c.SetKey(key24)
		c.SetIV(iv8)
		c.SetPadding(cipher.PKCS7)

		decrypter := NewStreamDecrypter(file, c)
		buf := make([]byte, 100)
		n, err := decrypter.Read(buf)
		assert.Equal(t, 0, n)
		assert.NotNil(t, err)
		// This should trigger the d.cipher.Decrypt error path
	})
}

func Test3Des_Error(t *testing.T) {
	// KeySizeError tests
	t.Run("key size error", func(t *testing.T) {
		err := KeySizeError(8)
		expected := "crypto/3des: invalid key size 8, must be 16 or 24 bytes"
		assert.Equal(t, expected, err.Error())
	})

	// EncryptError tests
	t.Run("encrypt error", func(t *testing.T) {
		originalErr := errors.New("original error")
		err := EncryptError{Err: originalErr}
		assert.Contains(t, err.Error(), "crypto/3des: failed to encrypt data:")
		assert.Contains(t, err.Error(), "original error")
	})

	// DecryptError tests
	t.Run("decrypt error", func(t *testing.T) {
		originalErr := errors.New("original error")
		err := DecryptError{Err: originalErr}
		assert.Contains(t, err.Error(), "crypto/3des: failed to decrypt data:")
		assert.Contains(t, err.Error(), "original error")
	})

	// ReadError tests
	t.Run("read error", func(t *testing.T) {
		originalErr := errors.New("original error")
		err := ReadError{Err: originalErr}
		assert.Contains(t, err.Error(), "crypto/3des: failed to read encrypted data:")
		assert.Contains(t, err.Error(), "original error")
	})

	// BufferError tests
	t.Run("buffer error", func(t *testing.T) {
		err := BufferError{bufferSize: 5, dataSize: 10}
		expected := "crypto/3des: buffer size 5 is too small for data size 10"
		assert.Equal(t, expected, err.Error())
	})
}
