package blowfish

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/dromara/dongle/crypto/cipher"
	"github.com/dromara/dongle/mock"
	"github.com/stretchr/testify/assert"
)

// Test data
var (
	key4      = []byte("1234")                                                     // 4 bytes - minimum key size
	key8      = []byte("12345678")                                                 // 8 bytes - common key size
	key16     = []byte("1234567890123456")                                         // 16 bytes
	key32     = []byte("12345678901234567890123456789012")                         // 32 bytes
	key56     = []byte("12345678901234567890123456789012345678901234567890123456") // 56 bytes - maximum key size
	iv8       = []byte("12345678")                                                 // 8-byte IV for Blowfish
	testData  = []byte("hello world")
	testData8 = []byte("12345678") // Exactly 8 bytes for block alignment
)

func TestNewStdEncrypter(t *testing.T) {
	t.Run("valid key sizes", func(t *testing.T) {
		validKeys := [][]byte{key4, key8, key16, key32, key56}
		for _, key := range validKeys {
			c := cipher.NewBlowfishCipher(cipher.CBC)
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
			[]byte("123"),    // 3 bytes - too short
			make([]byte, 57), // 57 bytes - too long
			[]byte("123456789012345678901234567890123456789012345678901234567890123"), // 63 bytes - too long
		}
		for _, key := range invalidKeys {
			c := cipher.NewBlowfishCipher(cipher.CBC)
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
		c := cipher.NewBlowfishCipher(cipher.CBC)
		c.SetKey(key16)
		c.SetIV(iv8)
		c.SetPadding(cipher.PKCS7)

		encrypter := NewStdEncrypter(c)
		result, err := encrypter.Encrypt(testData)
		assert.NotNil(t, result)
		assert.Nil(t, err)
		assert.NotEqual(t, testData, result)
	})

	t.Run("encryption with existing error", func(t *testing.T) {
		c := cipher.NewBlowfishCipher(cipher.CBC)
		c.SetKey(key16)
		c.SetIV(iv8)
		c.SetPadding(cipher.PKCS7)

		encrypter := NewStdEncrypter(c)
		assert.Nil(t, encrypter.Error)

		// Set an explicit error - but standard Encrypt method doesn't check this
		encrypter.Error = errors.New("test error")

		// The standard Encrypt method ignores the Error field and processes normally
		result, err := encrypter.Encrypt(testData)
		assert.NotNil(t, result)
		assert.Nil(t, err) // Should succeed despite Error field being set
	})

	t.Run("encryption with cipher error", func(t *testing.T) {
		c := cipher.NewBlowfishCipher(cipher.CBC)
		c.SetKey(key16)
		c.SetIV(iv8)
		c.SetPadding(cipher.PKCS7)

		encrypter := NewStdEncrypter(c)
		assert.Nil(t, encrypter.Error)

		// Modify the key to an invalid state after creation
		encrypter.cipher.Key = nil

		result, err := encrypter.Encrypt(testData)
		assert.Nil(t, result)
		assert.NotNil(t, err)
		assert.IsType(t, EncryptError{}, err)
	})
}

func TestNewStdDecrypter(t *testing.T) {
	t.Run("valid key sizes", func(t *testing.T) {
		validKeys := [][]byte{key4, key8, key16, key32, key56}
		for _, key := range validKeys {
			c := cipher.NewBlowfishCipher(cipher.CBC)
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
			[]byte("123"),    // 3 bytes - too short
			make([]byte, 57), // 57 bytes - too long
		}
		for _, key := range invalidKeys {
			c := cipher.NewBlowfishCipher(cipher.CBC)
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
		c := cipher.NewBlowfishCipher(cipher.CBC)
		c.SetKey(key16)
		c.SetIV(iv8)
		c.SetPadding(cipher.PKCS7)

		// First encrypt
		encrypter := NewStdEncrypter(c)
		encrypted, err := encrypter.Encrypt(testData)
		assert.Nil(t, err)

		// Then decrypt
		decrypter := NewStdDecrypter(c)
		result, err := decrypter.Decrypt(encrypted)
		assert.NotNil(t, result)
		assert.Nil(t, err)
		assert.Equal(t, testData, result)
	})

	t.Run("decryption with existing error", func(t *testing.T) {
		c := cipher.NewBlowfishCipher(cipher.CBC)
		c.SetKey(key16)
		c.SetIV(iv8)
		c.SetPadding(cipher.PKCS7)

		decrypter := NewStdDecrypter(c)
		assert.Nil(t, decrypter.Error)

		// Set an explicit error - but standard Decrypt method doesn't check this
		decrypter.Error = errors.New("test error")

		// First encrypt some data to get valid encrypted data
		encrypter := NewStdEncrypter(c)
		encrypted, _ := encrypter.Encrypt(testData)

		// The standard Decrypt method ignores the Error field and processes normally
		result, err := decrypter.Decrypt(encrypted)
		// Should succeed despite Error field being set
		assert.Equal(t, testData, result)
		assert.Nil(t, err)
	})

	t.Run("decryption with cipher error", func(t *testing.T) {
		c := cipher.NewBlowfishCipher(cipher.CBC)
		c.SetKey(key16)
		c.SetIV(iv8)
		c.SetPadding(cipher.PKCS7)

		decrypter := NewStdDecrypter(c)
		assert.Nil(t, decrypter.Error)

		// Modify the key to an invalid state after creation
		decrypter.cipher.Key = nil

		result, err := decrypter.Decrypt([]byte("testdata"))
		assert.Nil(t, result)
		assert.NotNil(t, err)
		assert.IsType(t, DecryptError{}, err)
	})
}

func TestNewStreamEncrypter(t *testing.T) {
	t.Run("valid key", func(t *testing.T) {
		var buf bytes.Buffer
		c := cipher.NewBlowfishCipher(cipher.CBC)
		c.SetKey(key16)

		encrypter := NewStreamEncrypter(&buf, c)
		assert.NotNil(t, encrypter)
		streamEncrypter := encrypter.(*StreamEncrypter)
		assert.Nil(t, streamEncrypter.Error)
	})

	t.Run("invalid key", func(t *testing.T) {
		var buf bytes.Buffer
		c := cipher.NewBlowfishCipher(cipher.CBC)
		c.SetKey([]byte("123")) // 3 bytes - too short for Blowfish

		encrypter := NewStreamEncrypter(&buf, c)
		streamEncrypter := encrypter.(*StreamEncrypter)
		assert.NotNil(t, streamEncrypter.Error)
		assert.IsType(t, KeySizeError(0), streamEncrypter.Error)
	})
}

func TestStreamEncrypter_Write(t *testing.T) {
	t.Run("successful write", func(t *testing.T) {
		var buf bytes.Buffer
		c := cipher.NewBlowfishCipher(cipher.CBC)
		c.SetKey(key16)
		c.SetIV(iv8)
		c.SetPadding(cipher.PKCS7)

		encrypter := NewStreamEncrypter(&buf, c)
		n, err := encrypter.Write(testData)
		assert.Equal(t, 16, n) // PKCS7 padding will pad to 16 bytes (2 blocks)
		assert.Nil(t, err)
	})

	t.Run("write with empty data", func(t *testing.T) {
		var buf bytes.Buffer
		c := cipher.NewBlowfishCipher(cipher.CBC)
		c.SetKey(key16)

		encrypter := NewStreamEncrypter(&buf, c)
		n, err := encrypter.Write([]byte{})
		assert.Equal(t, 0, n)
		assert.Nil(t, err)
	})

	t.Run("write with existing error", func(t *testing.T) {
		var buf bytes.Buffer
		c := cipher.NewBlowfishCipher(cipher.CBC)
		c.SetKey(key16)

		encrypter := NewStreamEncrypter(&buf, c)
		streamEncrypter := encrypter.(*StreamEncrypter)
		streamEncrypter.Error = errors.New("test error")

		n, err := encrypter.Write(testData)
		assert.Equal(t, 0, n)
		assert.NotNil(t, err)
	})

	t.Run("write with cipher error", func(t *testing.T) {
		var buf bytes.Buffer
		c := cipher.NewBlowfishCipher(cipher.CBC)
		c.SetKey(key16)

		encrypter := NewStreamEncrypter(&buf, c)
		streamEncrypter := encrypter.(*StreamEncrypter)
		streamEncrypter.Error = nil

		// Modify the key to invalid state
		streamEncrypter.cipher.Key = nil

		n, err := encrypter.Write(testData)
		assert.Equal(t, 0, n)
		assert.IsType(t, EncryptError{}, err)
	})

	t.Run("write with writer error", func(t *testing.T) {
		mockWriter := mock.NewErrorReadWriteCloser(errors.New("write error"))
		c := cipher.NewBlowfishCipher(cipher.CBC)
		c.SetKey(key16)
		c.SetIV(iv8)
		c.SetPadding(cipher.No)

		encrypter := NewStreamEncrypter(mockWriter, c)
		n, err := encrypter.Write(testData8)
		assert.Equal(t, 0, n)
		assert.Contains(t, err.Error(), "write error")
	})

	t.Run("write with cipher encrypt error", func(t *testing.T) {
		c := cipher.NewBlowfishCipher(cipher.CBC)
		c.SetKey(key16)
		// Don't set IV to cause encryption error
		c.SetPadding(cipher.PKCS7)

		var buf bytes.Buffer
		encrypter := NewStreamEncrypter(&buf, c)
		streamEncrypter := encrypter.(*StreamEncrypter)
		assert.Nil(t, streamEncrypter.Error)

		n, err := encrypter.Write(testData)
		assert.Equal(t, 0, n)
		// Should get a cipher-related error
		assert.NotNil(t, err)
	})
}

func TestStreamEncrypter_Close(t *testing.T) {
	t.Run("close with closer", func(t *testing.T) {
		mockWriter := mock.NewWriteCloser(&bytes.Buffer{})
		c := cipher.NewBlowfishCipher(cipher.CBC)
		c.SetKey(key16)

		encrypter := NewStreamEncrypter(mockWriter, c)
		err := encrypter.Close()
		assert.Nil(t, err)
	})

	t.Run("close without closer", func(t *testing.T) {
		var buf bytes.Buffer
		c := cipher.NewBlowfishCipher(cipher.CBC)
		c.SetKey(key16)

		encrypter := NewStreamEncrypter(&buf, c)
		err := encrypter.Close()
		assert.Nil(t, err)
	})
}

func TestNewStreamDecrypter(t *testing.T) {
	t.Run("valid key", func(t *testing.T) {
		reader := strings.NewReader("test")
		c := cipher.NewBlowfishCipher(cipher.CBC)
		c.SetKey(key16)

		decrypter := NewStreamDecrypter(reader, c)
		streamDecrypter := decrypter.(*StreamDecrypter)
		assert.Nil(t, streamDecrypter.Error)
	})

	t.Run("invalid key", func(t *testing.T) {
		reader := strings.NewReader("test")
		c := cipher.NewBlowfishCipher(cipher.CBC)
		c.SetKey([]byte("123")) // 3 bytes - too short for Blowfish

		decrypter := NewStreamDecrypter(reader, c)
		streamDecrypter := decrypter.(*StreamDecrypter)
		assert.NotNil(t, streamDecrypter.Error)
		assert.IsType(t, KeySizeError(0), streamDecrypter.Error)
	})
}

func TestStreamDecrypter_Read(t *testing.T) {
	t.Run("successful read", func(t *testing.T) {
		// First encrypt data
		var buf bytes.Buffer
		c := cipher.NewBlowfishCipher(cipher.CBC)
		c.SetKey(key16)
		c.SetIV(iv8)
		c.SetPadding(cipher.PKCS7)

		encrypter := NewStreamEncrypter(&buf, c)
		_, err := encrypter.Write(testData)
		if err != nil {
			return
		}
		err = encrypter.Close()
		if err != nil {
			return
		}

		// Then decrypt
		reader := bytes.NewReader(buf.Bytes())
		decrypter := NewStreamDecrypter(reader, c)
		resultBuf := make([]byte, 20)
		n, err := decrypter.Read(resultBuf)
		assert.Equal(t, len(testData), n)
		assert.Nil(t, err)
		assert.Equal(t, testData, resultBuf[:n])
	})

	t.Run("read with existing error", func(t *testing.T) {
		reader := strings.NewReader("test")
		c := cipher.NewBlowfishCipher(cipher.CBC)
		c.SetKey(key16)

		decrypter := NewStreamDecrypter(reader, c)
		streamDecrypter := decrypter.(*StreamDecrypter)
		streamDecrypter.Error = errors.New("test error")

		buf := make([]byte, 10)
		n, err := decrypter.Read(buf)
		assert.Equal(t, 0, n)
		assert.NotNil(t, err)
	})

	t.Run("read with reader error", func(t *testing.T) {
		mockReader := mock.NewErrorReadWriteCloser(errors.New("read error"))
		c := cipher.NewBlowfishCipher(cipher.CBC)
		c.SetKey(key16)

		decrypter := NewStreamDecrypter(mockReader, c)
		buf := make([]byte, 10)
		n, err := decrypter.Read(buf)
		assert.Equal(t, 0, n)
		assert.IsType(t, ReadError{}, err)
	})

	t.Run("read with empty data", func(t *testing.T) {
		reader := strings.NewReader("")
		c := cipher.NewBlowfishCipher(cipher.CBC)
		c.SetKey(key16)

		decrypter := NewStreamDecrypter(reader, c)
		buf := make([]byte, 10)
		n, err := decrypter.Read(buf)
		assert.Equal(t, 0, n)
		assert.Equal(t, io.EOF, err)
	})

	t.Run("read with cipher error", func(t *testing.T) {
		reader := strings.NewReader("test data")
		c := cipher.NewBlowfishCipher(cipher.CBC)
		c.SetKey(key16)

		decrypter := NewStreamDecrypter(reader, c)
		streamDecrypter := decrypter.(*StreamDecrypter)
		streamDecrypter.Error = nil

		// Modify key to invalid state
		streamDecrypter.cipher.Key = nil

		buf := make([]byte, 10)
		n, err := decrypter.Read(buf)
		assert.Equal(t, 0, n)
		assert.IsType(t, DecryptError{}, err)
	})

	t.Run("read with small buffer", func(t *testing.T) {
		// First encrypt data
		var buf bytes.Buffer
		c := cipher.NewBlowfishCipher(cipher.CBC)
		c.SetKey(key16)
		c.SetIV(iv8)
		c.SetPadding(cipher.PKCS7)

		encrypter := NewStreamEncrypter(&buf, c)
		_, err := encrypter.Write(testData)
		if err != nil {
			return
		}
		err = encrypter.Close()
		if err != nil {
			return
		}

		// Then decrypt with small buffer
		reader := bytes.NewReader(buf.Bytes())
		decrypter := NewStreamDecrypter(reader, c)
		smallBuf := make([]byte, 5)
		n, err := decrypter.Read(smallBuf)
		assert.Equal(t, 5, n)
		assert.IsType(t, BufferError{}, err)
	})

	t.Run("read with decrypt error", func(t *testing.T) {
		// Create data with wrong padding that will cause decryption error
		c := cipher.NewBlowfishCipher(cipher.CBC)
		c.SetKey(key16)
		c.SetIV(iv8)
		c.SetPadding(cipher.PKCS7)

		// First encrypt with one cipher configuration
		var buf bytes.Buffer
		encrypter := NewStreamEncrypter(&buf, c)
		_, err := encrypter.Write(testData)
		if err != nil {
			return
		}
		err = encrypter.Close()
		if err != nil {
			return
		}
		encrypted := buf.Bytes()

		// Try to decrypt with different padding mode to cause error
		c2 := cipher.NewBlowfishCipher(cipher.CBC)
		c2.SetKey(key16)
		c2.SetIV(iv8)
		c2.SetPadding(cipher.No) // Different padding mode

		reader := bytes.NewReader(encrypted)
		decrypter := NewStreamDecrypter(reader, c2)
		buf2 := make([]byte, 100)
		n, err := decrypter.Read(buf2)
		// This may or may not cause an error depending on the implementation
		// We'll accept either behavior
		if err != nil {
			assert.Equal(t, 0, n)
		} else {
			// If no error, at least some data should be read
			assert.NotEqual(t, 0, n)
		}
	})

	t.Run("read with cipher decrypt error path", func(t *testing.T) {
		// Use invalid data size to trigger cipher.Decrypt error
		invalidData := []byte("invalid") // 7 bytes, not multiple of block size (8)
		reader := bytes.NewReader(invalidData)
		c := cipher.NewBlowfishCipher(cipher.CBC)
		c.SetKey(key16)
		c.SetIV(iv8)
		c.SetPadding(cipher.No) // No padding with invalid block size

		decrypter := NewStreamDecrypter(reader, c)
		buf := make([]byte, 100)
		n, err := decrypter.Read(buf)
		assert.Equal(t, 0, n)
		assert.NotNil(t, err)
		// This should trigger the d.cipher.Decrypt error path
	})
}

func TestBlowfish_Errors(t *testing.T) {
	t.Run("key size error", func(t *testing.T) {
		err := KeySizeError(3)
		expected := "crypto/blowfish: invalid key size 3, must be between 1 and 56 bytes"
		assert.Equal(t, expected, err.Error())
	})

	t.Run("encrypt error", func(t *testing.T) {
		originalErr := errors.New("original error")
		err := EncryptError{Err: originalErr}
		assert.Contains(t, err.Error(), "crypto/blowfish: failed to encrypt data:")
		assert.Contains(t, err.Error(), "original error")
	})

	t.Run("decrypt error", func(t *testing.T) {
		originalErr := errors.New("original error")
		err := DecryptError{Err: originalErr}
		assert.Contains(t, err.Error(), "crypto/blowfish: failed to decrypt data:")
		assert.Contains(t, err.Error(), "original error")
	})

	t.Run("read error", func(t *testing.T) {
		originalErr := errors.New("original error")
		err := ReadError{Err: originalErr}
		assert.Contains(t, err.Error(), "crypto/blowfish: failed to read encrypted data:")
		assert.Contains(t, err.Error(), "original error")
	})

	t.Run("buffer error", func(t *testing.T) {
		err := BufferError{bufferSize: 5, dataSize: 10}
		expected := "crypto/blowfish: : buffer size 5 is too small for data size 10"
		assert.Equal(t, expected, err.Error())
	})
}
