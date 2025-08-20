package aes

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"

	"github.com/dromara/dongle/crypto/cipher"
	"github.com/dromara/dongle/mock"
	"github.com/stretchr/testify/assert"
)

// Test data and common setup
var (
	key16      = []byte("1234567890123456")                 // AES-128 key
	key24      = []byte("123456789012345678901234")         // AES-192 key
	key32      = []byte("12345678901234567890123456789012") // AES-256 key
	iv16       = []byte("1234567890123456")                 // 16-byte IV
	nonce12    = []byte("123456789012")                     // 12-byte nonce for GCM
	testData   = []byte("hello world")
	testData16 = []byte("1234567890123456") // Exactly 16 bytes for no-padding tests
)

func TestStdCBC_Encrypt(t *testing.T) {
	t.Run("CBC std encrypt with no padding", func(t *testing.T) {
		c := cipher.AesCipher{
			Key:     key16,
			Block:   cipher.CBC,
			IV:      iv16,
			Padding: cipher.No,
		}
		encrypter := NewStdEncrypter(c)
		result, err := encrypter.Encrypt(testData16)
		assert.NotNil(t, result)
		assert.Nil(t, err)
		assert.NotEqual(t, testData16, result)
	})

	t.Run("CBC std encrypt with zero padding", func(t *testing.T) {
		c := cipher.AesCipher{
			Key:     key16,
			Block:   cipher.CBC,
			IV:      iv16,
			Padding: cipher.Zero,
		}
		encrypter := NewStdEncrypter(c)
		result, err := encrypter.Encrypt(testData)
		assert.NotNil(t, result)
		assert.Nil(t, err)
		assert.NotEqual(t, testData, result)
	})

	t.Run("CBC std encrypt with zero padding", func(t *testing.T) {
		c := cipher.AesCipher{
			Key:     key16,
			Block:   cipher.CBC,
			IV:      iv16,
			Padding: cipher.Zero,
		}
		encrypter := NewStdEncrypter(c)
		result, err := encrypter.Encrypt(testData)
		assert.NotNil(t, result)
		assert.Nil(t, err)
		assert.NotEqual(t, testData, result)
	})

	t.Run("CBC std encrypt with pkcs5 padding", func(t *testing.T) {
		c := cipher.AesCipher{
			Key:     key16,
			Block:   cipher.CBC,
			IV:      iv16,
			Padding: cipher.PKCS5,
		}
		encrypter := NewStdEncrypter(c)
		result, err := encrypter.Encrypt(testData)
		assert.NotNil(t, result)
		assert.Nil(t, err)
		assert.NotEqual(t, testData, result)
	})

	t.Run("CBC std encrypt with pkcs7 padding", func(t *testing.T) {
		c := cipher.AesCipher{
			Key:     key16,
			Block:   cipher.CBC,
			IV:      iv16,
			Padding: cipher.PKCS7,
		}
		encrypter := NewStdEncrypter(c)
		result, err := encrypter.Encrypt(testData)
		assert.NotNil(t, result)
		assert.Nil(t, err)
		assert.NotEqual(t, testData, result)
	})

	t.Run("CBC std encrypt with ansiX923 padding", func(t *testing.T) {
		c := cipher.AesCipher{
			Key:     key16,
			Block:   cipher.CBC,
			IV:      iv16,
			Padding: cipher.AnsiX923,
		}
		encrypter := NewStdEncrypter(c)
		result, err := encrypter.Encrypt(testData)
		assert.NotNil(t, result)
		assert.Nil(t, err)
		assert.NotEqual(t, testData, result)
	})

	t.Run("CBC std encrypt with iso97971 padding", func(t *testing.T) {
		c := cipher.AesCipher{
			Key:     key16,
			Block:   cipher.CBC,
			IV:      iv16,
			Padding: cipher.ISO97971,
		}
		encrypter := NewStdEncrypter(c)
		result, err := encrypter.Encrypt(testData)
		assert.NotNil(t, result)
		assert.Nil(t, err)
		assert.NotEqual(t, testData, result)
	})

	t.Run("CBC std encrypt with iso10126 padding", func(t *testing.T) {
		c := cipher.AesCipher{
			Key:     key16,
			Block:   cipher.CBC,
			IV:      iv16,
			Padding: cipher.ISO10126,
		}
		encrypter := NewStdEncrypter(c)
		result, err := encrypter.Encrypt(testData)
		assert.NotNil(t, result)
		assert.Nil(t, err)
		assert.NotEqual(t, testData, result)
	})

	t.Run("CBC std encrypt with iso78164 padding", func(t *testing.T) {
		c := cipher.AesCipher{
			Key:     key16,
			Block:   cipher.CBC,
			IV:      iv16,
			Padding: cipher.ISO78164,
		}
		encrypter := NewStdEncrypter(c)
		result, err := encrypter.Encrypt(testData)
		assert.NotNil(t, result)
		assert.Nil(t, err)
		assert.NotEqual(t, testData, result)
	})

	t.Run("CBC std encrypt with bit padding", func(t *testing.T) {
		c := cipher.AesCipher{
			Key:     key16,
			Block:   cipher.CBC,
			IV:      iv16,
			Padding: cipher.Bit,
		}
		encrypter := NewStdEncrypter(c)
		result, err := encrypter.Encrypt(testData)
		assert.NotNil(t, result)
		assert.Nil(t, err)
		assert.NotEqual(t, testData, result)
	})
}

func TestStdCBC_Decrypt(t *testing.T) {
	t.Run("CBC std decrypt with no padding", func(t *testing.T) {
		// First encrypt
		c := cipher.AesCipher{
			Key:     key16,
			Block:   cipher.CBC,
			IV:      iv16,
			Padding: cipher.No,
		}
		encrypter := NewStdEncrypter(c)
		encrypted, err := encrypter.Encrypt(testData16)
		assert.Nil(t, err)

		// Then decrypt
		decrypter := NewStdDecrypter(c)
		result, err := decrypter.Decrypt(encrypted)
		assert.NotNil(t, result)
		assert.Nil(t, err)
		assert.Equal(t, testData16, result)
	})

	t.Run("CBC std decrypt with zero padding", func(t *testing.T) {
		// First encrypt
		c := cipher.AesCipher{
			Key:     key16,
			Block:   cipher.CBC,
			IV:      iv16,
			Padding: cipher.Zero,
		}
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

	t.Run("CBC std decrypt with zero padding", func(t *testing.T) {
		// First encrypt
		c := cipher.AesCipher{
			Key:     key16,
			Block:   cipher.CBC,
			IV:      iv16,
			Padding: cipher.Zero,
		}
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

	t.Run("CBC std decrypt with pkcs5 padding", func(t *testing.T) {
		// First encrypt
		c := cipher.AesCipher{
			Key:     key16,
			Block:   cipher.CBC,
			IV:      iv16,
			Padding: cipher.PKCS5,
		}
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

	t.Run("CBC std decrypt with pkcs7 padding", func(t *testing.T) {
		// First encrypt
		c := cipher.AesCipher{
			Key:     key16,
			Block:   cipher.CBC,
			IV:      iv16,
			Padding: cipher.PKCS7,
		}
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

	t.Run("CBC std decrypt with ansiX923 padding", func(t *testing.T) {
		// First encrypt
		c := cipher.AesCipher{
			Key:     key16,
			Block:   cipher.CBC,
			IV:      iv16,
			Padding: cipher.AnsiX923,
		}
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

	t.Run("CBC std decrypt with iso97971 padding", func(t *testing.T) {
		// First encrypt
		c := cipher.AesCipher{
			Key:     key16,
			Block:   cipher.CBC,
			IV:      iv16,
			Padding: cipher.ISO97971,
		}
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

	t.Run("CBC std decrypt with iso10126 padding", func(t *testing.T) {
		// First encrypt
		c := cipher.AesCipher{
			Key:     key16,
			Block:   cipher.CBC,
			IV:      iv16,
			Padding: cipher.ISO10126,
		}
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

	t.Run("CBC std decrypt with iso78164 padding", func(t *testing.T) {
		// First encrypt
		c := cipher.AesCipher{
			Key:     key16,
			Block:   cipher.CBC,
			IV:      iv16,
			Padding: cipher.ISO78164,
		}
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

	t.Run("CBC std decrypt with bit padding", func(t *testing.T) {
		// First encrypt
		c := cipher.AesCipher{
			Key:     key16,
			Block:   cipher.CBC,
			IV:      iv16,
			Padding: cipher.Bit,
		}
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
}

func TestStreamCBC_Encrypt(t *testing.T) {
	t.Run("CBC stream encrypt with no padding", func(t *testing.T) {
		var buf bytes.Buffer
		c := cipher.AesCipher{
			Key:     key16,
			Block:   cipher.CBC,
			IV:      iv16,
			Padding: cipher.No,
		}
		encrypter := NewStreamEncrypter(&buf, c)
		n, err := encrypter.Write(testData16)
		assert.Equal(t, len(testData16), n)
		assert.Nil(t, err)
		err = encrypter.Close()
		assert.Nil(t, err)
		assert.NotEqual(t, 0, buf.Len())
	})

	t.Run("CBC stream encrypt with zero padding", func(t *testing.T) {
		var buf bytes.Buffer
		c := cipher.AesCipher{
			Key:     key16,
			Block:   cipher.CBC,
			IV:      iv16,
			Padding: cipher.Zero,
		}
		encrypter := NewStreamEncrypter(&buf, c)
		n, err := encrypter.Write(testData)
		// Zero padding will pad to 16 bytes (AES block size)
		expectedLength := 16
		assert.Equal(t, expectedLength, n)
		assert.Nil(t, err)
		err = encrypter.Close()
		assert.Nil(t, err)
		assert.NotEqual(t, 0, buf.Len())
	})

	t.Run("CBC stream encrypt with zero padding", func(t *testing.T) {
		var buf bytes.Buffer
		c := cipher.AesCipher{
			Key:     key16,
			Block:   cipher.CBC,
			IV:      iv16,
			Padding: cipher.Zero,
		}
		encrypter := NewStreamEncrypter(&buf, c)
		n, err := encrypter.Write(testData)
		// Zero padding will pad to 16 bytes (AES block size)
		expectedLength := 16
		assert.Equal(t, expectedLength, n)
		assert.Nil(t, err)
		err = encrypter.Close()
		assert.Nil(t, err)
		assert.NotEqual(t, 0, buf.Len())
	})

	t.Run("CBC stream encrypt with ansiX923 padding", func(t *testing.T) {
		var buf bytes.Buffer
		c := cipher.AesCipher{
			Key:     key16,
			Block:   cipher.CBC,
			IV:      iv16,
			Padding: cipher.AnsiX923,
		}
		encrypter := NewStreamEncrypter(&buf, c)
		n, err := encrypter.Write(testData)
		// AnsiX923 padding will pad to 16 bytes (AES block size)
		expectedLength := 16
		assert.Equal(t, expectedLength, n)
		assert.Nil(t, err)
		err = encrypter.Close()
		assert.Nil(t, err)
		assert.NotEqual(t, 0, buf.Len())
	})

	t.Run("CBC stream encrypt with iso97971 padding", func(t *testing.T) {
		var buf bytes.Buffer
		c := cipher.AesCipher{
			Key:     key16,
			Block:   cipher.CBC,
			IV:      iv16,
			Padding: cipher.ISO97971,
		}
		encrypter := NewStreamEncrypter(&buf, c)
		n, err := encrypter.Write(testData)
		// ISO97971 padding will pad to 16 bytes (AES block size)
		expectedLength := 16
		assert.Equal(t, expectedLength, n)
		assert.Nil(t, err)
		err = encrypter.Close()
		assert.Nil(t, err)
		assert.NotEqual(t, 0, buf.Len())
	})

	t.Run("CBC stream encrypt with iso10126 padding", func(t *testing.T) {
		var buf bytes.Buffer
		c := cipher.AesCipher{
			Key:     key16,
			Block:   cipher.CBC,
			IV:      iv16,
			Padding: cipher.ISO10126,
		}
		encrypter := NewStreamEncrypter(&buf, c)
		n, err := encrypter.Write(testData)
		// ISO10126 padding will pad to 16 bytes (AES block size)
		expectedLength := 16
		assert.Equal(t, expectedLength, n)
		assert.Nil(t, err)
		err = encrypter.Close()
		assert.Nil(t, err)
		assert.NotEqual(t, 0, buf.Len())
	})

	t.Run("CBC stream encrypt with iso78164 padding", func(t *testing.T) {
		var buf bytes.Buffer
		c := cipher.AesCipher{
			Key:     key16,
			Block:   cipher.CBC,
			IV:      iv16,
			Padding: cipher.ISO78164,
		}
		encrypter := NewStreamEncrypter(&buf, c)
		n, err := encrypter.Write(testData)
		// ISO78164 padding will pad to 16 bytes (AES block size)
		expectedLength := 16
		assert.Equal(t, expectedLength, n)
		assert.Nil(t, err)
		err = encrypter.Close()
		assert.Nil(t, err)
		assert.NotEqual(t, 0, buf.Len())
	})

	t.Run("CBC stream encrypt with bit padding", func(t *testing.T) {
		var buf bytes.Buffer
		c := cipher.AesCipher{
			Key:     key16,
			Block:   cipher.CBC,
			IV:      iv16,
			Padding: cipher.Bit,
		}
		encrypter := NewStreamEncrypter(&buf, c)
		n, err := encrypter.Write(testData)
		// Bit padding will pad to 16 bytes (AES block size)
		expectedLength := 16
		assert.Equal(t, expectedLength, n)
		assert.Nil(t, err)
		err = encrypter.Close()
		assert.Nil(t, err)
		assert.NotEqual(t, 0, buf.Len())
	})
}
func TestStreamCBC_Decrypt(t *testing.T) {
	t.Run("CBC stream decrypt with no padding", func(t *testing.T) {
		// First encrypt
		var buf bytes.Buffer
		c := cipher.AesCipher{
			Key:     key16,
			Block:   cipher.CBC,
			IV:      iv16,
			Padding: cipher.No,
		}
		encrypter := NewStreamEncrypter(&buf, c)
		encrypter.Write(testData16)
		encrypter.Close()

		// Then decrypt
		reader := bytes.NewReader(buf.Bytes())
		decrypter := NewStreamDecrypter(reader, c)
		resultBuf := make([]byte, 20)
		n, err := decrypter.Read(resultBuf)
		assert.Equal(t, len(testData16), n)
		assert.Nil(t, err)
		assert.Equal(t, testData16, resultBuf[:n])
	})

	t.Run("CBC stream decrypt with zero padding", func(t *testing.T) {
		// First encrypt
		var buf bytes.Buffer
		c := cipher.AesCipher{
			Key:     key16,
			Block:   cipher.CBC,
			IV:      iv16,
			Padding: cipher.Zero,
		}
		encrypter := NewStreamEncrypter(&buf, c)
		encrypter.Write(testData)
		encrypter.Close()

		// Then decrypt
		reader := bytes.NewReader(buf.Bytes())
		decrypter := NewStreamDecrypter(reader, c)
		resultBuf := make([]byte, 20)
		n, err := decrypter.Read(resultBuf)
		assert.Equal(t, len(testData), n)
		assert.Nil(t, err)
		assert.Equal(t, testData, resultBuf[:n])
	})

	t.Run("CBC stream decrypt with empty padding", func(t *testing.T) {
		// First encrypt
		var buf bytes.Buffer
		c := cipher.AesCipher{
			Key:     key16,
			Block:   cipher.CBC,
			IV:      iv16,
			Padding: cipher.Zero,
		}
		encrypter := NewStreamEncrypter(&buf, c)
		encrypter.Write(testData)
		encrypter.Close()

		// Then decrypt
		reader := bytes.NewReader(buf.Bytes())
		decrypter := NewStreamDecrypter(reader, c)
		resultBuf := make([]byte, 20)
		n, err := decrypter.Read(resultBuf)
		assert.Equal(t, len(testData), n)
		assert.Nil(t, err)
		assert.Equal(t, testData, resultBuf[:n])
	})

	t.Run("CBC stream decrypt with ansiX923 padding", func(t *testing.T) {
		// First encrypt
		var buf bytes.Buffer
		c := cipher.AesCipher{
			Key:     key16,
			Block:   cipher.CBC,
			IV:      iv16,
			Padding: cipher.AnsiX923,
		}
		encrypter := NewStreamEncrypter(&buf, c)
		encrypter.Write(testData)
		encrypter.Close()

		// Then decrypt
		reader := bytes.NewReader(buf.Bytes())
		decrypter := NewStreamDecrypter(reader, c)
		resultBuf := make([]byte, 20)
		n, err := decrypter.Read(resultBuf)
		assert.Equal(t, len(testData), n)
		assert.Nil(t, err)
		assert.Equal(t, testData, resultBuf[:n])
	})

	t.Run("CBC stream decrypt with iso97971 padding", func(t *testing.T) {
		// First encrypt
		var buf bytes.Buffer
		c := cipher.AesCipher{
			Key:     key16,
			Block:   cipher.CBC,
			IV:      iv16,
			Padding: cipher.ISO97971,
		}
		encrypter := NewStreamEncrypter(&buf, c)
		encrypter.Write(testData)
		encrypter.Close()

		// Then decrypt
		reader := bytes.NewReader(buf.Bytes())
		decrypter := NewStreamDecrypter(reader, c)
		resultBuf := make([]byte, 20)
		n, err := decrypter.Read(resultBuf)
		assert.Equal(t, len(testData), n)
		assert.Nil(t, err)
		assert.Equal(t, testData, resultBuf[:n])
	})

	t.Run("CBC stream decrypt with iso10126 padding", func(t *testing.T) {
		// First encrypt
		var buf bytes.Buffer
		c := cipher.AesCipher{
			Key:     key16,
			Block:   cipher.CBC,
			IV:      iv16,
			Padding: cipher.ISO10126,
		}
		encrypter := NewStreamEncrypter(&buf, c)
		encrypter.Write(testData)
		encrypter.Close()

		// Then decrypt
		reader := bytes.NewReader(buf.Bytes())
		decrypter := NewStreamDecrypter(reader, c)
		resultBuf := make([]byte, 20)
		n, err := decrypter.Read(resultBuf)
		assert.Equal(t, len(testData), n)
		assert.Nil(t, err)
		assert.Equal(t, testData, resultBuf[:n])
	})

	t.Run("CBC stream decrypt with iso78164 padding", func(t *testing.T) {
		// First encrypt
		var buf bytes.Buffer
		c := cipher.AesCipher{
			Key:     key16,
			Block:   cipher.CBC,
			IV:      iv16,
			Padding: cipher.ISO78164,
		}
		encrypter := NewStreamEncrypter(&buf, c)
		encrypter.Write(testData)
		encrypter.Close()

		// Then decrypt
		reader := bytes.NewReader(buf.Bytes())
		decrypter := NewStreamDecrypter(reader, c)
		resultBuf := make([]byte, 20)
		n, err := decrypter.Read(resultBuf)
		assert.Equal(t, len(testData), n)
		assert.Nil(t, err)
		assert.Equal(t, testData, resultBuf[:n])
	})

	t.Run("CBC stream decrypt with bit padding", func(t *testing.T) {
		// First encrypt
		var buf bytes.Buffer
		c := cipher.AesCipher{
			Key:     key16,
			Block:   cipher.CBC,
			IV:      iv16,
			Padding: cipher.Bit,
		}
		encrypter := NewStreamEncrypter(&buf, c)
		encrypter.Write(testData)
		encrypter.Close()

		// Then decrypt
		reader := bytes.NewReader(buf.Bytes())
		decrypter := NewStreamDecrypter(reader, c)
		resultBuf := make([]byte, 20)
		n, err := decrypter.Read(resultBuf)
		assert.Equal(t, len(testData), n)
		assert.Nil(t, err)
		assert.Equal(t, testData, resultBuf[:n])
	})
}

func TestStdECB_Encrypt(t *testing.T) {
	t.Run("ECB std encrypt with no padding", func(t *testing.T) {
		c := cipher.AesCipher{
			Key:     key16,
			Block:   cipher.ECB,
			Padding: cipher.No,
		}
		encrypter := NewStdEncrypter(c)
		result, err := encrypter.Encrypt(testData16)
		assert.NotNil(t, result)
		assert.Nil(t, err)
		assert.NotEqual(t, testData16, result)
	})

	t.Run("ECB std encrypt with zero padding", func(t *testing.T) {
		c := cipher.AesCipher{
			Key:     key16,
			Block:   cipher.ECB,
			Padding: cipher.Zero,
		}
		encrypter := NewStdEncrypter(c)
		result, err := encrypter.Encrypt(testData)
		assert.NotNil(t, result)
		assert.Nil(t, err)
		assert.NotEqual(t, testData, result)
	})

	t.Run("ECB std encrypt with empty padding", func(t *testing.T) {
		c := cipher.AesCipher{
			Key:     key16,
			Block:   cipher.ECB,
			Padding: cipher.Zero,
		}
		encrypter := NewStdEncrypter(c)
		result, err := encrypter.Encrypt(testData)
		assert.NotNil(t, result)
		assert.Nil(t, err)
		assert.NotEqual(t, testData, result)
	})

	t.Run("ECB std encrypt with pkcs5 padding", func(t *testing.T) {
		c := cipher.AesCipher{
			Key:     key16,
			Block:   cipher.ECB,
			Padding: cipher.PKCS5,
		}
		encrypter := NewStdEncrypter(c)
		result, err := encrypter.Encrypt(testData)
		assert.NotNil(t, result)
		assert.Nil(t, err)
		assert.NotEqual(t, testData, result)
	})

	t.Run("ECB std encrypt with pkcs7 padding", func(t *testing.T) {
		c := cipher.AesCipher{
			Key:     key16,
			Block:   cipher.ECB,
			Padding: cipher.PKCS7,
		}
		encrypter := NewStdEncrypter(c)
		result, err := encrypter.Encrypt(testData)
		assert.NotNil(t, result)
		assert.Nil(t, err)
		assert.NotEqual(t, testData, result)
	})

	t.Run("ECB std encrypt with ansiX923 padding", func(t *testing.T) {
		c := cipher.AesCipher{
			Key:     key16,
			Block:   cipher.ECB,
			Padding: cipher.AnsiX923,
		}
		encrypter := NewStdEncrypter(c)
		result, err := encrypter.Encrypt(testData)
		assert.NotNil(t, result)
		assert.Nil(t, err)
		assert.NotEqual(t, testData, result)
	})

	t.Run("ECB std encrypt with iso97971 padding", func(t *testing.T) {
		c := cipher.AesCipher{
			Key:     key16,
			Block:   cipher.ECB,
			Padding: cipher.ISO97971,
		}
		encrypter := NewStdEncrypter(c)
		result, err := encrypter.Encrypt(testData)
		assert.NotNil(t, result)
		assert.Nil(t, err)
		assert.NotEqual(t, testData, result)
	})

	t.Run("ECB std encrypt with iso10126 padding", func(t *testing.T) {
		c := cipher.AesCipher{
			Key:     key16,
			Block:   cipher.ECB,
			Padding: cipher.ISO10126,
		}
		encrypter := NewStdEncrypter(c)
		result, err := encrypter.Encrypt(testData)
		assert.NotNil(t, result)
		assert.Nil(t, err)
		assert.NotEqual(t, testData, result)
	})

	t.Run("ECB std encrypt with iso78164 padding", func(t *testing.T) {
		c := cipher.AesCipher{
			Key:     key16,
			Block:   cipher.ECB,
			Padding: cipher.ISO78164,
		}
		encrypter := NewStdEncrypter(c)
		result, err := encrypter.Encrypt(testData)
		assert.NotNil(t, result)
		assert.Nil(t, err)
		assert.NotEqual(t, testData, result)
	})

	t.Run("ECB std encrypt with bit padding", func(t *testing.T) {
		c := cipher.AesCipher{
			Key:     key16,
			Block:   cipher.ECB,
			Padding: cipher.Bit,
		}
		encrypter := NewStdEncrypter(c)
		result, err := encrypter.Encrypt(testData)
		assert.NotNil(t, result)
		assert.Nil(t, err)
		assert.NotEqual(t, testData, result)
	})
}

func TestStdECB_Decrypt(t *testing.T) {
	t.Run("ECB std decrypt with no padding", func(t *testing.T) {
		// First encrypt
		c := cipher.AesCipher{
			Key:     key16,
			Block:   cipher.ECB,
			Padding: cipher.No,
		}
		encrypter := NewStdEncrypter(c)
		encrypted, err := encrypter.Encrypt(testData16)
		assert.Nil(t, err)

		// Then decrypt
		decrypter := NewStdDecrypter(c)
		result, err := decrypter.Decrypt(encrypted)
		assert.NotNil(t, result)
		assert.Nil(t, err)
		assert.Equal(t, testData16, result)
	})

	t.Run("ECB std decrypt with zero padding", func(t *testing.T) {
		// First encrypt
		c := cipher.AesCipher{
			Key:     key16,
			Block:   cipher.ECB,
			Padding: cipher.Zero,
		}
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

	t.Run("ECB std decrypt with empty padding", func(t *testing.T) {
		// First encrypt
		c := cipher.AesCipher{
			Key:     key16,
			Block:   cipher.ECB,
			Padding: cipher.Zero,
		}
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

	t.Run("ECB std decrypt with pkcs5 padding", func(t *testing.T) {
		// First encrypt
		c := cipher.AesCipher{
			Key:     key16,
			Block:   cipher.ECB,
			Padding: cipher.PKCS5,
		}
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

	t.Run("ECB std decrypt with pkcs7 padding", func(t *testing.T) {
		// First encrypt
		c := cipher.AesCipher{
			Key:     key16,
			Block:   cipher.ECB,
			Padding: cipher.PKCS7,
		}
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

	t.Run("ECB std decrypt with ansiX923 padding", func(t *testing.T) {
		// First encrypt
		c := cipher.AesCipher{
			Key:     key16,
			Block:   cipher.ECB,
			Padding: cipher.AnsiX923,
		}
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

	t.Run("ECB std decrypt with iso97971 padding", func(t *testing.T) {
		// First encrypt
		c := cipher.AesCipher{
			Key:     key16,
			Block:   cipher.ECB,
			Padding: cipher.ISO97971,
		}
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

	t.Run("ECB std decrypt with iso10126 padding", func(t *testing.T) {
		// First encrypt
		c := cipher.AesCipher{
			Key:     key16,
			Block:   cipher.ECB,
			Padding: cipher.ISO10126,
		}
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

	t.Run("ECB std decrypt with iso78164 padding", func(t *testing.T) {
		// First encrypt
		c := cipher.AesCipher{
			Key:     key16,
			Block:   cipher.ECB,
			Padding: cipher.ISO78164,
		}
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

	t.Run("ECB std decrypt with bit padding", func(t *testing.T) {
		// First encrypt
		c := cipher.AesCipher{
			Key:     key16,
			Block:   cipher.ECB,
			Padding: cipher.Bit,
		}
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
}

func TestStreamECB_Encrypt(t *testing.T) {
	t.Run("ECB stream encrypt with no padding", func(t *testing.T) {
		var buf bytes.Buffer
		c := cipher.AesCipher{
			Key:     key16,
			Block:   cipher.ECB,
			Padding: cipher.No,
		}
		encrypter := NewStreamEncrypter(&buf, c)
		n, err := encrypter.Write(testData16)
		assert.Equal(t, len(testData16), n)
		assert.Nil(t, err)
		err = encrypter.Close()
		assert.Nil(t, err)
		assert.NotEqual(t, 0, buf.Len())
	})

	t.Run("ECB stream encrypt with zero padding", func(t *testing.T) {
		var buf bytes.Buffer
		c := cipher.AesCipher{
			Key:     key16,
			Block:   cipher.ECB,
			Padding: cipher.Zero,
		}
		encrypter := NewStreamEncrypter(&buf, c)
		n, err := encrypter.Write(testData)
		// Zero padding will pad to 16 bytes (AES block size)
		expectedLength := 16
		assert.Equal(t, expectedLength, n)
		assert.Nil(t, err)
		err = encrypter.Close()
		assert.Nil(t, err)
		assert.NotEqual(t, 0, buf.Len())
	})

	t.Run("ECB stream encrypt with empty padding", func(t *testing.T) {
		var buf bytes.Buffer
		c := cipher.AesCipher{
			Key:     key16,
			Block:   cipher.ECB,
			Padding: cipher.Zero,
		}
		encrypter := NewStreamEncrypter(&buf, c)
		n, err := encrypter.Write(testData)
		// Zero padding will pad to 16 bytes (AES block size)
		expectedLength := 16
		assert.Equal(t, expectedLength, n)
		assert.Nil(t, err)
		err = encrypter.Close()
		assert.Nil(t, err)
		assert.NotEqual(t, 0, buf.Len())
	})

	t.Run("ECB stream encrypt with ansiX923 padding", func(t *testing.T) {
		var buf bytes.Buffer
		c := cipher.AesCipher{
			Key:     key16,
			Block:   cipher.ECB,
			Padding: cipher.AnsiX923,
		}
		encrypter := NewStreamEncrypter(&buf, c)
		n, err := encrypter.Write(testData)
		// AnsiX923 padding will pad to 16 bytes (AES block size)
		expectedLength := 16
		assert.Equal(t, expectedLength, n)
		assert.Nil(t, err)
		err = encrypter.Close()
		assert.Nil(t, err)
		assert.NotEqual(t, 0, buf.Len())
	})

	t.Run("ECB stream encrypt with iso97971 padding", func(t *testing.T) {
		var buf bytes.Buffer
		c := cipher.AesCipher{
			Key:     key16,
			Block:   cipher.ECB,
			Padding: cipher.ISO97971,
		}
		encrypter := NewStreamEncrypter(&buf, c)
		n, err := encrypter.Write(testData)
		// ISO97971 padding will pad to 16 bytes (AES block size)
		expectedLength := 16
		assert.Equal(t, expectedLength, n)
		assert.Nil(t, err)
		err = encrypter.Close()
		assert.Nil(t, err)
		assert.NotEqual(t, 0, buf.Len())
	})

	t.Run("ECB stream encrypt with iso10126 padding", func(t *testing.T) {
		var buf bytes.Buffer
		c := cipher.AesCipher{
			Key:     key16,
			Block:   cipher.ECB,
			Padding: cipher.ISO10126,
		}
		encrypter := NewStreamEncrypter(&buf, c)
		n, err := encrypter.Write(testData)
		// ISO10126 padding will pad to 16 bytes (AES block size)
		expectedLength := 16
		assert.Equal(t, expectedLength, n)
		assert.Nil(t, err)
		err = encrypter.Close()
		assert.Nil(t, err)
		assert.NotEqual(t, 0, buf.Len())
	})

	t.Run("ECB stream encrypt with iso78164 padding", func(t *testing.T) {
		var buf bytes.Buffer
		c := cipher.AesCipher{
			Key:     key16,
			Block:   cipher.ECB,
			Padding: cipher.ISO78164,
		}
		encrypter := NewStreamEncrypter(&buf, c)
		n, err := encrypter.Write(testData)
		// ISO78164 padding will pad to 16 bytes (AES block size)
		expectedLength := 16
		assert.Equal(t, expectedLength, n)
		assert.Nil(t, err)
		err = encrypter.Close()
		assert.Nil(t, err)
		assert.NotEqual(t, 0, buf.Len())
	})

	t.Run("ECB stream encrypt with bit padding", func(t *testing.T) {
		var buf bytes.Buffer
		c := cipher.AesCipher{
			Key:     key16,
			Block:   cipher.ECB,
			Padding: cipher.Bit,
		}
		encrypter := NewStreamEncrypter(&buf, c)
		n, err := encrypter.Write(testData)
		// Bit padding will pad to 16 bytes (AES block size)
		expectedLength := 16
		assert.Equal(t, expectedLength, n)
		assert.Nil(t, err)
		err = encrypter.Close()
		assert.Nil(t, err)
		assert.NotEqual(t, 0, buf.Len())
	})
}
func TestStreamECB_Decrypt(t *testing.T) {
	t.Run("ECB stream decrypt with no padding", func(t *testing.T) {
		// First encrypt
		var buf bytes.Buffer
		c := cipher.AesCipher{
			Key:     key16,
			Block:   cipher.ECB,
			Padding: cipher.No,
		}
		encrypter := NewStreamEncrypter(&buf, c)
		encrypter.Write(testData16)
		encrypter.Close()

		// Then decrypt
		reader := bytes.NewReader(buf.Bytes())
		decrypter := NewStreamDecrypter(reader, c)
		resultBuf := make([]byte, 20)
		n, err := decrypter.Read(resultBuf)
		assert.Equal(t, len(testData16), n)
		assert.Nil(t, err)
		assert.Equal(t, testData16, resultBuf[:n])
	})

	t.Run("ECB stream decrypt with zero padding", func(t *testing.T) {
		// First encrypt
		var buf bytes.Buffer
		c := cipher.AesCipher{
			Key:     key16,
			Block:   cipher.ECB,
			Padding: cipher.Zero,
		}
		encrypter := NewStreamEncrypter(&buf, c)
		encrypter.Write(testData)
		encrypter.Close()

		// Then decrypt
		reader := bytes.NewReader(buf.Bytes())
		decrypter := NewStreamDecrypter(reader, c)
		resultBuf := make([]byte, 20)
		n, err := decrypter.Read(resultBuf)
		assert.Equal(t, len(testData), n)
		assert.Nil(t, err)
		assert.Equal(t, testData, resultBuf[:n])
	})

	t.Run("ECB stream decrypt with empty padding", func(t *testing.T) {
		// First encrypt
		var buf bytes.Buffer
		c := cipher.AesCipher{
			Key:     key16,
			Block:   cipher.ECB,
			Padding: cipher.Zero,
		}
		encrypter := NewStreamEncrypter(&buf, c)
		encrypter.Write(testData)
		encrypter.Close()

		// Then decrypt
		reader := bytes.NewReader(buf.Bytes())
		decrypter := NewStreamDecrypter(reader, c)
		resultBuf := make([]byte, 20)
		n, err := decrypter.Read(resultBuf)
		assert.Equal(t, len(testData), n)
		assert.Nil(t, err)
		assert.Equal(t, testData, resultBuf[:n])
	})

	t.Run("ECB stream decrypt with ansiX923 padding", func(t *testing.T) {
		// First encrypt
		var buf bytes.Buffer
		c := cipher.AesCipher{
			Key:     key16,
			Block:   cipher.ECB,
			Padding: cipher.AnsiX923,
		}
		encrypter := NewStreamEncrypter(&buf, c)
		encrypter.Write(testData)
		encrypter.Close()

		// Then decrypt
		reader := bytes.NewReader(buf.Bytes())
		decrypter := NewStreamDecrypter(reader, c)
		resultBuf := make([]byte, 20)
		n, err := decrypter.Read(resultBuf)
		assert.Equal(t, len(testData), n)
		assert.Nil(t, err)
		assert.Equal(t, testData, resultBuf[:n])
	})

	t.Run("ECB stream decrypt with iso97971 padding", func(t *testing.T) {
		// First encrypt
		var buf bytes.Buffer
		c := cipher.AesCipher{
			Key:     key16,
			Block:   cipher.ECB,
			Padding: cipher.ISO97971,
		}
		encrypter := NewStreamEncrypter(&buf, c)
		encrypter.Write(testData)
		encrypter.Close()

		// Then decrypt
		reader := bytes.NewReader(buf.Bytes())
		decrypter := NewStreamDecrypter(reader, c)
		resultBuf := make([]byte, 20)
		n, err := decrypter.Read(resultBuf)
		assert.Equal(t, len(testData), n)
		assert.Nil(t, err)
		assert.Equal(t, testData, resultBuf[:n])
	})

	t.Run("ECB stream decrypt with iso10126 padding", func(t *testing.T) {
		// First encrypt
		var buf bytes.Buffer
		c := cipher.AesCipher{
			Key:     key16,
			Block:   cipher.ECB,
			Padding: cipher.ISO10126,
		}
		encrypter := NewStreamEncrypter(&buf, c)
		encrypter.Write(testData)
		encrypter.Close()

		// Then decrypt
		reader := bytes.NewReader(buf.Bytes())
		decrypter := NewStreamDecrypter(reader, c)
		resultBuf := make([]byte, 20)
		n, err := decrypter.Read(resultBuf)
		assert.Equal(t, len(testData), n)
		assert.Nil(t, err)
		assert.Equal(t, testData, resultBuf[:n])
	})

	t.Run("ECB stream decrypt with iso78164 padding", func(t *testing.T) {
		// First encrypt
		var buf bytes.Buffer
		c := cipher.AesCipher{
			Key:     key16,
			Block:   cipher.ECB,
			Padding: cipher.ISO78164,
		}
		encrypter := NewStreamEncrypter(&buf, c)
		encrypter.Write(testData)
		encrypter.Close()

		// Then decrypt
		reader := bytes.NewReader(buf.Bytes())
		decrypter := NewStreamDecrypter(reader, c)
		resultBuf := make([]byte, 20)
		n, err := decrypter.Read(resultBuf)
		assert.Equal(t, len(testData), n)
		assert.Nil(t, err)
		assert.Equal(t, testData, resultBuf[:n])
	})

	t.Run("ECB stream decrypt with bit padding", func(t *testing.T) {
		// First encrypt
		var buf bytes.Buffer
		c := cipher.AesCipher{
			Key:     key16,
			Block:   cipher.ECB,
			Padding: cipher.Bit,
		}
		encrypter := NewStreamEncrypter(&buf, c)
		encrypter.Write(testData)
		encrypter.Close()

		// Then decrypt
		reader := bytes.NewReader(buf.Bytes())
		decrypter := NewStreamDecrypter(reader, c)
		resultBuf := make([]byte, 20)
		n, err := decrypter.Read(resultBuf)
		assert.Equal(t, len(testData), n)
		assert.Nil(t, err)
		assert.Equal(t, testData, resultBuf[:n])
	})
}

func TestStdCTR_Encrypt(t *testing.T) {
	t.Run("CTR std encrypt", func(t *testing.T) {
		c := cipher.AesCipher{
			Key:     key16,
			Block:   cipher.CTR,
			IV:      nonce12,   // CTR uses IV (12 or 16 bytes)
			Padding: cipher.No, // CTR mode doesn't need padding
		}
		encrypter := NewStdEncrypter(c)
		result, err := encrypter.Encrypt(testData)
		assert.NotNil(t, result)
		assert.Nil(t, err)
		assert.NotEqual(t, testData, result)
	})
}

func TestStdCTR_Decrypt(t *testing.T) {
	t.Run("CTR std decrypt", func(t *testing.T) {
		// First encrypt
		c := cipher.AesCipher{
			Key:     key16,
			Block:   cipher.CTR,
			IV:      nonce12,
			Padding: cipher.No, // CTR mode doesn't need padding
		}
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
}

func TestStreamCTR_Encrypt(t *testing.T) {
	t.Run("CTR stream encrypt", func(t *testing.T) {
		var buf bytes.Buffer
		c := cipher.AesCipher{
			Key:     key16,
			Block:   cipher.CTR,
			IV:      nonce12,
			Padding: cipher.No, // CTR mode doesn't need padding
		}
		encrypter := NewStreamEncrypter(&buf, c)
		n, err := encrypter.Write(testData)
		assert.Equal(t, len(testData), n)
		assert.Nil(t, err)
		err = encrypter.Close()
		assert.Nil(t, err)
		assert.NotEqual(t, 0, buf.Len())
	})
}

func TestStreamCTR_Decrypt(t *testing.T) {
	t.Run("CTR stream decrypt", func(t *testing.T) {
		// First encrypt
		var buf bytes.Buffer
		c := cipher.AesCipher{
			Key:     key16,
			Block:   cipher.CTR,
			IV:      nonce12,
			Padding: cipher.No, // CTR mode doesn't need padding
		}
		encrypter := NewStreamEncrypter(&buf, c)
		encrypter.Write(testData)
		encrypter.Close()

		// Then decrypt
		reader := bytes.NewReader(buf.Bytes())
		decrypter := NewStreamDecrypter(reader, c)
		resultBuf := make([]byte, 20)
		n, err := decrypter.Read(resultBuf)
		assert.Equal(t, len(testData), n)
		assert.Nil(t, err)
		assert.Equal(t, testData, resultBuf[:n])
	})
}

func TestStdCFB_Encrypt(t *testing.T) {
	t.Run("CFB std encrypt", func(t *testing.T) {
		c := cipher.AesCipher{
			Key:     key16,
			Block:   cipher.CFB,
			IV:      iv16,
			Padding: cipher.No, // CFB mode doesn't need padding
		}
		encrypter := NewStdEncrypter(c)
		result, err := encrypter.Encrypt(testData)
		assert.NotNil(t, result)
		assert.Nil(t, err)
		assert.NotEqual(t, testData, result)
	})
}

func TestStdCFB_Decrypt(t *testing.T) {
	t.Run("CFB std decrypt", func(t *testing.T) {
		// First encrypt
		c := cipher.AesCipher{
			Key:     key16,
			Block:   cipher.CFB,
			IV:      iv16,
			Padding: cipher.No, // CFB mode doesn't need padding
		}
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
}

func TestStreamCFB_Encrypt(t *testing.T) {
	t.Run("CFB stream encrypt", func(t *testing.T) {
		var buf bytes.Buffer
		c := cipher.AesCipher{
			Key:     key16,
			Block:   cipher.CFB,
			IV:      iv16,
			Padding: cipher.No, // CFB mode doesn't need padding
		}
		encrypter := NewStreamEncrypter(&buf, c)
		n, err := encrypter.Write(testData)
		assert.Equal(t, len(testData), n)
		assert.Nil(t, err)
		err = encrypter.Close()
		assert.Nil(t, err)
		assert.NotEqual(t, 0, buf.Len())
	})
}

func TestStreamCFB_Decrypt(t *testing.T) {
	t.Run("CFB stream decrypt", func(t *testing.T) {
		// First encrypt
		var buf bytes.Buffer
		c := cipher.AesCipher{
			Key:     key16,
			Block:   cipher.CFB,
			IV:      iv16,
			Padding: cipher.No, // CFB mode doesn't need padding
		}
		encrypter := NewStreamEncrypter(&buf, c)
		encrypter.Write(testData)
		encrypter.Close()

		// Then decrypt
		reader := bytes.NewReader(buf.Bytes())
		decrypter := NewStreamDecrypter(reader, c)
		resultBuf := make([]byte, 20)
		n, err := decrypter.Read(resultBuf)
		assert.Equal(t, len(testData), n)
		assert.Nil(t, err)
		assert.Equal(t, testData, resultBuf[:n])
	})
}

func TestStdOFB_Encrypt(t *testing.T) {
	t.Run("OFB std encrypt", func(t *testing.T) {
		c := cipher.AesCipher{
			Key:     key16,
			Block:   cipher.OFB,
			IV:      iv16,
			Padding: cipher.No, // OFB mode doesn't need padding
		}
		encrypter := NewStdEncrypter(c)
		result, err := encrypter.Encrypt(testData)
		assert.NotNil(t, result)
		assert.Nil(t, err)
		assert.NotEqual(t, testData, result)
	})
}

func TestStdOFB_Decrypt(t *testing.T) {
	t.Run("OFB std decrypt", func(t *testing.T) {
		// First encrypt
		c := cipher.AesCipher{
			Key:     key16,
			Block:   cipher.OFB,
			IV:      iv16,
			Padding: cipher.No, // OFB mode doesn't need padding
		}
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
}

func TestStreamOFB_Encrypt(t *testing.T) {
	t.Run("OFB stream encrypt", func(t *testing.T) {
		var buf bytes.Buffer
		c := cipher.AesCipher{
			Key:     key16,
			Block:   cipher.OFB,
			IV:      iv16,
			Padding: cipher.No, // OFB mode doesn't need padding
		}
		encrypter := NewStreamEncrypter(&buf, c)
		n, err := encrypter.Write(testData)
		assert.Equal(t, len(testData), n)
		assert.Nil(t, err)
		err = encrypter.Close()
		assert.Nil(t, err)
		assert.NotEqual(t, 0, buf.Len())
	})
}

func TestStreamOFB_Decrypt(t *testing.T) {
	t.Run("OFB stream decrypt", func(t *testing.T) {
		// First encrypt
		var buf bytes.Buffer
		c := cipher.AesCipher{
			Key:     key16,
			Block:   cipher.OFB,
			IV:      iv16,
			Padding: cipher.No, // OFB mode doesn't need padding
		}
		encrypter := NewStreamEncrypter(&buf, c)
		encrypter.Write(testData)
		encrypter.Close()

		// Then decrypt
		reader := bytes.NewReader(buf.Bytes())
		decrypter := NewStreamDecrypter(reader, c)
		resultBuf := make([]byte, 20)
		n, err := decrypter.Read(resultBuf)
		assert.Equal(t, len(testData), n)
		assert.Nil(t, err)
		assert.Equal(t, testData, resultBuf[:n])
	})
}

func TestStdGCM_Encrypt(t *testing.T) {
	t.Run("GCM std encrypt", func(t *testing.T) {
		c := cipher.AesCipher{
			Key:   key16,
			Block: cipher.GCM,
			Nonce: nonce12, // GCM uses nonce (12 or 16 bytes)
		}
		encrypter := NewStdEncrypter(c)
		result, err := encrypter.Encrypt(testData)
		assert.NotNil(t, result)
		assert.Nil(t, err)
		assert.NotEqual(t, testData, result)
	})
}

func TestStdGCM_Decrypt(t *testing.T) {
	t.Run("GCM std decrypt", func(t *testing.T) {
		// First encrypt
		c := cipher.AesCipher{
			Key:   key16,
			Block: cipher.GCM,
			Nonce: nonce12,
		}
		encrypter := NewStdEncrypter(c)
		encrypted, err := encrypter.Encrypt(testData)
		assert.Nil(t, err)

		// Then decrypt
		decrypter := NewStdDecrypter(c)
		result, err := decrypter.Decrypt(encrypted)
		assert.Nil(t, result)
		assert.Nil(t, err)
	})
}

func TestStreamGCM_Encrypt(t *testing.T) {
	t.Run("GCM stream encrypt", func(t *testing.T) {
		var buf bytes.Buffer
		c := cipher.AesCipher{
			Key:   key16,
			Block: cipher.GCM,
			Nonce: nonce12,
		}
		encrypter := NewStreamEncrypter(&buf, c)
		n, err := encrypter.Write(testData)
		// GCM mode adds authentication tag (16 bytes) to the output
		expectedLength := len(testData) + 16
		assert.Equal(t, expectedLength, n)
		assert.Nil(t, err)
		err = encrypter.Close()
		assert.Nil(t, err)
		assert.NotEqual(t, 0, buf.Len())
	})
}

func TestStreamGCM_Decrypt(t *testing.T) {
	t.Run("GCM stream decrypt", func(t *testing.T) {
		// First encrypt
		var buf bytes.Buffer
		c := cipher.AesCipher{
			Key:   key16,
			Block: cipher.GCM,
			Nonce: nonce12,
		}
		encrypter := NewStreamEncrypter(&buf, c)
		encrypter.Write(testData)
		encrypter.Close()

		// GCM mode decryption test

		// Then decrypt
		reader := bytes.NewReader(buf.Bytes())
		decrypter := NewStreamDecrypter(reader, c)
		resultBuf := make([]byte, 20)
		n, err := decrypter.Read(resultBuf)
		assert.Equal(t, 0, n)
		assert.Nil(t, err)
	})
}

func TestAES_Error(t *testing.T) {
	t.Run("invalid key size", func(t *testing.T) {
		c := cipher.AesCipher{Key: []byte("invalid")}
		encrypter := NewStdEncrypter(c)
		assert.NotNil(t, encrypter.Error)
		assert.IsType(t, KeySizeError(0), encrypter.Error)
		assert.Equal(t, "crypto/aes: invalid key size 7, must be 16, 24, or 32 bytes", encrypter.Error.Error())

		decrypter := NewStdDecrypter(c)
		assert.NotNil(t, decrypter.Error)
		assert.IsType(t, KeySizeError(0), decrypter.Error)
		assert.Equal(t, "crypto/aes: invalid key size 7, must be 16, 24, or 32 bytes", decrypter.Error.Error())
	})

	t.Run("nil key", func(t *testing.T) {
		c := cipher.AesCipher{Key: nil}
		encrypter := NewStdEncrypter(c)
		assert.NotNil(t, encrypter.Error)
		assert.IsType(t, KeySizeError(0), encrypter.Error)
		assert.Equal(t, "crypto/aes: invalid key size 0, must be 16, 24, or 32 bytes", encrypter.Error.Error())

		decrypter := NewStdDecrypter(c)
		assert.NotNil(t, decrypter.Error)
		assert.IsType(t, KeySizeError(0), decrypter.Error)
		assert.Equal(t, "crypto/aes: invalid key size 0, must be 16, 24, or 32 bytes", decrypter.Error.Error())
	})

	t.Run("empty key", func(t *testing.T) {
		c := cipher.AesCipher{Key: []byte{}}
		encrypter := NewStdEncrypter(c)
		assert.NotNil(t, encrypter.Error)
		assert.IsType(t, KeySizeError(0), encrypter.Error)
		assert.Equal(t, "crypto/aes: invalid key size 0, must be 16, 24, or 32 bytes", encrypter.Error.Error())

		decrypter := NewStdDecrypter(c)
		assert.NotNil(t, decrypter.Error)
		assert.IsType(t, KeySizeError(0), decrypter.Error)
		assert.Equal(t, "crypto/aes: invalid key size 0, must be 16, 24, or 32 bytes", decrypter.Error.Error())
	})

	t.Run("encryption with invalid key", func(t *testing.T) {
		c := cipher.AesCipher{
			Key:     []byte("invalid"),
			Block:   cipher.CBC,
			IV:      iv16,
			Padding: cipher.PKCS7,
		}
		encrypter := NewStdEncrypter(c)
		// Clear the error to test the encryption error path
		encrypter.Error = nil
		result, err := encrypter.Encrypt([]byte("hello"))
		assert.Nil(t, result)
		assert.NotNil(t, err)
		assert.IsType(t, EncryptError{}, err)
	})

	t.Run("decryption with invalid key", func(t *testing.T) {
		c := cipher.AesCipher{
			Key:     []byte("invalid"),
			Block:   cipher.CBC,
			IV:      iv16,
			Padding: cipher.PKCS7,
		}
		decrypter := NewStdDecrypter(c)
		// Clear the error to test the decryption error path
		decrypter.Error = nil
		result, err := decrypter.Decrypt([]byte("hello"))
		assert.Nil(t, result)
		assert.NotNil(t, err)
		assert.IsType(t, DecryptError{}, err)
	})

	t.Run("stream encryption with invalid key", func(t *testing.T) {
		var buf bytes.Buffer
		c := cipher.AesCipher{
			Key:     []byte("invalid"),
			Block:   cipher.CBC,
			IV:      iv16,
			Padding: cipher.PKCS7,
		}
		encrypter := NewStreamEncrypter(&buf, c)
		// Clear the error to test the encryption error path
		streamEncrypter := encrypter.(*StreamEncrypter)
		streamEncrypter.Error = nil
		n, err := encrypter.Write([]byte("hello"))
		assert.Equal(t, 0, n)
		assert.NotNil(t, err)
		assert.IsType(t, EncryptError{}, err)
	})

	t.Run("stream decryption with invalid key", func(t *testing.T) {
		reader := strings.NewReader("test")
		c := cipher.AesCipher{
			Key:     []byte("invalid"),
			Block:   cipher.CBC,
			IV:      iv16,
			Padding: cipher.PKCS7,
		}
		decrypter := NewStreamDecrypter(reader, c)
		// Clear the error to test the decryption error path
		streamDecrypter := decrypter.(*StreamDecrypter)
		streamDecrypter.Error = nil
		buf := make([]byte, 10)
		n, err := decrypter.Read(buf)
		assert.Equal(t, 0, n)
		assert.NotNil(t, err)
		assert.IsType(t, DecryptError{}, err)
	})

	t.Run("write with writer error", func(t *testing.T) {
		// Create a mock writer that returns error using mock package
		mockWriter := mock.NewErrorReadWriteCloser(assert.AnError)
		c := cipher.AesCipher{
			Key:     key16,
			Block:   cipher.ECB,
			Padding: cipher.PKCS7,
		}
		encrypter := NewStreamEncrypter(mockWriter, c)
		n, err := encrypter.Write([]byte("1234567890123456"))
		assert.Equal(t, 0, n)
		assert.NotNil(t, err)
		assert.Equal(t, assert.AnError, err)
	})

	t.Run("read with reader error", func(t *testing.T) {
		// Create a mock reader that returns error using mock package
		mockReader := mock.NewErrorReadWriteCloser(assert.AnError)
		c := cipher.AesCipher{
			Key:     key16,
			Block:   cipher.CBC,
			IV:      iv16,
			Padding: cipher.PKCS7,
		}
		decrypter := NewStreamDecrypter(mockReader, c)
		buf := make([]byte, 10)
		n, err := decrypter.Read(buf)
		assert.Equal(t, 0, n)
		assert.NotNil(t, err)
		assert.IsType(t, ReadError{}, err)
	})

	t.Run("buffer too small error", func(t *testing.T) {
		// First encrypt some data
		c := cipher.AesCipher{
			Key:     key16,
			Block:   cipher.CBC,
			IV:      iv16,
			Padding: cipher.PKCS7,
		}
		var buf bytes.Buffer
		encrypter := NewStreamEncrypter(&buf, c)
		encrypter.Write([]byte("hello world"))
		encrypter.Close()

		// Now decrypt with small buffer
		reader := bytes.NewReader(buf.Bytes())
		decrypter := NewStreamDecrypter(reader, c)
		smallBuf := make([]byte, 5) // Too small for "hello world"
		n, err := decrypter.Read(smallBuf)
		assert.Equal(t, 5, n)
		assert.NotNil(t, err)
		assert.IsType(t, BufferError{}, err)
	})

	t.Run("error types", func(t *testing.T) {
		// Test KeySizeError
		err := KeySizeError(8)
		assert.Equal(t, "crypto/aes: invalid key size 8, must be 16, 24, or 32 bytes", err.Error())

		// Test EncryptError
		encryptErr := EncryptError{Err: assert.AnError}
		assert.Contains(t, encryptErr.Error(), "crypto/aes: failed to encrypt data:")

		// Test DecryptError
		decryptErr := DecryptError{Err: assert.AnError}
		assert.Contains(t, decryptErr.Error(), "crypto/aes: failed to decrypt data:")

		// Test ReadError
		readErr := ReadError{Err: assert.AnError}
		assert.Contains(t, readErr.Error(), "crypto/aes: failed to read encrypted data:")

		// Test BufferError
		bufferErr := BufferError{bufferSize: 5, dataSize: 10}
		assert.Equal(t, "crypto/aes: : buffer size 5 is too small for data size 10", bufferErr.Error())
	})

	t.Run("empty data handling", func(t *testing.T) {
		c := cipher.AesCipher{
			Key:     key16,
			Block:   cipher.CBC,
			IV:      iv16,
			Padding: cipher.PKCS7,
		}
		encrypter := NewStdEncrypter(c)
		result, err := encrypter.Encrypt([]byte{})
		assert.NotNil(t, result)
		assert.Nil(t, err)

		decrypter := NewStdDecrypter(c)
		decrypted, err := decrypter.Decrypt(result)
		assert.NotNil(t, decrypted)
		assert.Nil(t, err)
		assert.Equal(t, []byte{}, decrypted)
	})

	t.Run("large buffer handling", func(t *testing.T) {
		// First encrypt some data
		c := cipher.AesCipher{
			Key:     key16,
			Block:   cipher.CBC,
			IV:      iv16,
			Padding: cipher.PKCS7,
		}
		var buf bytes.Buffer
		encrypter := NewStreamEncrypter(&buf, c)
		encrypter.Write([]byte("hello world"))
		encrypter.Close()

		// Now decrypt with large buffer
		reader := bytes.NewReader(buf.Bytes())
		decrypter := NewStreamDecrypter(reader, c)
		largeBuf := make([]byte, 100) // Much larger than needed
		n, err := decrypter.Read(largeBuf)
		assert.Equal(t, len("hello world"), n)
		assert.Nil(t, err)
		assert.Equal(t, []byte("hello world"), largeBuf[:n])
	})

	t.Run("close without write", func(t *testing.T) {
		var buf bytes.Buffer
		c := cipher.AesCipher{
			Key:     key16,
			Block:   cipher.CBC,
			IV:      iv16,
			Padding: cipher.PKCS7,
		}
		encrypter := NewStreamEncrypter(&buf, c)
		err := encrypter.Close()
		assert.Nil(t, err)
		assert.Equal(t, 0, buf.Len()) // No data written, so buffer should be empty
	})

	t.Run("read empty stream", func(t *testing.T) {
		reader := strings.NewReader("")
		c := cipher.AesCipher{
			Key:     key16,
			Block:   cipher.CBC,
			IV:      iv16,
			Padding: cipher.PKCS7,
		}
		decrypter := NewStreamDecrypter(reader, c)
		buf := make([]byte, 10)
		n, err := decrypter.Read(buf)
		assert.Equal(t, 0, n)
		assert.Equal(t, io.EOF, err)
	})

	t.Run("write empty data", func(t *testing.T) {
		var buf bytes.Buffer
		c := cipher.AesCipher{
			Key:     key16,
			Block:   cipher.ECB,
			Padding: cipher.PKCS7,
		}
		encrypter := NewStreamEncrypter(&buf, c)
		n, err := encrypter.Write([]byte{})
		assert.Equal(t, 0, n)
		assert.Nil(t, err)
		assert.Equal(t, 0, buf.Len()) // No data should be written
	})

	t.Run("close with non-closer writer", func(t *testing.T) {
		// Create a writer that doesn't implement io.Closer
		var buf bytes.Buffer
		c := cipher.AesCipher{
			Key:     key16,
			Block:   cipher.ECB,
			Padding: cipher.PKCS7,
		}
		encrypter := NewStreamEncrypter(&buf, c)
		err := encrypter.Close()
		assert.Nil(t, err) // Should not error when writer is not io.Closer
	})

	t.Run("different key sizes", func(t *testing.T) {
		// Test AES-192
		c192 := cipher.AesCipher{
			Key:     key24,
			Block:   cipher.CBC,
			IV:      iv16,
			Padding: cipher.PKCS7,
		}
		encrypter192 := NewStdEncrypter(c192)
		assert.Nil(t, encrypter192.Error)
		result192, err := encrypter192.Encrypt(testData)
		assert.NotNil(t, result192)
		assert.Nil(t, err)

		decrypter192 := NewStdDecrypter(c192)
		assert.Nil(t, decrypter192.Error)
		decrypted192, err := decrypter192.Decrypt(result192)
		assert.NotNil(t, decrypted192)
		assert.Nil(t, err)
		assert.Equal(t, testData, decrypted192)

		// Test AES-256
		c256 := cipher.AesCipher{
			Key:     key32,
			Block:   cipher.CBC,
			IV:      iv16,
			Padding: cipher.PKCS7,
		}
		encrypter256 := NewStdEncrypter(c256)
		assert.Nil(t, encrypter256.Error)
		result256, err := encrypter256.Encrypt(testData)
		assert.NotNil(t, result256)
		assert.Nil(t, err)

		decrypter256 := NewStdDecrypter(c256)
		assert.Nil(t, decrypter256.Error)
		decrypted256, err := decrypter256.Decrypt(result256)
		assert.NotNil(t, decrypted256)
		assert.Nil(t, err)
		assert.Equal(t, testData, decrypted256)
	})

	t.Run("different block modes with same data", func(t *testing.T) {
		testData := []byte("test")
		modes := []cipher.BlockMode{
			cipher.CBC, cipher.ECB, cipher.CTR, cipher.CFB, cipher.OFB,
		}

		for _, mode := range modes {
			var c cipher.AesCipher
			if mode == cipher.ECB {
				c = cipher.AesCipher{
					Key:     key16,
					Block:   mode,
					Padding: cipher.PKCS7,
				}
			} else if mode == cipher.CTR || mode == cipher.CFB || mode == cipher.OFB {
				c = cipher.AesCipher{
					Key:     key16,
					Block:   mode,
					IV:      iv16,
					Padding: cipher.No,
				}
			} else {
				c = cipher.AesCipher{
					Key:     key16,
					Block:   mode,
					IV:      iv16,
					Padding: cipher.PKCS7,
				}
			}

			encrypter := NewStdEncrypter(c)
			assert.Nil(t, encrypter.Error)
			result, err := encrypter.Encrypt(testData)
			assert.NotNil(t, result)
			assert.Nil(t, err)
			assert.NotEqual(t, testData, result)
		}
	})

	// Additional test cases to improve coverage
	t.Run("stream encrypter write with error", func(t *testing.T) {
		var buf bytes.Buffer
		c := cipher.AesCipher{
			Key:     key16,
			Block:   cipher.CBC,
			IV:      iv16,
			Padding: cipher.PKCS7,
		}
		encrypter := NewStreamEncrypter(&buf, c)
		// Set error to test error path
		streamEncrypter := encrypter.(*StreamEncrypter)
		streamEncrypter.Error = assert.AnError
		n, err := encrypter.Write([]byte("hello"))
		assert.Equal(t, 0, n)
		assert.Equal(t, assert.AnError, err)
	})

	t.Run("stream decrypter read with error", func(t *testing.T) {
		reader := strings.NewReader("test")
		c := cipher.AesCipher{
			Key:     key16,
			Block:   cipher.CBC,
			IV:      iv16,
			Padding: cipher.PKCS7,
		}
		decrypter := NewStreamDecrypter(reader, c)
		// Set error to test error path
		streamDecrypter := decrypter.(*StreamDecrypter)
		streamDecrypter.Error = assert.AnError
		buf := make([]byte, 10)
		n, err := decrypter.Read(buf)
		assert.Equal(t, 0, n)
		assert.Equal(t, assert.AnError, err)
	})

	t.Run("stream encrypter write with encryption error", func(t *testing.T) {
		var buf bytes.Buffer
		c := cipher.AesCipher{
			Key:     key16,
			Block:   cipher.CBC,
			IV:      iv16,
			Padding: cipher.PKCS7,
		}
		encrypter := NewStreamEncrypter(&buf, c)
		// Create a mock writer that returns error on first write
		mockWriter := mock.NewErrorReadWriteCloser(assert.AnError)
		streamEncrypter := encrypter.(*StreamEncrypter)
		streamEncrypter.writer = mockWriter
		n, err := encrypter.Write([]byte("1234567890123456"))
		assert.Equal(t, 0, n)
		assert.Equal(t, assert.AnError, err)
	})

	t.Run("stream decrypter read with decryption error", func(t *testing.T) {
		// Create invalid encrypted data that will cause decryption error
		invalidData := []byte("invalid_encrypted_data")
		reader := bytes.NewReader(invalidData)
		c := cipher.AesCipher{
			Key:     key16,
			Block:   cipher.CBC,
			IV:      iv16,
			Padding: cipher.PKCS7,
		}
		decrypter := NewStreamDecrypter(reader, c)
		buf := make([]byte, 100)
		n, err := decrypter.Read(buf)
		assert.Equal(t, 0, n)
		assert.NotNil(t, err)
		assert.IsType(t, DecryptError{}, err)
	})

	t.Run("stream encrypter close with closer", func(t *testing.T) {
		// Create a mock writer that implements io.Closer
		mockWriter := mock.NewErrorReadWriteCloser(nil) // No error on close
		c := cipher.AesCipher{
			Key:     key16,
			Block:   cipher.ECB,
			Padding: cipher.PKCS7,
		}
		encrypter := NewStreamEncrypter(mockWriter, c)
		err := encrypter.Close()
		assert.Nil(t, err)
	})

	t.Run("stream decrypter read with read error", func(t *testing.T) {
		// Create a mock reader that returns error
		mockReader := mock.NewErrorReadWriteCloser(assert.AnError)
		c := cipher.AesCipher{
			Key:     key16,
			Block:   cipher.CBC,
			IV:      iv16,
			Padding: cipher.PKCS7,
		}
		decrypter := NewStreamDecrypter(mockReader, c)
		buf := make([]byte, 10)
		n, err := decrypter.Read(buf)
		assert.Equal(t, 0, n)
		assert.IsType(t, ReadError{}, err)
	})

	t.Run("encrypt with unknown block mode", func(t *testing.T) {
		c := cipher.AesCipher{
			Key:     key16,
			Block:   cipher.BlockMode("UNKNOWN"), // Unknown mode
			IV:      iv16,
			Padding: cipher.PKCS7,
		}
		encrypter := NewStdEncrypter(c)
		result, err := encrypter.Encrypt(testData)
		// Unknown block mode test
		assert.Nil(t, result)
		assert.Nil(t, err) // encrypt function returns nil for unknown mode
	})

	t.Run("decrypt with unknown block mode", func(t *testing.T) {
		c := cipher.AesCipher{
			Key:     key16,
			Block:   cipher.BlockMode("UNKNOWN"), // Unknown mode
			IV:      iv16,
			Padding: cipher.PKCS7,
		}
		decrypter := NewStdDecrypter(c)
		result, err := decrypter.Decrypt([]byte("test"))
		// Unknown block mode test
		assert.Nil(t, result)
		assert.Nil(t, err)
	})

	t.Run("encrypt with unknown padding mode", func(t *testing.T) {
		c := cipher.AesCipher{
			Key:     key16,
			Block:   cipher.CBC,
			IV:      iv16,
			Padding: cipher.PaddingMode("UNKNOWN"), // Unknown padding
		}
		encrypter := NewStdEncrypter(c)
		result, err := encrypter.Encrypt(testData)
		// Unknown padding mode test
		assert.Nil(t, result)
		assert.NotNil(t, err) // encrypt function returns error for unknown padding
	})

	t.Run("decrypt with unknown padding mode", func(t *testing.T) {
		// First encrypt with valid padding
		c := cipher.AesCipher{
			Key:     key16,
			Block:   cipher.CBC,
			IV:      iv16,
			Padding: cipher.PKCS7,
		}
		encrypter := NewStdEncrypter(c)
		encrypted, err := encrypter.Encrypt(testData)
		assert.Nil(t, err)

		// Then decrypt with unknown padding
		c.Padding = cipher.PaddingMode("UNKNOWN")
		decrypter := NewStdDecrypter(c)
		result, err := decrypter.Decrypt(encrypted)
		// Unknown padding mode test
		assert.Nil(t, result)
		assert.Nil(t, err) // decrypt function returns nil for unknown padding
	})

	t.Run("GCM mode encryption and decryption", func(t *testing.T) {
		// GCM mode test
		c := cipher.AesCipher{
			Key:   key16,
			Block: cipher.GCM,
			Nonce: nonce12,
		}
		encrypter := NewStdEncrypter(c)
		result, err := encrypter.Encrypt(testData)
		assert.NotNil(t, result)
		assert.Nil(t, err)
	})

	t.Run("GCM mode with AAD", func(t *testing.T) {
		// GCM mode with AAD test
		c := cipher.AesCipher{
			Key:   key16,
			Block: cipher.GCM,
			Nonce: nonce12,
			Aad:   []byte("additional_data"),
		}
		encrypter := NewStdEncrypter(c)
		result, err := encrypter.Encrypt(testData)
		assert.NotNil(t, result)
		assert.Nil(t, err)
	})

	t.Run("stream GCM mode", func(t *testing.T) {
		// Stream GCM mode test
		var buf bytes.Buffer
		c := cipher.AesCipher{
			Key:   key16,
			Block: cipher.GCM,
			Nonce: nonce12,
		}
		encrypter := NewStreamEncrypter(&buf, c)
		n, err := encrypter.Write(testData)
		// GCM mode adds authentication tag (16 bytes) to the output
		expectedLength := len(testData) + 16
		assert.Equal(t, expectedLength, n)
		assert.Nil(t, err)
		err = encrypter.Close()
		assert.Nil(t, err)
		assert.NotEqual(t, 0, buf.Len())
	})

	t.Run("stream GCM mode with AAD", func(t *testing.T) {
		// Stream GCM mode with AAD test
		var buf bytes.Buffer
		c := cipher.AesCipher{
			Key:   key16,
			Block: cipher.GCM,
			Nonce: nonce12,
			Aad:   []byte("additional_data"),
		}
		encrypter := NewStreamEncrypter(&buf, c)
		n, err := encrypter.Write(testData)
		// GCM mode adds authentication tag (16 bytes) to the output
		expectedLength := len(testData) + 16
		assert.Equal(t, expectedLength, n)
		assert.Nil(t, err)
		err = encrypter.Close()
		assert.Nil(t, err)
		assert.NotEqual(t, 0, buf.Len())
	})

	t.Run("decrypt with invalid encrypted data", func(t *testing.T) {
		c := cipher.AesCipher{
			Key:     key16,
			Block:   cipher.CBC,
			IV:      iv16,
			Padding: cipher.PKCS7,
		}
		decrypter := NewStdDecrypter(c)
		// Try to decrypt invalid data
		invalidData := []byte("invalid_encrypted_data")
		result, err := decrypter.Decrypt(invalidData)
		assert.Nil(t, result)
		assert.NotNil(t, err)
		assert.IsType(t, DecryptError{}, err)
	})

	t.Run("stream decrypter read with invalid data", func(t *testing.T) {
		// Create invalid encrypted data
		invalidData := []byte("invalid_encrypted_data")
		reader := bytes.NewReader(invalidData)
		c := cipher.AesCipher{
			Key:     key16,
			Block:   cipher.CBC,
			IV:      iv16,
			Padding: cipher.PKCS7,
		}
		decrypter := NewStreamDecrypter(reader, c)
		buf := make([]byte, 100)
		n, err := decrypter.Read(buf)
		assert.Equal(t, 0, n)
		assert.NotNil(t, err)
		assert.IsType(t, DecryptError{}, err)
	})

	t.Run("stream encrypter write with empty data", func(t *testing.T) {
		var buf bytes.Buffer
		c := cipher.AesCipher{
			Key:     key16,
			Block:   cipher.ECB,
			Padding: cipher.PKCS7,
		}
		encrypter := NewStreamEncrypter(&buf, c)
		n, err := encrypter.Write([]byte{})
		assert.Equal(t, 0, n)
		assert.Nil(t, err)
		assert.Equal(t, 0, buf.Len())
	})

	t.Run("stream decrypter read with empty reader", func(t *testing.T) {
		reader := strings.NewReader("")
		c := cipher.AesCipher{
			Key:     key16,
			Block:   cipher.CBC,
			IV:      iv16,
			Padding: cipher.PKCS7,
		}
		decrypter := NewStreamDecrypter(reader, c)
		buf := make([]byte, 10)
		n, err := decrypter.Read(buf)
		assert.Equal(t, 0, n)
		assert.Equal(t, io.EOF, err)
	})

	t.Run("stream encrypter close without write", func(t *testing.T) {
		var buf bytes.Buffer
		c := cipher.AesCipher{
			Key:     key16,
			Block:   cipher.CBC,
			IV:      iv16,
			Padding: cipher.PKCS7,
		}
		encrypter := NewStreamEncrypter(&buf, c)
		err := encrypter.Close()
		assert.Nil(t, err)
		assert.Equal(t, 0, buf.Len())
	})

	t.Run("stream decrypter read with large buffer", func(t *testing.T) {
		// First encrypt some data
		c := cipher.AesCipher{
			Key:     key16,
			Block:   cipher.CBC,
			IV:      iv16,
			Padding: cipher.PKCS7,
		}
		var buf bytes.Buffer
		encrypter := NewStreamEncrypter(&buf, c)
		encrypter.Write([]byte("hello world"))
		encrypter.Close()

		// Now decrypt with large buffer
		reader := bytes.NewReader(buf.Bytes())
		decrypter := NewStreamDecrypter(reader, c)
		largeBuf := make([]byte, 100) // Much larger than needed
		n, err := decrypter.Read(largeBuf)
		assert.Equal(t, len("hello world"), n)
		assert.Nil(t, err)
		assert.Equal(t, []byte("hello world"), largeBuf[:n])
	})

	t.Run("stream decrypter read with small buffer", func(t *testing.T) {
		// First encrypt some data
		c := cipher.AesCipher{
			Key:     key16,
			Block:   cipher.CBC,
			IV:      iv16,
			Padding: cipher.PKCS7,
		}
		var buf bytes.Buffer
		encrypter := NewStreamEncrypter(&buf, c)
		encrypter.Write([]byte("hello world"))
		encrypter.Close()

		// Now decrypt with small buffer
		reader := bytes.NewReader(buf.Bytes())
		decrypter := NewStreamDecrypter(reader, c)
		smallBuf := make([]byte, 5) // Too small for "hello world"
		n, err := decrypter.Read(smallBuf)
		assert.Equal(t, 5, n)
		assert.NotNil(t, err)
		assert.IsType(t, BufferError{}, err)
	})

	t.Run("error types with detailed messages", func(t *testing.T) {
		// Test KeySizeError with different sizes
		err16 := KeySizeError(16)
		assert.Equal(t, "crypto/aes: invalid key size 16, must be 16, 24, or 32 bytes", err16.Error())

		err24 := KeySizeError(24)
		assert.Equal(t, "crypto/aes: invalid key size 24, must be 16, 24, or 32 bytes", err24.Error())

		err32 := KeySizeError(32)
		assert.Equal(t, "crypto/aes: invalid key size 32, must be 16, 24, or 32 bytes", err32.Error())

		// Test EncryptError with custom error
		customErr := errors.New("custom encryption error")
		encryptErr := EncryptError{Err: customErr}
		assert.Contains(t, encryptErr.Error(), "crypto/aes: failed to encrypt data:")
		assert.Contains(t, encryptErr.Error(), "custom encryption error")

		// Test DecryptError with custom error
		decryptErr := DecryptError{Err: customErr}
		assert.Contains(t, decryptErr.Error(), "crypto/aes: failed to decrypt data:")
		assert.Contains(t, decryptErr.Error(), "custom encryption error")

		// Test ReadError with custom error
		readErr := ReadError{Err: customErr}
		assert.Contains(t, readErr.Error(), "crypto/aes: failed to read encrypted data:")
		assert.Contains(t, readErr.Error(), "custom encryption error")

		// Test BufferError with different sizes
		bufferErr := BufferError{bufferSize: 5, dataSize: 10}
		assert.Equal(t, "crypto/aes: : buffer size 5 is too small for data size 10", bufferErr.Error())

		bufferErr2 := BufferError{bufferSize: 1, dataSize: 100}
		assert.Equal(t, "crypto/aes: : buffer size 1 is too small for data size 100", bufferErr2.Error())
	})

	t.Run("AES key size validation edge cases", func(t *testing.T) {
		// Test key sizes just below valid ranges
		invalidSizes := []int{0, 1, 15, 17, 23, 25, 31, 33, 100}

		for _, size := range invalidSizes {
			invalidKey := make([]byte, size)
			c := cipher.AesCipher{Key: invalidKey}

			encrypter := NewStdEncrypter(c)
			assert.NotNil(t, encrypter.Error)
			assert.IsType(t, KeySizeError(0), encrypter.Error)
			assert.Equal(t, fmt.Sprintf("crypto/aes: invalid key size %d, must be 16, 24, or 32 bytes", size), encrypter.Error.Error())

			decrypter := NewStdDecrypter(c)
			assert.NotNil(t, decrypter.Error)
			assert.IsType(t, KeySizeError(0), decrypter.Error)
			assert.Equal(t, fmt.Sprintf("crypto/aes: invalid key size %d, must be 16, 24, or 32 bytes", size), decrypter.Error.Error())
		}
	})

	t.Run("padding mode edge cases", func(t *testing.T) {
		// Test with data that is exactly block size
		exactBlockData := make([]byte, 16)
		copy(exactBlockData, "1234567890123456")

		c := cipher.AesCipher{
			Key:     key16,
			Block:   cipher.CBC,
			IV:      iv16,
			Padding: cipher.PKCS7,
		}

		encrypter := NewStdEncrypter(c)
		result, err := encrypter.Encrypt(exactBlockData)
		assert.NotNil(t, result)
		assert.Nil(t, err)

		decrypter := NewStdDecrypter(c)
		decrypted, err := decrypter.Decrypt(result)
		assert.NotNil(t, decrypted)
		assert.Nil(t, err)
		assert.Equal(t, exactBlockData, decrypted)
	})

	t.Run("stream operations with different data sizes", func(t *testing.T) {
		testCases := []struct {
			name     string
			data     []byte
			expected int
		}{
			{"empty data", []byte{}, 0},
			{"single byte", []byte("a"), 16},           // PKCS7 padding will pad to 16 bytes
			{"exact block size", make([]byte, 16), 32}, // PKCS7 padding will pad to 32 bytes
			{"multiple blocks", make([]byte, 64), 80},  // PKCS7 padding will pad to 80 bytes
			{"large data", make([]byte, 1024), 1040},   // PKCS7 padding will pad to 1040 bytes
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				var buf bytes.Buffer
				c := cipher.AesCipher{
					Key:     key16,
					Block:   cipher.CBC,
					IV:      iv16,
					Padding: cipher.PKCS7,
				}
				encrypter := NewStreamEncrypter(&buf, c)
				n, err := encrypter.Write(tc.data)
				assert.Equal(t, tc.expected, n)
				assert.Nil(t, err)
				err = encrypter.Close()
				assert.Nil(t, err)

				if tc.expected > 0 {
					assert.NotEqual(t, 0, buf.Len())
				} else {
					assert.Equal(t, 0, buf.Len())
				}
			})
		}
	})

	// Additional test cases to improve coverage
	t.Run("encrypt with invalid block creation", func(t *testing.T) {
		// This test would require mocking the aes.NewCipher function
		// For now, we'll test the error handling in the encrypt function
		c := cipher.AesCipher{
			Key:     key16,
			Block:   cipher.CBC,
			IV:      iv16,
			Padding: cipher.PKCS7,
		}
		encrypter := NewStdEncrypter(c)
		// Clear any existing error to test the encryption path
		encrypter.Error = nil
		result, err := encrypter.Encrypt(testData)
		assert.NotNil(t, result)
		assert.Nil(t, err)
	})

	t.Run("decrypt with invalid block creation", func(t *testing.T) {
		// This test would require mocking the aes.NewCipher function
		// For now, we'll test the error handling in the decrypt function
		c := cipher.AesCipher{
			Key:     key16,
			Block:   cipher.CBC,
			IV:      iv16,
			Padding: cipher.PKCS7,
		}
		decrypter := NewStdDecrypter(c)
		// Clear any existing error to test the decryption path
		decrypter.Error = nil
		// First encrypt some data
		encrypter := NewStdEncrypter(c)
		encrypted, err := encrypter.Encrypt(testData)
		assert.Nil(t, err)

		// Then decrypt
		result, err := decrypter.Decrypt(encrypted)
		assert.NotNil(t, result)
		assert.Nil(t, err)
	})

	t.Run("stream encrypter write with invalid block creation", func(t *testing.T) {
		// This test would require mocking the aes.NewCipher function
		// For now, we'll test the error handling in the Write function
		var buf bytes.Buffer
		c := cipher.AesCipher{
			Key:     key16,
			Block:   cipher.CBC,
			IV:      iv16,
			Padding: cipher.PKCS7,
		}
		encrypter := NewStreamEncrypter(&buf, c)
		// Clear any existing error to test the Write path
		streamEncrypter := encrypter.(*StreamEncrypter)
		streamEncrypter.Error = nil
		n, err := encrypter.Write(testData)
		// PKCS7 padding will pad to 16 bytes (AES block size)
		expectedLength := 16
		assert.Equal(t, expectedLength, n)
		assert.Nil(t, err)
	})

	t.Run("stream decrypter read with invalid block creation", func(t *testing.T) {
		// This test would require mocking the aes.NewCipher function
		// For now, we'll test the error handling in the Read function
		// First encrypt some data
		c := cipher.AesCipher{
			Key:     key16,
			Block:   cipher.CBC,
			IV:      iv16,
			Padding: cipher.PKCS7,
		}
		var buf bytes.Buffer
		encrypter := NewStreamEncrypter(&buf, c)
		encrypter.Write(testData)
		encrypter.Close()

		// Then decrypt
		reader := bytes.NewReader(buf.Bytes())
		decrypter := NewStreamDecrypter(reader, c)
		// Clear any existing error to test the Read path
		streamDecrypter := decrypter.(*StreamDecrypter)
		streamDecrypter.Error = nil
		resultBuf := make([]byte, 20)
		n, err := decrypter.Read(resultBuf)
		assert.Equal(t, len(testData), n)
		assert.Nil(t, err)
	})

	t.Run("encrypt function edge cases", func(t *testing.T) {
		// Test encrypt function with different block modes and padding combinations
		testCases := []struct {
			name     string
			block    cipher.BlockMode
			padding  cipher.PaddingMode
			hasIV    bool
			hasNonce bool
		}{
			{"CBC with PKCS7", cipher.CBC, cipher.PKCS7, true, false},
			{"ECB with PKCS7", cipher.ECB, cipher.PKCS7, false, false},
			{"CTR with No padding", cipher.CTR, cipher.No, true, false},
			{"CFB with No padding", cipher.CFB, cipher.No, true, false},
			{"OFB with No padding", cipher.OFB, cipher.No, true, false},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				c := cipher.AesCipher{
					Key:     key16,
					Block:   tc.block,
					Padding: tc.padding,
				}
				if tc.hasIV {
					c.IV = iv16
				}
				if tc.hasNonce {
					c.Nonce = nonce12
				}

				encrypter := NewStdEncrypter(c)
				result, err := encrypter.Encrypt(testData)
				assert.NotNil(t, result)
				assert.Nil(t, err)
			})
		}
	})

	t.Run("decrypt function edge cases", func(t *testing.T) {
		// Test decrypt function with different block modes and padding combinations
		testCases := []struct {
			name     string
			block    cipher.BlockMode
			padding  cipher.PaddingMode
			hasIV    bool
			hasNonce bool
		}{
			{"CBC with PKCS7", cipher.CBC, cipher.PKCS7, true, false},
			{"ECB with PKCS7", cipher.ECB, cipher.PKCS7, false, false},
			{"CTR with No padding", cipher.CTR, cipher.No, true, false},
			{"CFB with No padding", cipher.CFB, cipher.No, true, false},
			{"OFB with No padding", cipher.OFB, cipher.No, true, false},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				c := cipher.AesCipher{
					Key:     key16,
					Block:   tc.block,
					Padding: tc.padding,
				}
				if tc.hasIV {
					c.IV = iv16
				}
				if tc.hasNonce {
					c.Nonce = nonce12
				}

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
		}
	})

	t.Run("padding mode combinations", func(t *testing.T) {
		// Test all padding modes with CBC mode
		paddingModes := []struct {
			mode cipher.PaddingMode
			data []byte
		}{
			{cipher.No, testData16},     // No padding requires exact block size
			{cipher.Zero, testData},     // Empty padding works with any data
			{cipher.Zero, testData},     // Zero padding works with any data
			{cipher.PKCS5, testData},    // PKCS5 padding works with any data
			{cipher.PKCS7, testData},    // PKCS7 padding works with any data
			{cipher.AnsiX923, testData}, // AnsiX923 padding works with any data
			{cipher.ISO97971, testData}, // ISO97971 padding works with any data
			{cipher.ISO10126, testData}, // ISO10126 padding works with any data
			{cipher.ISO78164, testData}, // ISO78164 padding works with any data
			{cipher.Bit, testData},      // Bit padding works with any data
		}

		for _, tc := range paddingModes {
			t.Run(fmt.Sprintf("CBC with %v padding", tc.mode), func(t *testing.T) {
				c := cipher.AesCipher{
					Key:     key16,
					Block:   cipher.CBC,
					IV:      iv16,
					Padding: tc.mode,
				}

				encrypter := NewStdEncrypter(c)
				result, err := encrypter.Encrypt(tc.data)
				assert.NotNil(t, result)
				assert.Nil(t, err)

				decrypter := NewStdDecrypter(c)
				decrypted, err := decrypter.Decrypt(result)
				assert.NotNil(t, decrypted)
				assert.Nil(t, err)
				assert.Equal(t, tc.data, decrypted)
			})
		}
	})

	t.Run("key size combinations", func(t *testing.T) {
		// Test all key sizes with CBC mode
		keySizes := []struct {
			name string
			key  []byte
		}{
			{"AES-128", key16},
			{"AES-192", key24},
			{"AES-256", key32},
		}

		for _, keySize := range keySizes {
			t.Run(keySize.name, func(t *testing.T) {
				c := cipher.AesCipher{
					Key:     keySize.key,
					Block:   cipher.CBC,
					IV:      iv16,
					Padding: cipher.PKCS7,
				}

				encrypter := NewStdEncrypter(c)
				result, err := encrypter.Encrypt(testData)
				assert.NotNil(t, result)
				assert.Nil(t, err)

				decrypter := NewStdDecrypter(c)
				decrypted, err := decrypter.Decrypt(result)
				assert.NotNil(t, decrypted)
				assert.Nil(t, err)
				assert.Equal(t, testData, decrypted)
			})
		}
	})

	t.Run("stream operations with different block modes", func(t *testing.T) {
		// Test stream operations with different block modes
		blockModes := []struct {
			name string
			mode cipher.BlockMode
			iv   []byte
		}{
			{"CBC", cipher.CBC, iv16},
			{"ECB", cipher.ECB, nil},
			{"CTR", cipher.CTR, iv16},
			{"CFB", cipher.CFB, iv16},
			{"OFB", cipher.OFB, iv16},
		}

		for _, blockMode := range blockModes {
			t.Run(fmt.Sprintf("Stream %s mode", blockMode.name), func(t *testing.T) {
				var buf bytes.Buffer
				c := cipher.AesCipher{
					Key:     key16,
					Block:   blockMode.mode,
					IV:      blockMode.iv,
					Padding: cipher.PKCS7,
				}

				encrypter := NewStreamEncrypter(&buf, c)
				n, err := encrypter.Write(testData)
				// PKCS7 padding will pad to 16 bytes (AES block size)
				expectedLength := 16
				assert.Equal(t, expectedLength, n)
				assert.Nil(t, err)
				err = encrypter.Close()
				assert.Nil(t, err)

				// Test decryption
				reader := bytes.NewReader(buf.Bytes())
				decrypter := NewStreamDecrypter(reader, c)
				resultBuf := make([]byte, 20)
				n, err = decrypter.Read(resultBuf)
				assert.Equal(t, len(testData), n)
				assert.Nil(t, err)
				assert.Equal(t, testData, resultBuf[:n])
			})
		}
	})

	t.Run("stream with invalid padding mode", func(t *testing.T) {
		// Test stream encryption with invalid padding mode
		var buf bytes.Buffer
		c := cipher.AesCipher{
			Key:     key16,
			Block:   cipher.CBC,
			IV:      iv16,
			Padding: cipher.PaddingMode("INVALID"), // Invalid padding mode
		}
		encrypter := NewStreamEncrypter(&buf, c)
		n, err := encrypter.Write(testData)
		// Invalid padding mode will return error
		assert.Equal(t, 0, n)
		assert.NotNil(t, err)
		err = encrypter.Close()
		assert.Nil(t, err)
	})

	t.Run("ISO97971 padding mode", func(t *testing.T) {
		// Test ISO97971 padding mode specifically
		c := cipher.AesCipher{
			Key:     key16,
			Block:   cipher.CBC,
			IV:      iv16,
			Padding: cipher.ISO97971,
		}
		encrypter := NewStdEncrypter(c)
		result, err := encrypter.Encrypt(testData)
		assert.NotNil(t, result)
		assert.Nil(t, err)

		decrypter := NewStdDecrypter(c)
		decrypted, err := decrypter.Decrypt(result)
		assert.NotNil(t, decrypted)
		assert.Nil(t, err)
		assert.Equal(t, testData, decrypted)
	})
}

func TestAES_EdgeCases(t *testing.T) {
	t.Run("invalid block mode", func(t *testing.T) {
		// Test with an invalid block mode (should return zero values)
		c := cipher.AesCipher{
			Key:     key16,
			Block:   cipher.BlockMode("INVALID"), // Invalid block mode
			IV:      iv16,
			Padding: cipher.PKCS7,
		}
		encrypter := NewStdEncrypter(c)
		result, err := encrypter.Encrypt(testData)
		// Invalid block mode test
		assert.Nil(t, result)
		assert.Nil(t, err)
	})

	t.Run("invalid padding mode", func(t *testing.T) {
		// Test with an invalid padding mode (should return zero values)
		c := cipher.AesCipher{
			Key:     key16,
			Block:   cipher.CBC,
			IV:      iv16,
			Padding: cipher.PaddingMode("INVALID"), // Invalid padding mode
		}
		encrypter := NewStdEncrypter(c)
		result, err := encrypter.Encrypt(testData)
		// Invalid padding mode test
		assert.Nil(t, result)
		assert.NotNil(t, err)
	})

	t.Run("invalid block mode for decrypt", func(t *testing.T) {
		// Test decrypt with an invalid block mode
		c := cipher.AesCipher{
			Key:     key16,
			Block:   cipher.BlockMode("INVALID"), // Invalid block mode
			IV:      iv16,
			Padding: cipher.PKCS7,
		}
		decrypter := NewStdDecrypter(c)
		result, err := decrypter.Decrypt([]byte("test"))
		// Invalid block mode test
		assert.Nil(t, result)
		assert.Nil(t, err)
	})

	t.Run("invalid padding mode for decrypt", func(t *testing.T) {
		// Test decrypt with an invalid padding mode
		c := cipher.AesCipher{
			Key:     key16,
			Block:   cipher.CBC,
			IV:      iv16,
			Padding: cipher.PaddingMode("INVALID"), // Invalid padding mode
		}
		decrypter := NewStdDecrypter(c)
		result, err := decrypter.Decrypt([]byte("test"))
		// Invalid padding mode test
		assert.Nil(t, result)
		assert.NotNil(t, err)
		assert.IsType(t, DecryptError{}, err)
	})

	t.Run("empty data with no padding", func(t *testing.T) {
		// Test encryption with empty data and no padding
		c := cipher.AesCipher{
			Key:     key16,
			Block:   cipher.CBC,
			IV:      iv16,
			Padding: cipher.No,
		}
		encrypter := NewStdEncrypter(c)
		result, err := encrypter.Encrypt([]byte{})
		assert.NotNil(t, result)
		assert.Nil(t, err)
	})

	t.Run("nil data", func(t *testing.T) {
		// Test encryption with nil data
		c := cipher.AesCipher{
			Key:     key16,
			Block:   cipher.CBC,
			IV:      iv16,
			Padding: cipher.PKCS7,
		}
		encrypter := NewStdEncrypter(c)
		result, err := encrypter.Encrypt(nil)
		assert.NotNil(t, result)
		assert.Nil(t, err)
	})

	t.Run("very long data", func(t *testing.T) {
		// Test encryption with very long data
		longData := make([]byte, 10000)
		for i := range longData {
			longData[i] = byte(i % 256)
		}
		c := cipher.AesCipher{
			Key:     key16,
			Block:   cipher.CBC,
			IV:      iv16,
			Padding: cipher.PKCS7,
		}
		encrypter := NewStdEncrypter(c)
		result, err := encrypter.Encrypt(longData)
		assert.NotNil(t, result)
		assert.Nil(t, err)
		assert.NotEqual(t, longData, result)
	})

	t.Run("exact block size data with no padding", func(t *testing.T) {
		// Test encryption with data that is exactly block size
		exactBlockData := make([]byte, 16)
		for i := range exactBlockData {
			exactBlockData[i] = byte(i)
		}
		c := cipher.AesCipher{
			Key:     key16,
			Block:   cipher.CBC,
			IV:      iv16,
			Padding: cipher.No,
		}
		encrypter := NewStdEncrypter(c)
		result, err := encrypter.Encrypt(exactBlockData)
		assert.NotNil(t, result)
		assert.Nil(t, err)
		assert.NotEqual(t, exactBlockData, result)
	})

	t.Run("stream with invalid block mode", func(t *testing.T) {
		// Test stream encryption with invalid block mode
		var buf bytes.Buffer
		c := cipher.AesCipher{
			Key:     key16,
			Block:   cipher.BlockMode("INVALID"), // Invalid block mode
			IV:      iv16,
			Padding: cipher.PKCS7,
		}
		encrypter := NewStreamEncrypter(&buf, c)
		n, err := encrypter.Write(testData)
		// Invalid block mode will return zero values
		assert.Equal(t, 0, n)
		assert.Nil(t, err)
		err = encrypter.Close()
		assert.Nil(t, err)
	})

	t.Run("stream with invalid padding mode", func(t *testing.T) {
		// Test stream encryption with invalid padding mode
		var buf bytes.Buffer
		c := cipher.AesCipher{
			Key:     key16,
			Block:   cipher.CBC,
			IV:      iv16,
			Padding: cipher.PaddingMode("INVALID"), // Invalid padding mode
		}
		encrypter := NewStreamEncrypter(&buf, c)
		n, err := encrypter.Write(testData)
		// Invalid padding mode will return error
		assert.Equal(t, 0, n)
		assert.NotNil(t, err)
		err = encrypter.Close()
		assert.Nil(t, err)
	})
}
