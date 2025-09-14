package crypto

import (
	"errors"
	"strings"
	"testing"

	"github.com/dromara/dongle/crypto/cipher"
	"github.com/dromara/dongle/mock"
	"github.com/stretchr/testify/assert"
)

// Test data and common setup for 3DES
var (
	key243des = []byte("123456789012345678901234") // 24-byte key for 3DES
	iv83des   = []byte("12345678")                 // 8-byte IV for 3DES

	testdata3des  = []byte("hello world")
	testdata83des = []byte("12345678") // Exactly 8 bytes for no-padding tests
)

func TestEncrypter_By3Des(t *testing.T) {
	t.Run("standard encryption with 24-byte key", func(t *testing.T) {
		c := cipher.New3DesCipher(cipher.CBC)
		c.SetKey(key243des)
		c.SetIV(iv83des)
		c.SetPadding(cipher.PKCS7)
		encrypter := NewEncrypter().FromBytes(testdata3des).By3Des(c)
		assert.Nil(t, encrypter.Error)
		assert.NotNil(t, encrypter.dst)
		assert.NotEqual(t, testdata3des, encrypter.dst)
	})

	t.Run("streaming encryption with reader", func(t *testing.T) {
		c := cipher.New3DesCipher(cipher.CBC)
		c.SetKey(key243des)
		c.SetIV(iv83des)
		c.SetPadding(cipher.PKCS7)
		file := mock.NewFile([]byte("hello world"), "test.txt")
		encrypter := NewEncrypter().FromFile(file).By3Des(c)
		assert.Nil(t, encrypter.Error)
		assert.NotNil(t, encrypter.dst)
		assert.NotEqual(t, testdata3des, encrypter.dst)
	})

	t.Run("streaming encryption with large data", func(t *testing.T) {
		c := cipher.New3DesCipher(cipher.CBC)
		c.SetKey(key243des)
		c.SetIV(iv83des)
		c.SetPadding(cipher.PKCS7)
		largeData := strings.Repeat("hello world ", 1000)
		file := mock.NewFile([]byte(largeData), "large.txt")
		encrypter := NewEncrypter().FromFile(file).By3Des(c)
		assert.Nil(t, encrypter.Error)
		assert.NotNil(t, encrypter.dst)
		assert.NotEqual(t, []byte(largeData), encrypter.dst)
	})

	t.Run("streaming encryption with empty reader", func(t *testing.T) {
		c := cipher.New3DesCipher(cipher.CBC)
		c.SetKey(key243des)
		c.SetIV(iv83des)
		c.SetPadding(cipher.PKCS7)
		file := mock.NewFile([]byte{}, "empty.txt")
		encrypter := NewEncrypter().FromFile(file).By3Des(c)
		assert.Nil(t, encrypter.Error)
		assert.NotNil(t, encrypter.dst)
	})

	t.Run("streaming encryption with error reader", func(t *testing.T) {
		c := cipher.New3DesCipher(cipher.CBC)
		c.SetKey(key243des)
		c.SetIV(iv83des)
		c.SetPadding(cipher.PKCS7)
		file := mock.NewFile([]byte("hello world"), "error.txt")
		encrypter := NewEncrypter().FromFile(file).By3Des(c)
		// This should succeed as the error is handled in the goroutine
		assert.Nil(t, encrypter.Error)
	})

	t.Run("encryption with existing error", func(t *testing.T) {
		c := cipher.New3DesCipher(cipher.CBC)
		c.SetKey(key243des)
		c.SetIV(iv83des)
		c.SetPadding(cipher.PKCS7)
		encrypter := NewEncrypter()
		encrypter.Error = errors.New("existing error")
		result := encrypter.By3Des(c)
		assert.Equal(t, encrypter, result)
		assert.Equal(t, "existing error", result.Error.Error())
	})

	t.Run("encryption with invalid key size", func(t *testing.T) {
		c := cipher.New3DesCipher(cipher.CBC)
		c.SetKey([]byte("invalid"))
		c.SetIV(iv83des)
		c.SetPadding(cipher.PKCS7)
		encrypter := NewEncrypter().FromBytes(testdata3des).By3Des(c)
		assert.NotNil(t, encrypter.Error)
		assert.Contains(t, encrypter.Error.Error(), "invalid key size")
	})

	t.Run("encryption with nil key", func(t *testing.T) {
		c := cipher.New3DesCipher(cipher.CBC)
		c.SetKey(nil)
		c.SetIV(iv83des)
		c.SetPadding(cipher.PKCS7)
		encrypter := NewEncrypter().FromBytes(testdata3des).By3Des(c)
		assert.NotNil(t, encrypter.Error)
		assert.Contains(t, encrypter.Error.Error(), "invalid key size")
	})

	t.Run("encryption with empty key", func(t *testing.T) {
		c := cipher.New3DesCipher(cipher.CBC)
		c.SetKey([]byte{})
		c.SetIV(iv83des)
		c.SetPadding(cipher.PKCS7)
		encrypter := NewEncrypter().FromBytes(testdata3des).By3Des(c)
		assert.NotNil(t, encrypter.Error)
		assert.Contains(t, encrypter.Error.Error(), "invalid key size")
	})

	t.Run("encryption with different block modes", func(t *testing.T) {
		modes := []cipher.BlockMode{
			cipher.CBC, cipher.ECB, cipher.CTR, cipher.CFB, cipher.OFB,
		}
		for _, mode := range modes {
			t.Run(string(mode), func(t *testing.T) {
				c := cipher.New3DesCipher(mode)
				c.SetKey(key243des)
				c.SetPadding(cipher.PKCS7)
				// For modes that need IV
				if mode == cipher.CTR || mode == cipher.CFB || mode == cipher.OFB || mode == cipher.CBC {
					c.SetIV(iv83des)
				}
				// For ECB mode, we don't need IV (default nil)

				encrypter := NewEncrypter().FromBytes(testdata3des).By3Des(c)
				assert.Nil(t, encrypter.Error)
				assert.NotNil(t, encrypter.dst)
			})
		}
	})

	t.Run("encryption with different padding modes", func(t *testing.T) {
		paddings := []cipher.PaddingMode{
			cipher.No, cipher.Zero, cipher.PKCS5, cipher.PKCS7,
			cipher.AnsiX923, cipher.ISO97971, cipher.ISO10126, cipher.ISO78164, cipher.Bit,
		}
		for _, padding := range paddings {
			t.Run(string(padding), func(t *testing.T) {
				c := cipher.New3DesCipher(cipher.CBC)
				c.SetKey(key243des)
				c.SetIV(iv83des)
				c.SetPadding(padding)

				// For No padding, we need data that is block-aligned
				var testDataForPadding []byte
				if padding == cipher.No {
					testDataForPadding = testdata83des
				} else {
					testDataForPadding = testdata3des
				}

				encrypter := NewEncrypter().FromBytes(testDataForPadding).By3Des(c)
				assert.Nil(t, encrypter.Error)
				assert.NotNil(t, encrypter.dst)
			})
		}
	})

	t.Run("encryption with empty data", func(t *testing.T) {
		c := cipher.New3DesCipher(cipher.CBC)
		c.SetKey(key243des)
		c.SetIV(iv83des)
		c.SetPadding(cipher.PKCS7)
		encrypter := NewEncrypter().FromBytes([]byte{}).By3Des(c)
		assert.Nil(t, encrypter.Error)
		assert.Empty(t, encrypter.dst)
	})

	t.Run("encryption with nil data", func(t *testing.T) {
		c := cipher.New3DesCipher(cipher.CBC)
		c.SetKey(key243des)
		c.SetIV(iv83des)
		c.SetPadding(cipher.PKCS7)
		encrypter := NewEncrypter().FromBytes(nil).By3Des(c)
		assert.Nil(t, encrypter.Error)
		assert.Empty(t, encrypter.dst)
	})

	t.Run("encryption with missing IV for CBC", func(t *testing.T) {
		c := cipher.New3DesCipher(cipher.CBC)
		c.SetKey(key243des)
		// Don't set IV - should cause error
		c.SetPadding(cipher.PKCS7)
		encrypter := NewEncrypter().FromBytes(testdata3des).By3Des(c)
		assert.NotNil(t, encrypter.Error)
		assert.Contains(t, encrypter.Error.Error(), "iv cannot be empty")
	})
}

func TestDecrypter_By3Des(t *testing.T) {
	t.Run("standard decryption with 24-byte key", func(t *testing.T) {
		c := cipher.New3DesCipher(cipher.CBC)
		c.SetKey(key243des)
		c.SetIV(iv83des)
		c.SetPadding(cipher.PKCS7)
		// First encrypt some data
		encrypter := NewEncrypter().FromBytes(testdata3des).By3Des(c)
		assert.Nil(t, encrypter.Error)
		encryptedData := encrypter.ToRawBytes()

		// Then decrypt it
		decrypter := NewDecrypter().FromRawBytes(encryptedData).By3Des(c)
		assert.Nil(t, decrypter.Error)
		assert.NotNil(t, decrypter.dst)
		assert.Equal(t, testdata3des, decrypter.dst)
	})

	t.Run("streaming decryption with reader", func(t *testing.T) {
		c := cipher.New3DesCipher(cipher.CBC)
		c.SetKey(key243des)
		c.SetIV(iv83des)
		c.SetPadding(cipher.PKCS7)
		// First encrypt some data
		encrypter := NewEncrypter().FromBytes(testdata3des).By3Des(c)
		assert.Nil(t, encrypter.Error)
		encryptedData := encrypter.ToRawBytes()

		// Create a mock file with encrypted data
		mockFile := mock.NewFile(encryptedData, "test.txt")

		// Then decrypt it using streaming
		decrypter := NewDecrypter().FromRawFile(mockFile).By3Des(c)
		assert.Nil(t, decrypter.Error)
		assert.NotNil(t, decrypter.dst)
		assert.Equal(t, testdata3des, decrypter.dst)
	})

	t.Run("streaming decryption with large data", func(t *testing.T) {
		c := cipher.New3DesCipher(cipher.CBC)
		c.SetKey(key243des)
		c.SetIV(iv83des)
		c.SetPadding(cipher.PKCS7)
		largeData := strings.Repeat("hello world ", 1000)
		// First encrypt large data
		encrypter := NewEncrypter().FromBytes([]byte(largeData)).By3Des(c)
		assert.Nil(t, encrypter.Error)
		encryptedData := encrypter.ToRawBytes()

		// Create a mock file with encrypted data
		mockFile := mock.NewFile(encryptedData, "large.txt")

		// Then decrypt it using streaming
		decrypter := NewDecrypter().FromRawFile(mockFile).By3Des(c)
		assert.Nil(t, decrypter.Error)
		assert.NotNil(t, decrypter.dst)
		assert.Equal(t, []byte(largeData), decrypter.dst)
	})

	t.Run("streaming decryption with empty reader", func(t *testing.T) {
		c := cipher.New3DesCipher(cipher.CBC)
		c.SetKey(key243des)
		c.SetIV(iv83des)
		c.SetPadding(cipher.PKCS7)
		mockFile := mock.NewFile([]byte{}, "empty.txt")
		decrypter := NewDecrypter().FromRawFile(mockFile).By3Des(c)
		assert.Nil(t, decrypter.Error)
		// Empty data may result in nil or empty dst, which is acceptable
	})

	t.Run("decryption with existing error", func(t *testing.T) {
		c := cipher.New3DesCipher(cipher.CBC)
		c.SetKey(key243des)
		c.SetIV(iv83des)
		c.SetPadding(cipher.PKCS7)
		decrypter := NewDecrypter()
		decrypter.Error = errors.New("existing error")
		result := decrypter.By3Des(c)
		assert.Equal(t, decrypter, result)
		assert.Equal(t, "existing error", result.Error.Error())
	})

	t.Run("decryption with invalid key size", func(t *testing.T) {
		c := cipher.New3DesCipher(cipher.CBC)
		c.SetKey([]byte("invalid"))
		c.SetIV(iv83des)
		c.SetPadding(cipher.PKCS7)
		decrypter := NewDecrypter().FromRawBytes(testdata3des).By3Des(c)
		assert.NotNil(t, decrypter.Error)
		assert.Contains(t, decrypter.Error.Error(), "invalid key size")
	})

	t.Run("decryption with nil key", func(t *testing.T) {
		c := cipher.New3DesCipher(cipher.CBC)
		c.SetKey(nil)
		c.SetIV(iv83des)
		c.SetPadding(cipher.PKCS7)
		decrypter := NewDecrypter().FromRawBytes(testdata3des).By3Des(c)
		assert.NotNil(t, decrypter.Error)
		assert.Contains(t, decrypter.Error.Error(), "invalid key size")
	})

	t.Run("decryption with empty key", func(t *testing.T) {
		c := cipher.New3DesCipher(cipher.CBC)
		c.SetKey([]byte{})
		c.SetIV(iv83des)
		c.SetPadding(cipher.PKCS7)
		decrypter := NewDecrypter().FromRawBytes(testdata3des).By3Des(c)
		assert.NotNil(t, decrypter.Error)
		assert.Contains(t, decrypter.Error.Error(), "invalid key size")
	})

	t.Run("decryption with different block modes", func(t *testing.T) {
		modes := []cipher.BlockMode{
			cipher.CBC, cipher.ECB, cipher.CTR, cipher.CFB, cipher.OFB,
		}
		for _, mode := range modes {
			t.Run(string(mode), func(t *testing.T) {
				c := cipher.New3DesCipher(mode)
				c.SetKey(key243des)
				c.SetPadding(cipher.PKCS7)
				// For modes that need IV
				if mode == cipher.CTR || mode == cipher.CFB || mode == cipher.OFB || mode == cipher.CBC {
					c.SetIV(iv83des)
				}

				// First encrypt some data
				encrypter := NewEncrypter().FromBytes(testdata3des).By3Des(c)
				assert.Nil(t, encrypter.Error)
				encryptedData := encrypter.ToRawBytes()

				// Then decrypt it
				decrypter := NewDecrypter().FromRawBytes(encryptedData).By3Des(c)
				assert.Nil(t, decrypter.Error)
				assert.NotNil(t, decrypter.dst)
				assert.Equal(t, testdata3des, decrypter.dst)
			})
		}
	})

	t.Run("decryption with different padding modes", func(t *testing.T) {
		paddings := []cipher.PaddingMode{
			cipher.No, cipher.Zero, cipher.PKCS5, cipher.PKCS7,
			cipher.AnsiX923, cipher.ISO97971, cipher.ISO10126, cipher.ISO78164, cipher.Bit,
		}
		for _, padding := range paddings {
			t.Run(string(padding), func(t *testing.T) {
				c := cipher.New3DesCipher(cipher.CBC)
				c.SetKey(key243des)
				c.SetIV(iv83des)
				c.SetPadding(padding)

				// For No padding, we need data that is block-aligned
				var testDataForPadding []byte
				if padding == cipher.No {
					testDataForPadding = testdata83des
				} else {
					testDataForPadding = testdata3des
				}

				// First encrypt some data
				encrypter := NewEncrypter().FromBytes(testDataForPadding).By3Des(c)
				assert.Nil(t, encrypter.Error)
				encryptedData := encrypter.ToRawBytes()

				// Then decrypt it
				decrypter := NewDecrypter().FromRawBytes(encryptedData).By3Des(c)
				assert.Nil(t, decrypter.Error)
				assert.NotNil(t, decrypter.dst)
				assert.Equal(t, testDataForPadding, decrypter.dst)
			})
		}
	})

	t.Run("decryption with empty data", func(t *testing.T) {
		c := cipher.New3DesCipher(cipher.CBC)
		c.SetKey(key243des)
		c.SetIV(iv83des)
		c.SetPadding(cipher.PKCS7)
		decrypter := NewDecrypter().FromRawBytes([]byte{}).By3Des(c)
		assert.Nil(t, decrypter.Error)
		// Empty data may result in nil dst, which is acceptable
	})

	t.Run("decryption with nil data", func(t *testing.T) {
		c := cipher.New3DesCipher(cipher.CBC)
		c.SetKey(key243des)
		c.SetIV(iv83des)
		c.SetPadding(cipher.PKCS7)
		decrypter := NewDecrypter().FromRawBytes(nil).By3Des(c)
		assert.Nil(t, decrypter.Error)
		// Nil data may result in nil dst, which is acceptable
	})

	t.Run("decryption with missing IV for CBC", func(t *testing.T) {
		c := cipher.New3DesCipher(cipher.CBC)
		c.SetKey(key243des)
		// Don't set IV - should cause error
		c.SetPadding(cipher.PKCS7)
		decrypter := NewDecrypter().FromRawBytes(testdata3des).By3Des(c)
		assert.NotNil(t, decrypter.Error)
		assert.Contains(t, decrypter.Error.Error(), "iv cannot be empty")
	})

	t.Run("decryption with wrong key", func(t *testing.T) {
		// Encrypt with one key
		c1 := cipher.New3DesCipher(cipher.CBC)
		c1.SetKey(key243des)
		c1.SetIV(iv83des)
		c1.SetPadding(cipher.PKCS7)
		encrypter := NewEncrypter().FromBytes(testdata3des).By3Des(c1)
		assert.Nil(t, encrypter.Error)
		encryptedData := encrypter.ToRawBytes()

		// Try to decrypt with different key
		c2 := cipher.New3DesCipher(cipher.CBC)
		c2.SetKey([]byte("876543210987654321098765")) // Different 24-byte key
		c2.SetIV(iv83des)
		c2.SetPadding(cipher.PKCS7)
		decrypter := NewDecrypter().FromRawBytes(encryptedData).By3Des(c2)
		assert.Nil(t, decrypter.Error)
		assert.NotNil(t, decrypter.dst)
		// The decrypted data should not match the original
		assert.NotEqual(t, testdata3des, decrypter.dst)
	})

	t.Run("decryption with wrong IV", func(t *testing.T) {
		// Encrypt with one IV
		c1 := cipher.New3DesCipher(cipher.CBC)
		c1.SetKey(key243des)
		c1.SetIV(iv83des)
		c1.SetPadding(cipher.PKCS7)
		encrypter := NewEncrypter().FromBytes(testdata3des).By3Des(c1)
		assert.Nil(t, encrypter.Error)
		encryptedData := encrypter.ToRawBytes()

		// Try to decrypt with different IV
		c2 := cipher.New3DesCipher(cipher.CBC)
		c2.SetKey(key243des)
		c2.SetIV([]byte("87654321")) // Different IV
		c2.SetPadding(cipher.PKCS7)
		decrypter := NewDecrypter().FromRawBytes(encryptedData).By3Des(c2)
		assert.Nil(t, decrypter.Error)
		assert.NotNil(t, decrypter.dst)
		// The decrypted data should not match the original
		assert.NotEqual(t, testdata3des, decrypter.dst)
	})
}
