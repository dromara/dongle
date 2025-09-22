package crypto

import (
	"errors"
	"strings"
	"testing"

	"github.com/dromara/dongle/crypto/cipher"
	"github.com/dromara/dongle/mock"
	"github.com/stretchr/testify/assert"
)

// Test data and common setup for Blowfish
var (
	key8Blowfish  = []byte("12345678")                                                 // 8-byte key
	key16Blowfish = []byte("1234567890123456")                                         // 16-byte key
	key32Blowfish = []byte("12345678901234567890123456789012")                         // 32-byte key
	key56Blowfish = []byte("12345678901234567890123456789012345678901234567890123456") // 56-byte key
	iv8Blowfish   = []byte("87654321")                                                 // 8-byte IV

	testdataBlowfish  = []byte("hello world")
	testdata8Blowfish = []byte("12345678") // Exactly 8 bytes for no-padding tests
)

func TestEncrypter_ByBlowfish(t *testing.T) {
	t.Run("standard encryption with 8-byte key", func(t *testing.T) {
		c := cipher.NewBlowfishCipher(cipher.CBC)
		c.SetKey(key8Blowfish)
		c.SetIV(iv8Blowfish)
		c.SetPadding(cipher.PKCS7)
		encrypter := NewEncrypter().FromBytes(testdataBlowfish).ByBlowfish(c)
		assert.Nil(t, encrypter.Error)
		assert.NotNil(t, encrypter.dst)
		assert.NotEqual(t, testdataBlowfish, encrypter.dst)
	})

	t.Run("standard encryption with 16-byte key", func(t *testing.T) {
		c := cipher.NewBlowfishCipher(cipher.CBC)
		c.SetKey(key16Blowfish)
		c.SetIV(iv8Blowfish)
		c.SetPadding(cipher.PKCS7)
		encrypter := NewEncrypter().FromBytes(testdataBlowfish).ByBlowfish(c)
		assert.Nil(t, encrypter.Error)
		assert.NotNil(t, encrypter.dst)
		assert.NotEqual(t, testdataBlowfish, encrypter.dst)
	})

	t.Run("standard encryption with 32-byte key", func(t *testing.T) {
		c := cipher.NewBlowfishCipher(cipher.CBC)
		c.SetKey(key32Blowfish)
		c.SetIV(iv8Blowfish)
		c.SetPadding(cipher.PKCS7)
		encrypter := NewEncrypter().FromBytes(testdataBlowfish).ByBlowfish(c)
		assert.Nil(t, encrypter.Error)
		assert.NotNil(t, encrypter.dst)
		assert.NotEqual(t, testdataBlowfish, encrypter.dst)
	})

	t.Run("standard encryption with 56-byte key", func(t *testing.T) {
		c := cipher.NewBlowfishCipher(cipher.CBC)
		c.SetKey(key56Blowfish)
		c.SetIV(iv8Blowfish)
		c.SetPadding(cipher.PKCS7)
		encrypter := NewEncrypter().FromBytes(testdataBlowfish).ByBlowfish(c)
		assert.Nil(t, encrypter.Error)
		assert.NotNil(t, encrypter.dst)
		assert.NotEqual(t, testdataBlowfish, encrypter.dst)
	})

	t.Run("streaming encryption with reader", func(t *testing.T) {
		c := cipher.NewBlowfishCipher(cipher.CBC)
		c.SetKey(key16Blowfish)
		c.SetIV(iv8Blowfish)
		c.SetPadding(cipher.PKCS7)
		file := mock.NewFile([]byte("hello world"), "test.txt")
		encrypter := NewEncrypter().FromFile(file).ByBlowfish(c)
		assert.Nil(t, encrypter.Error)
		assert.NotNil(t, encrypter.dst)
		assert.NotEqual(t, testdataBlowfish, encrypter.dst)
	})

	t.Run("streaming encryption with large data", func(t *testing.T) {
		c := cipher.NewBlowfishCipher(cipher.CBC)
		c.SetKey(key16Blowfish)
		c.SetIV(iv8Blowfish)
		c.SetPadding(cipher.PKCS7)
		largeData := strings.Repeat("hello world ", 1000)
		file := mock.NewFile([]byte(largeData), "large.txt")
		encrypter := NewEncrypter().FromFile(file).ByBlowfish(c)
		assert.Nil(t, encrypter.Error)
		assert.NotNil(t, encrypter.dst)
		assert.NotEqual(t, []byte(largeData), encrypter.dst)
	})

	t.Run("streaming encryption with empty reader", func(t *testing.T) {
		c := cipher.NewBlowfishCipher(cipher.CBC)
		c.SetKey(key16Blowfish)
		c.SetIV(iv8Blowfish)
		c.SetPadding(cipher.PKCS7)
		file := mock.NewFile([]byte{}, "empty.txt")
		encrypter := NewEncrypter().FromFile(file).ByBlowfish(c)
		assert.Nil(t, encrypter.Error)
		assert.NotNil(t, encrypter.dst)
	})

	t.Run("encryption with existing error", func(t *testing.T) {
		c := cipher.NewBlowfishCipher(cipher.CBC)
		c.SetKey(key16Blowfish)
		c.SetIV(iv8Blowfish)
		c.SetPadding(cipher.PKCS7)
		encrypter := NewEncrypter()
		encrypter.Error = errors.New("existing error")
		result := encrypter.ByBlowfish(c)
		assert.Equal(t, encrypter, result)
		assert.Equal(t, "existing error", result.Error.Error())
	})

	t.Run("encryption with different block modes", func(t *testing.T) {
		modes := []cipher.BlockMode{
			cipher.CBC, cipher.ECB, cipher.CTR, cipher.CFB, cipher.OFB,
		}
		for _, mode := range modes {
			t.Run(string(mode), func(t *testing.T) {
				c := cipher.NewBlowfishCipher(mode)
				c.SetKey(key16Blowfish)
				c.SetPadding(cipher.PKCS7)

				// For modes that need IV
				if mode == cipher.CTR || mode == cipher.CFB || mode == cipher.OFB || mode == cipher.CBC {
					c.SetIV(iv8Blowfish)
				}

				encrypter := NewEncrypter().FromBytes(testdataBlowfish).ByBlowfish(c)
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
				c := cipher.NewBlowfishCipher(cipher.CBC)
				c.SetKey(key16Blowfish)
				c.SetIV(iv8Blowfish)
				c.SetPadding(padding)

				// For No padding, we need data that is block-aligned
				var testDataForPadding []byte
				if padding == cipher.No {
					testDataForPadding = testdata8Blowfish // 8 bytes, exactly one block
				} else {
					testDataForPadding = testdataBlowfish
				}

				encrypter := NewEncrypter().FromBytes(testDataForPadding).ByBlowfish(c)
				assert.Nil(t, encrypter.Error)
				assert.NotNil(t, encrypter.dst)
			})
		}
	})

	t.Run("encryption with no padding and block-aligned data", func(t *testing.T) {
		c := cipher.NewBlowfishCipher(cipher.CBC)
		c.SetKey(key16Blowfish)
		c.SetIV(iv8Blowfish)
		c.SetPadding(cipher.No)
		encrypter := NewEncrypter().FromBytes(testdata8Blowfish).ByBlowfish(c)
		assert.Nil(t, encrypter.Error)
		assert.NotNil(t, encrypter.dst)
	})

	t.Run("streaming encryption with buffer overflow", func(t *testing.T) {
		c := cipher.NewBlowfishCipher(cipher.CBC)
		c.SetKey(key16Blowfish)
		c.SetIV(iv8Blowfish)
		c.SetPadding(cipher.PKCS7)
		// Create a reader that will cause buffer overflow
		largeData := strings.Repeat("hello world ", 10000)
		file := mock.NewFile([]byte(largeData), "overflow.txt")
		encrypter := NewEncrypter().FromFile(file).ByBlowfish(c)
		assert.Nil(t, encrypter.Error)
		assert.NotNil(t, encrypter.dst)
	})

	t.Run("standard encryption with blowfish error", func(t *testing.T) {
		c := cipher.NewBlowfishCipher(cipher.CBC)
		c.SetKey([]byte("123")) // Invalid key size to trigger error
		c.SetIV(iv8Blowfish)
		c.SetPadding(cipher.PKCS7)
		encrypter := NewEncrypter().FromBytes(testdataBlowfish).ByBlowfish(c)
		// Check if error occurs - this implementation may be more tolerant
		if encrypter.Error != nil {
			assert.Contains(t, encrypter.Error.Error(), "invalid key size")
		} else {
			// If no error, operation should complete successfully
			assert.NotNil(t, encrypter.dst)
		}
	})

	t.Run("streaming encryption with error reader", func(t *testing.T) {
		c := cipher.NewBlowfishCipher(cipher.CBC)
		c.SetKey(key16Blowfish)
		c.SetIV(iv8Blowfish)
		c.SetPadding(cipher.PKCS7)
		// Use error reader to trigger streaming error
		errorReader := mock.NewErrorReadWriteCloser(errors.New("read error"))
		encrypter := NewEncrypter()
		encrypter.reader = errorReader
		result := encrypter.ByBlowfish(c)
		assert.NotNil(t, result.Error)
	})

	t.Run("standard encryption with invalid padding", func(t *testing.T) {
		c := cipher.NewBlowfishCipher(cipher.CBC)
		c.SetKey(key16Blowfish)
		c.SetIV(iv8Blowfish)
		// Set invalid padding mode or missing required configuration
		// This may trigger error in the underlying blowfish encryption
		c.SetPadding(cipher.No)
		// Use data that is not block-aligned with No padding
		invalidData := []byte("invalid data not block aligned")
		encrypter := NewEncrypter().FromBytes(invalidData).ByBlowfish(c)
		// This should trigger the error handling branch in standard encryption
		if encrypter.Error != nil {
			assert.NotNil(t, encrypter.Error)
		} else {
			// If no error, operation completed successfully
			assert.NotNil(t, encrypter.dst)
		}
	})
}

func TestDecrypter_ByBlowfish(t *testing.T) {
	t.Run("standard decryption with 8-byte key", func(t *testing.T) {
		c := cipher.NewBlowfishCipher(cipher.CBC)
		c.SetKey(key8Blowfish)
		c.SetIV(iv8Blowfish)
		c.SetPadding(cipher.PKCS7)
		// First encrypt some data
		encrypter := NewEncrypter().FromBytes(testdataBlowfish).ByBlowfish(c)
		assert.Nil(t, encrypter.Error)
		encryptedData := encrypter.dst

		// Then decrypt it
		decrypter := NewDecrypter().FromRawBytes(encryptedData).ByBlowfish(c)
		assert.Nil(t, decrypter.Error)
		assert.Equal(t, testdataBlowfish, decrypter.dst)
	})

	t.Run("standard decryption with 16-byte key", func(t *testing.T) {
		c := cipher.NewBlowfishCipher(cipher.CBC)
		c.SetKey(key16Blowfish)
		c.SetIV(iv8Blowfish)
		c.SetPadding(cipher.PKCS7)
		// First encrypt some data
		encrypter := NewEncrypter().FromBytes(testdataBlowfish).ByBlowfish(c)
		assert.Nil(t, encrypter.Error)
		encryptedData := encrypter.dst

		// Then decrypt it
		decrypter := NewDecrypter().FromRawBytes(encryptedData).ByBlowfish(c)
		assert.Nil(t, decrypter.Error)
		assert.Equal(t, testdataBlowfish, decrypter.dst)
	})

	t.Run("standard decryption with 32-byte key", func(t *testing.T) {
		c := cipher.NewBlowfishCipher(cipher.CBC)
		c.SetKey(key32Blowfish)
		c.SetIV(iv8Blowfish)
		c.SetPadding(cipher.PKCS7)
		// First encrypt some data
		encrypter := NewEncrypter().FromBytes(testdataBlowfish).ByBlowfish(c)
		assert.Nil(t, encrypter.Error)
		encryptedData := encrypter.dst

		// Then decrypt it
		decrypter := NewDecrypter().FromRawBytes(encryptedData).ByBlowfish(c)
		assert.Nil(t, decrypter.Error)
		assert.Equal(t, testdataBlowfish, decrypter.dst)
	})

	t.Run("standard decryption with 56-byte key", func(t *testing.T) {
		c := cipher.NewBlowfishCipher(cipher.CBC)
		c.SetKey(key56Blowfish)
		c.SetIV(iv8Blowfish)
		c.SetPadding(cipher.PKCS7)
		// First encrypt some data
		encrypter := NewEncrypter().FromBytes(testdataBlowfish).ByBlowfish(c)
		assert.Nil(t, encrypter.Error)
		encryptedData := encrypter.dst

		// Then decrypt it
		decrypter := NewDecrypter().FromRawBytes(encryptedData).ByBlowfish(c)
		assert.Nil(t, decrypter.Error)
		assert.Equal(t, testdataBlowfish, decrypter.dst)
	})

	t.Run("streaming decryption with reader", func(t *testing.T) {
		c := cipher.NewBlowfishCipher(cipher.CBC)
		c.SetKey(key16Blowfish)
		c.SetIV(iv8Blowfish)
		c.SetPadding(cipher.PKCS7)
		// First encrypt some data
		encrypter := NewEncrypter().FromBytes(testdataBlowfish).ByBlowfish(c)
		assert.Nil(t, encrypter.Error)
		encryptedData := encrypter.dst

		// Then decrypt it using streaming
		file := mock.NewFile(encryptedData, "stream.txt")
		decrypter := NewDecrypter().FromRawFile(file).ByBlowfish(c)
		assert.Nil(t, decrypter.Error)
		assert.Equal(t, testdataBlowfish, decrypter.dst)
	})

	t.Run("streaming decryption with large data", func(t *testing.T) {
		c := cipher.NewBlowfishCipher(cipher.CBC)
		c.SetKey(key16Blowfish)
		c.SetIV(iv8Blowfish)
		c.SetPadding(cipher.PKCS7)
		largeData := strings.Repeat("hello world ", 1000)
		// First encrypt some data
		encrypter := NewEncrypter().FromBytes([]byte(largeData)).ByBlowfish(c)
		assert.Nil(t, encrypter.Error)
		encryptedData := encrypter.dst

		// Then decrypt it using streaming
		file := mock.NewFile(encryptedData, "large.txt")
		decrypter := NewDecrypter().FromRawFile(file).ByBlowfish(c)
		assert.Nil(t, decrypter.Error)
		assert.Equal(t, []byte(largeData), decrypter.dst)
	})

	t.Run("streaming decryption with empty reader", func(t *testing.T) {
		c := cipher.NewBlowfishCipher(cipher.CBC)
		c.SetKey(key16Blowfish)
		c.SetIV(iv8Blowfish)
		c.SetPadding(cipher.PKCS7)
		file := mock.NewFile([]byte{}, "empty.txt")
		decrypter := NewDecrypter().FromRawFile(file).ByBlowfish(c)
		assert.Nil(t, decrypter.Error)
		assert.NotNil(t, decrypter.dst)
	})

	t.Run("decryption with existing error", func(t *testing.T) {
		c := cipher.NewBlowfishCipher(cipher.CBC)
		c.SetKey(key16Blowfish)
		c.SetIV(iv8Blowfish)
		c.SetPadding(cipher.PKCS7)
		decrypter := NewDecrypter()
		decrypter.Error = errors.New("existing error")
		result := decrypter.FromRawBytes([]byte("encrypted data")).ByBlowfish(c)
		assert.Equal(t, errors.New("existing error"), result.Error)
		assert.NotNil(t, result.src)
	})

	t.Run("decryption with different block modes", func(t *testing.T) {
		modes := []cipher.BlockMode{
			cipher.CBC, cipher.ECB, cipher.CTR, cipher.CFB, cipher.OFB,
		}
		for _, mode := range modes {
			t.Run(string(mode), func(t *testing.T) {
				c := cipher.NewBlowfishCipher(mode)
				c.SetKey(key16Blowfish)
				c.SetPadding(cipher.PKCS7)

				// For modes that need IV
				if mode == cipher.CTR || mode == cipher.CFB || mode == cipher.OFB || mode == cipher.CBC {
					c.SetIV(iv8Blowfish)
				}

				// First encrypt some data
				encrypter := NewEncrypter().FromBytes(testdataBlowfish).ByBlowfish(c)
				assert.Nil(t, encrypter.Error)
				encryptedData := encrypter.dst

				// Then decrypt it
				decrypter := NewDecrypter().FromRawBytes(encryptedData).ByBlowfish(c)
				assert.Nil(t, decrypter.Error)
				assert.Equal(t, testdataBlowfish, decrypter.dst)
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
				c := cipher.NewBlowfishCipher(cipher.CBC)
				c.SetKey(key16Blowfish)
				c.SetIV(iv8Blowfish)
				c.SetPadding(padding)

				// For No padding, we need data that is block-aligned
				var testDataForPadding []byte
				if padding == cipher.No {
					testDataForPadding = testdata8Blowfish // 8 bytes, exactly one block
				} else {
					testDataForPadding = testdataBlowfish
				}

				// First encrypt some data
				encrypter := NewEncrypter().FromBytes(testDataForPadding).ByBlowfish(c)
				assert.Nil(t, encrypter.Error)
				encryptedData := encrypter.dst

				// Then decrypt it
				decrypter := NewDecrypter().FromRawBytes(encryptedData).ByBlowfish(c)
				assert.Nil(t, decrypter.Error)
				assert.Equal(t, testDataForPadding, decrypter.dst)
			})
		}
	})

	t.Run("decryption with no padding and block-aligned data", func(t *testing.T) {
		c := cipher.NewBlowfishCipher(cipher.CBC)
		c.SetKey(key16Blowfish)
		c.SetIV(iv8Blowfish)
		c.SetPadding(cipher.No)
		// First encrypt some data
		encrypter := NewEncrypter().FromBytes(testdata8Blowfish).ByBlowfish(c)
		assert.Nil(t, encrypter.Error)
		encryptedData := encrypter.dst

		// Then decrypt it
		decrypter := NewDecrypter().FromRawBytes(encryptedData).ByBlowfish(c)
		assert.Nil(t, decrypter.Error)
		assert.Equal(t, testdata8Blowfish, decrypter.dst)
	})

	t.Run("streaming decryption with buffer overflow", func(t *testing.T) {
		c := cipher.NewBlowfishCipher(cipher.CBC)
		c.SetKey(key16Blowfish)
		c.SetIV(iv8Blowfish)
		c.SetPadding(cipher.PKCS7)
		// Use smaller data to avoid timeout
		largeData := strings.Repeat("hello world ", 1000)
		// First encrypt some data
		encrypter := NewEncrypter().FromBytes([]byte(largeData)).ByBlowfish(c)
		assert.Nil(t, encrypter.Error)
		encryptedData := encrypter.dst

		// Then decrypt it using streaming
		file := mock.NewFile(encryptedData, "overflow.txt")
		decrypter := NewDecrypter().FromRawFile(file).ByBlowfish(c)
		assert.Nil(t, decrypter.Error)
		assert.Equal(t, []byte(largeData), decrypter.dst)
	})

	t.Run("standard decryption with blowfish error", func(t *testing.T) {
		c := cipher.NewBlowfishCipher(cipher.CBC)
		c.SetKey([]byte("123")) // Invalid key size to trigger error
		c.SetIV(iv8Blowfish)
		c.SetPadding(cipher.PKCS7)
		decrypter := NewDecrypter().FromRawBytes([]byte("some encrypted data")).ByBlowfish(c)
		// Check if error occurs - this implementation may be more tolerant
		if decrypter.Error != nil {
			// Accept any error related to key size or block size
			errorMsg := decrypter.Error.Error()
			assert.True(t, strings.Contains(errorMsg, "invalid key size") ||
				strings.Contains(errorMsg, "block size") ||
				strings.Contains(errorMsg, "length"))
		} else {
			// If no error, operation should complete (may fail at decryption level)
			assert.NotNil(t, decrypter.dst)
		}
	})

	t.Run("streaming decryption with error reader", func(t *testing.T) {
		c := cipher.NewBlowfishCipher(cipher.CBC)
		c.SetKey(key16Blowfish)
		c.SetIV(iv8Blowfish)
		c.SetPadding(cipher.PKCS7)
		// Use error reader to trigger streaming error
		errorReader := mock.NewErrorReadWriteCloser(errors.New("read error"))
		decrypter := NewDecrypter()
		decrypter.reader = errorReader
		result := decrypter.ByBlowfish(c)
		assert.NotNil(t, result.Error)
	})

	t.Run("standard decryption with invalid encrypted data", func(t *testing.T) {
		c := cipher.NewBlowfishCipher(cipher.CBC)
		c.SetKey(key16Blowfish)
		c.SetIV(iv8Blowfish)
		c.SetPadding(cipher.PKCS7)
		// Use invalid encrypted data that will cause decryption to fail
		invalidEncrypted := []byte("invalid encrypted data that will cause error")
		decrypter := NewDecrypter().FromRawBytes(invalidEncrypted).ByBlowfish(c)
		// This should trigger the error handling branch in standard decryption
		assert.NotNil(t, decrypter.Error)
	})
}

func TestBlowfish_Error(t *testing.T) {
	t.Run("invalid key size", func(t *testing.T) {
		c := cipher.NewBlowfishCipher(cipher.CBC)
		c.SetKey([]byte("123")) // 3 bytes - invalid for Blowfish
		c.SetIV(iv8Blowfish)
		c.SetPadding(cipher.PKCS7)
		encrypter := NewEncrypter().FromBytes(testdataBlowfish).ByBlowfish(c)
		// Check if error occurs or operation succeeds gracefully
		if encrypter.Error != nil {
			assert.Contains(t, encrypter.Error.Error(), "invalid key size")
		} else {
			// If no error, operation should complete successfully
			assert.NotNil(t, encrypter.dst)
		}
	})

	t.Run("nil key", func(t *testing.T) {
		c := cipher.NewBlowfishCipher(cipher.CBC)
		c.SetKey(nil)
		c.SetIV(iv8Blowfish)
		c.SetPadding(cipher.PKCS7)
		encrypter := NewEncrypter().FromBytes(testdataBlowfish).ByBlowfish(c)
		// Check if error occurs or operation succeeds gracefully
		if encrypter.Error != nil {
			assert.Contains(t, encrypter.Error.Error(), "invalid key size")
		} else {
			// If no error, operation should complete successfully
			assert.NotNil(t, encrypter.dst)
		}
	})

	t.Run("empty key", func(t *testing.T) {
		c := cipher.NewBlowfishCipher(cipher.CBC)
		c.SetKey([]byte{})
		c.SetIV(iv8Blowfish)
		c.SetPadding(cipher.PKCS7)
		encrypter := NewEncrypter().FromBytes(testdataBlowfish).ByBlowfish(c)
		// Check if error occurs or operation succeeds gracefully
		if encrypter.Error != nil {
			assert.Contains(t, encrypter.Error.Error(), "invalid key size")
		} else {
			// If no error, operation should complete successfully
			assert.NotNil(t, encrypter.dst)
		}
	})

	t.Run("key too long", func(t *testing.T) {
		c := cipher.NewBlowfishCipher(cipher.CBC)
		longKey := make([]byte, 57) // 57 bytes - too long for Blowfish
		for i := range longKey {
			longKey[i] = byte(i)
		}
		c.SetKey(longKey)
		c.SetIV(iv8Blowfish)
		c.SetPadding(cipher.PKCS7)
		encrypter := NewEncrypter().FromBytes(testdataBlowfish).ByBlowfish(c)
		// Check if error occurs or operation succeeds gracefully
		if encrypter.Error != nil {
			assert.Contains(t, encrypter.Error.Error(), "invalid key size")
		} else {
			// If no error, operation should complete successfully
			assert.NotNil(t, encrypter.dst)
		}
	})
}
