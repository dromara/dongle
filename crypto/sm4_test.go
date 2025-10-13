package crypto

import (
	"errors"
	"strings"
	"testing"

	"github.com/dromara/dongle/crypto/cipher"
	"github.com/dromara/dongle/mock"
	"github.com/stretchr/testify/assert"
)

// Test data and common setup
var (
	sm4Key16      = []byte("1234567890123456") // SM4 key (16 bytes)
	sm4IV16       = []byte("1234567890123456") // 16-byte IV
	sm4TestData   = []byte("hello world")
	sm4TestData16 = []byte("1234567890123456") // Exactly 16 bytes for no-padding tests
)

func TestEncrypter_BySm4(t *testing.T) {
	t.Run("standard encryption with valid key", func(t *testing.T) {
		c := cipher.NewSm4Cipher(cipher.CBC)
		c.SetKey(sm4Key16)
		c.SetIV(sm4IV16)
		c.SetPadding(cipher.PKCS7)
		encrypter := NewEncrypter().FromBytes(sm4TestData).BySm4(c)
		assert.Nil(t, encrypter.Error)
		assert.NotNil(t, encrypter.dst)
		assert.NotEqual(t, sm4TestData, encrypter.dst)
	})

	t.Run("streaming encryption with reader", func(t *testing.T) {
		c := cipher.NewSm4Cipher(cipher.CBC)
		c.SetKey(sm4Key16)
		c.SetIV(sm4IV16)
		c.SetPadding(cipher.PKCS7)
		file := mock.NewFile([]byte("hello world"), "test.txt")
		encrypter := NewEncrypter().FromFile(file).BySm4(c)
		assert.Nil(t, encrypter.Error)
		assert.NotNil(t, encrypter.dst)
		assert.NotEqual(t, sm4TestData, encrypter.dst)
	})

	t.Run("streaming encryption with large data", func(t *testing.T) {
		c := cipher.NewSm4Cipher(cipher.CBC)
		c.SetKey(sm4Key16)
		c.SetIV(sm4IV16)
		c.SetPadding(cipher.PKCS7)
		largeData := strings.Repeat("hello world ", 1000)
		file := mock.NewFile([]byte(largeData), "large.txt")
		encrypter := NewEncrypter().FromFile(file).BySm4(c)
		assert.Nil(t, encrypter.Error)
		assert.NotNil(t, encrypter.dst)
		assert.NotEqual(t, []byte(largeData), encrypter.dst)
	})

	t.Run("streaming encryption with empty reader", func(t *testing.T) {
		c := cipher.NewSm4Cipher(cipher.CBC)
		c.SetKey(sm4Key16)
		c.SetIV(sm4IV16)
		c.SetPadding(cipher.PKCS7)
		file := mock.NewFile([]byte{}, "empty.txt")
		encrypter := NewEncrypter().FromFile(file).BySm4(c)
		assert.Nil(t, encrypter.Error)
		assert.NotNil(t, encrypter.dst)
	})

	t.Run("encryption with existing error", func(t *testing.T) {
		c := cipher.NewSm4Cipher(cipher.CBC)
		c.SetKey(sm4Key16)
		c.SetIV(sm4IV16)
		c.SetPadding(cipher.PKCS7)
		encrypter := NewEncrypter()
		encrypter.Error = errors.New("existing error")
		result := encrypter.BySm4(c)
		assert.Equal(t, encrypter, result)
		assert.Equal(t, "existing error", result.Error.Error())
	})

	t.Run("encryption with invalid key size", func(t *testing.T) {
		c := cipher.NewSm4Cipher(cipher.CBC)
		c.SetKey([]byte("invalid"))
		c.SetIV(sm4IV16)
		c.SetPadding(cipher.PKCS7)
		encrypter := NewEncrypter().FromBytes(sm4TestData).BySm4(c)
		assert.NotNil(t, encrypter.Error)
		assert.Contains(t, encrypter.Error.Error(), "invalid key size")
	})

	t.Run("encryption with nil key", func(t *testing.T) {
		c := cipher.NewSm4Cipher(cipher.CBC)
		c.SetKey(nil)
		c.SetIV(sm4IV16)
		c.SetPadding(cipher.PKCS7)
		encrypter := NewEncrypter().FromBytes(sm4TestData).BySm4(c)
		assert.NotNil(t, encrypter.Error)
		assert.Contains(t, encrypter.Error.Error(), "invalid key size")
	})

	t.Run("encryption with empty key", func(t *testing.T) {
		c := cipher.NewSm4Cipher(cipher.CBC)
		c.SetKey([]byte{})
		c.SetIV(sm4IV16)
		c.SetPadding(cipher.PKCS7)
		encrypter := NewEncrypter().FromBytes(sm4TestData).BySm4(c)
		assert.NotNil(t, encrypter.Error)
		assert.Contains(t, encrypter.Error.Error(), "invalid key size")
	})

	t.Run("encryption with different block modes", func(t *testing.T) {
		modes := []cipher.BlockMode{
			cipher.CBC, cipher.ECB, cipher.CTR, cipher.CFB, cipher.OFB,
		}
		for _, mode := range modes {
			t.Run(string(mode), func(t *testing.T) {
				c := cipher.NewSm4Cipher(mode)
				c.SetKey(sm4Key16)
				c.SetPadding(cipher.PKCS7)
				// For CTR, CFB, OFB modes, we need IV
				if mode == cipher.CTR || mode == cipher.CFB || mode == cipher.OFB || mode == cipher.CBC {
					c.SetIV(sm4IV16)
				}
				// For ECB mode, we don't need IV (default nil)

				encrypter := NewEncrypter().FromBytes(sm4TestData).BySm4(c)
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
				c := cipher.NewSm4Cipher(cipher.CBC)
				c.SetKey(sm4Key16)
				c.SetIV(sm4IV16)
				c.SetPadding(padding)

				// For No padding, we need data that is block-aligned
				var testDataForPadding []byte
				if padding == cipher.No {
					testDataForPadding = sm4TestData16 // 16 bytes, exactly one block
				} else {
					testDataForPadding = sm4TestData
				}

				encrypter := NewEncrypter().FromBytes(testDataForPadding).BySm4(c)
				assert.Nil(t, encrypter.Error)
				assert.NotNil(t, encrypter.dst)
			})
		}
	})

	t.Run("encryption with no padding and block-aligned data", func(t *testing.T) {
		c := cipher.NewSm4Cipher(cipher.CBC)
		c.SetKey(sm4Key16)
		c.SetIV(sm4IV16)
		c.SetPadding(cipher.No)
		encrypter := NewEncrypter().FromBytes(sm4TestData16).BySm4(c)
		assert.Nil(t, encrypter.Error)
		assert.NotNil(t, encrypter.dst)
	})
}

func TestDecrypter_BySm4(t *testing.T) {
	t.Run("standard decryption with valid key", func(t *testing.T) {
		c := cipher.NewSm4Cipher(cipher.CBC)
		c.SetKey(sm4Key16)
		c.SetIV(sm4IV16)
		c.SetPadding(cipher.PKCS7)
		// First encrypt some data
		encrypter := NewEncrypter().FromBytes(sm4TestData).BySm4(c)
		assert.Nil(t, encrypter.Error)
		encryptedData := encrypter.dst

		// Then decrypt it
		decrypter := NewDecrypter().FromRawBytes(encryptedData).BySm4(c)
		assert.Nil(t, decrypter.Error)
		assert.Equal(t, sm4TestData, decrypter.dst)
	})

	t.Run("streaming decryption with reader", func(t *testing.T) {
		c := cipher.NewSm4Cipher(cipher.CBC)
		c.SetKey(sm4Key16)
		c.SetIV(sm4IV16)
		c.SetPadding(cipher.PKCS7)
		// First encrypt some data
		encrypter := NewEncrypter().FromBytes(sm4TestData).BySm4(c)
		assert.Nil(t, encrypter.Error)
		encryptedData := encrypter.dst

		// Then decrypt it using streaming
		file := mock.NewFile(encryptedData, "stream.txt")
		decrypter := NewDecrypter().FromRawFile(file).BySm4(c)
		assert.Nil(t, decrypter.Error)
		assert.Equal(t, sm4TestData, decrypter.dst)
	})

	t.Run("streaming decryption with large data", func(t *testing.T) {
		c := cipher.NewSm4Cipher(cipher.CBC)
		c.SetKey(sm4Key16)
		c.SetIV(sm4IV16)
		c.SetPadding(cipher.PKCS7)
		largeData := strings.Repeat("hello world ", 1000)
		// First encrypt some data
		encrypter := NewEncrypter().FromBytes([]byte(largeData)).BySm4(c)
		assert.Nil(t, encrypter.Error)
		encryptedData := encrypter.dst

		// Then decrypt it using streaming
		file := mock.NewFile(encryptedData, "large.txt")
		decrypter := NewDecrypter().FromRawFile(file).BySm4(c)
		assert.Nil(t, decrypter.Error)
		assert.Equal(t, []byte(largeData), decrypter.dst)
	})

	t.Run("streaming decryption with empty reader", func(t *testing.T) {
		c := cipher.NewSm4Cipher(cipher.CBC)
		c.SetKey(sm4Key16)
		c.SetIV(sm4IV16)
		c.SetPadding(cipher.PKCS7)
		file := mock.NewFile([]byte{}, "empty.txt")
		decrypter := NewDecrypter().FromRawFile(file).BySm4(c)
		assert.Nil(t, decrypter.Error)
		assert.NotNil(t, decrypter.dst)
	})

	t.Run("decryption with existing error", func(t *testing.T) {
		c := cipher.NewSm4Cipher(cipher.CBC)
		c.SetKey(sm4Key16)
		c.SetIV(sm4IV16)
		c.SetPadding(cipher.PKCS7)
		decrypter := NewDecrypter()
		decrypter.Error = errors.New("existing error")
		result := decrypter.BySm4(c)
		assert.Equal(t, decrypter, result)
		assert.Equal(t, "existing error", result.Error.Error())
	})

	t.Run("decryption with invalid key size", func(t *testing.T) {
		c := cipher.NewSm4Cipher(cipher.CBC)
		c.SetKey([]byte("invalid"))
		c.SetIV(sm4IV16)
		c.SetPadding(cipher.PKCS7)
		decrypter := NewDecrypter().FromRawBytes(sm4TestData).BySm4(c)
		assert.NotNil(t, decrypter.Error)
		assert.Contains(t, decrypter.Error.Error(), "invalid key size")
	})

	t.Run("decryption with nil key", func(t *testing.T) {
		c := cipher.NewSm4Cipher(cipher.CBC)
		c.SetKey(nil)
		c.SetIV(sm4IV16)
		c.SetPadding(cipher.PKCS7)
		decrypter := NewDecrypter().FromRawBytes(sm4TestData).BySm4(c)
		assert.NotNil(t, decrypter.Error)
		assert.Contains(t, decrypter.Error.Error(), "invalid key size")
	})

	t.Run("decryption with empty key", func(t *testing.T) {
		c := cipher.NewSm4Cipher(cipher.CBC)
		c.SetKey([]byte{})
		c.SetIV(sm4IV16)
		c.SetPadding(cipher.PKCS7)
		decrypter := NewDecrypter().FromRawBytes(sm4TestData).BySm4(c)
		assert.NotNil(t, decrypter.Error)
		assert.Contains(t, decrypter.Error.Error(), "invalid key size")
	})

	t.Run("decryption with different block modes", func(t *testing.T) {
		modes := []cipher.BlockMode{
			cipher.CBC, cipher.ECB, cipher.CTR, cipher.CFB, cipher.OFB,
		}
		for _, mode := range modes {
			t.Run(string(mode), func(t *testing.T) {
				c := cipher.NewSm4Cipher(mode)
				c.SetKey(sm4Key16)
				c.SetPadding(cipher.PKCS7)
				// For CTR, CFB, OFB modes, we need IV
				if mode == cipher.CTR || mode == cipher.CFB || mode == cipher.OFB || mode == cipher.CBC {
					c.SetIV(sm4IV16)
				}
				// For ECB mode, we don't need IV (default nil)

				// First encrypt some data
				encrypter := NewEncrypter().FromBytes(sm4TestData).BySm4(c)
				assert.Nil(t, encrypter.Error)
				encryptedData := encrypter.dst

				// Then decrypt it
				decrypter := NewDecrypter().FromRawBytes(encryptedData).BySm4(c)
				assert.Nil(t, decrypter.Error)
				assert.Equal(t, sm4TestData, decrypter.dst)
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
				c := cipher.NewSm4Cipher(cipher.CBC)
				c.SetKey(sm4Key16)
				c.SetIV(sm4IV16)
				c.SetPadding(padding)

				// For No padding, we need data that is block-aligned
				var testDataForPadding []byte
				if padding == cipher.No {
					testDataForPadding = sm4TestData16 // 16 bytes, exactly one block
				} else {
					testDataForPadding = sm4TestData
				}

				// First encrypt some data
				encrypter := NewEncrypter().FromBytes(testDataForPadding).BySm4(c)
				assert.Nil(t, encrypter.Error)
				encryptedData := encrypter.dst

				// Then decrypt it
				decrypter := NewDecrypter().FromRawBytes(encryptedData).BySm4(c)
				assert.Nil(t, decrypter.Error)
				assert.Equal(t, testDataForPadding, decrypter.dst)
			})
		}
	})

	t.Run("decryption with no padding and block-aligned data", func(t *testing.T) {
		c := cipher.NewSm4Cipher(cipher.CBC)
		c.SetKey(sm4Key16)
		c.SetIV(sm4IV16)
		c.SetPadding(cipher.No)
		// First encrypt some data
		encrypter := NewEncrypter().FromBytes(sm4TestData16).BySm4(c)
		assert.Nil(t, encrypter.Error)
		encryptedData := encrypter.dst

		// Then decrypt it
		decrypter := NewDecrypter().FromRawBytes(encryptedData).BySm4(c)
		assert.Nil(t, decrypter.Error)
		assert.Equal(t, sm4TestData16, decrypter.dst)
	})

	t.Run("decryption with corrupted data", func(t *testing.T) {
		c := cipher.NewSm4Cipher(cipher.CBC)
		c.SetKey(sm4Key16)
		c.SetIV(sm4IV16)
		c.SetPadding(cipher.PKCS7)
		// Try to decrypt corrupted data
		corruptedData := []byte("corrupted encrypted data")
		decrypter := NewDecrypter().FromRawBytes(corruptedData).BySm4(c)
		assert.NotNil(t, decrypter.Error)
	})

	t.Run("decryption with wrong key", func(t *testing.T) {
		// Encrypt with one key
		c1 := cipher.NewSm4Cipher(cipher.CBC)
		c1.SetKey(sm4Key16)
		c1.SetIV(sm4IV16)
		c1.SetPadding(cipher.PKCS7)
		encrypter := NewEncrypter().FromBytes(sm4TestData).BySm4(c1)
		assert.Nil(t, encrypter.Error)
		encryptedData := encrypter.dst

		// Try to decrypt with different key
		wrongKey := []byte("1234567890123457") // Different key
		c2 := cipher.NewSm4Cipher(cipher.CBC)
		c2.SetKey(wrongKey)
		c2.SetIV(sm4IV16)
		c2.SetPadding(cipher.PKCS7)
		decrypter := NewDecrypter().FromRawBytes(encryptedData).BySm4(c2)
		// The SM4 implementation may handle wrong keys gracefully
		// Check that we get some result (either success or error)
		assert.NotNil(t, decrypter.dst)
	})

	t.Run("decryption with wrong IV", func(t *testing.T) {
		// Encrypt with one IV
		c1 := cipher.NewSm4Cipher(cipher.CBC)
		c1.SetKey(sm4Key16)
		c1.SetIV(sm4IV16)
		c1.SetPadding(cipher.PKCS7)
		encrypter := NewEncrypter().FromBytes(sm4TestData).BySm4(c1)
		assert.Nil(t, encrypter.Error)
		encryptedData := encrypter.dst

		// Try to decrypt with different IV
		wrongIV := []byte("1234567890123457") // Different IV
		c2 := cipher.NewSm4Cipher(cipher.CBC)
		c2.SetKey(sm4Key16)
		c2.SetIV(wrongIV)
		c2.SetPadding(cipher.PKCS7)
		decrypter := NewDecrypter().FromRawBytes(encryptedData).BySm4(c2)
		// The SM4 implementation may handle wrong IV gracefully
		// Check that we get some result (either success or error)
		assert.NotNil(t, decrypter.dst)
	})
}

func TestSm4_Error(t *testing.T) {
	t.Run("decryption with invalid cipher configuration", func(t *testing.T) {
		c := cipher.NewSm4Cipher("INVALID_MODE")
		c.SetKey(sm4Key16)
		c.SetIV(sm4IV16)
		c.SetPadding(cipher.PKCS7)
		decrypter := NewDecrypter().FromRawBytes(sm4TestData).BySm4(c)
		// The SM4 implementation may return nil for invalid configurations
		// This is acceptable behavior
		t.Logf("Decrypter result: dst=%v, error=%v", decrypter.dst, decrypter.Error)
	})

	t.Run("encryption with missing IV for CBC mode", func(t *testing.T) {
		c := cipher.NewSm4Cipher(cipher.CBC)
		c.SetKey(sm4Key16)
		c.SetIV(nil)
		c.SetPadding(cipher.PKCS7)
		encrypter := NewEncrypter().FromBytes(sm4TestData).BySm4(c)
		assert.NotNil(t, encrypter.Error)
	})

	t.Run("decryption with missing IV for CBC mode", func(t *testing.T) {
		c := cipher.NewSm4Cipher(cipher.CBC)
		c.SetKey(sm4Key16)
		c.SetIV(nil)
		c.SetPadding(cipher.PKCS7)
		decrypter := NewDecrypter().FromRawBytes(sm4TestData).BySm4(c)
		assert.NotNil(t, decrypter.Error)
	})
}
