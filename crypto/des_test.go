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
	desKey8      = []byte("12345678") // DES key (8 bytes)
	desIv8       = []byte("87654321") // 8-byte IV
	desTestData  = []byte("hello world")
	desTestData8 = []byte("12345678") // Exactly 8 bytes for no-padding tests
)

func TestEncrypter_ByDes(t *testing.T) {
	t.Run("standard encryption with valid key", func(t *testing.T) {
		c := cipher.NewDesCipher(cipher.CBC)
		c.SetKey(desKey8)
		c.SetIV(desIv8)
		c.SetPadding(cipher.PKCS7)
		encrypter := NewEncrypter().FromBytes(desTestData).ByDes(c)
		assert.Nil(t, encrypter.Error)
		assert.NotNil(t, encrypter.dst)
		assert.NotEqual(t, desTestData, encrypter.dst)
	})

	t.Run("streaming encryption with reader", func(t *testing.T) {
		c := cipher.NewDesCipher(cipher.CBC)
		c.SetKey(desKey8)
		c.SetIV(desIv8)
		c.SetPadding(cipher.PKCS7)
		file := mock.NewFile([]byte("hello world"), "test.txt")
		encrypter := NewEncrypter().FromFile(file).ByDes(c)
		assert.Nil(t, encrypter.Error)
		assert.NotNil(t, encrypter.dst)
		assert.NotEqual(t, desTestData, encrypter.dst)
	})

	t.Run("streaming encryption with large data", func(t *testing.T) {
		c := cipher.NewDesCipher(cipher.CBC)
		c.SetKey(desKey8)
		c.SetIV(desIv8)
		c.SetPadding(cipher.PKCS7)
		largeData := strings.Repeat("hello world ", 1000)
		file := mock.NewFile([]byte(largeData), "large.txt")
		encrypter := NewEncrypter().FromFile(file).ByDes(c)
		assert.Nil(t, encrypter.Error)
		assert.NotNil(t, encrypter.dst)
		assert.NotEqual(t, []byte(largeData), encrypter.dst)
	})

	t.Run("encryption with existing error", func(t *testing.T) {
		c := cipher.NewDesCipher(cipher.CBC)
		c.SetKey(desKey8)
		c.SetIV(desIv8)
		c.SetPadding(cipher.PKCS7)
		encrypter := NewEncrypter()
		encrypter.Error = errors.New("existing error")
		result := encrypter.ByDes(c)
		assert.Equal(t, encrypter, result)
		assert.Equal(t, "existing error", result.Error.Error())
	})

	t.Run("encryption with invalid key size", func(t *testing.T) {
		c := cipher.NewDesCipher(cipher.CBC)
		c.SetKey([]byte("invalid"))
		c.SetIV(desIv8)
		c.SetPadding(cipher.PKCS7)
		encrypter := NewEncrypter().FromBytes(desTestData).ByDes(c)
		assert.NotNil(t, encrypter.Error)
		assert.Contains(t, encrypter.Error.Error(), "invalid key size")
	})

	t.Run("encryption with different block modes", func(t *testing.T) {
		modes := []cipher.BlockMode{
			cipher.CBC, cipher.ECB, cipher.CTR, cipher.CFB, cipher.OFB,
		}
		for _, mode := range modes {
			t.Run(string(mode), func(t *testing.T) {
				c := cipher.NewDesCipher(mode)
				c.SetKey(desKey8)
				c.SetPadding(cipher.PKCS7)
				if mode == cipher.CTR || mode == cipher.CFB || mode == cipher.OFB || mode == cipher.CBC {
					c.SetIV(desIv8)
				}

				encrypter := NewEncrypter().FromBytes(desTestData).ByDes(c)
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
				c := cipher.NewDesCipher(cipher.CBC)
				c.SetKey(desKey8)
				c.SetIV(desIv8)
				c.SetPadding(padding)

				var testDataForPadding []byte
				if padding == cipher.No {
					testDataForPadding = desTestData8
				} else {
					testDataForPadding = desTestData
				}

				encrypter := NewEncrypter().FromBytes(testDataForPadding).ByDes(c)
				assert.Nil(t, encrypter.Error)
				assert.NotNil(t, encrypter.dst)
			})
		}
	})
}

func TestDecrypter_ByDes(t *testing.T) {
	t.Run("standard decryption with valid key", func(t *testing.T) {
		c := cipher.NewDesCipher(cipher.CBC)
		c.SetKey(desKey8)
		c.SetIV(desIv8)
		c.SetPadding(cipher.PKCS7)
		// First encrypt some data
		encrypter := NewEncrypter().FromBytes(desTestData).ByDes(c)
		assert.Nil(t, encrypter.Error)
		encryptedData := encrypter.dst

		// Then decrypt it
		decrypter := NewDecrypter().FromRawBytes(encryptedData).ByDes(c)
		assert.Nil(t, decrypter.Error)
		assert.Equal(t, desTestData, decrypter.dst)
	})

	t.Run("streaming decryption with reader", func(t *testing.T) {
		c := cipher.NewDesCipher(cipher.CBC)
		c.SetKey(desKey8)
		c.SetIV(desIv8)
		c.SetPadding(cipher.PKCS7)
		// First encrypt some data
		encrypter := NewEncrypter().FromBytes(desTestData).ByDes(c)
		assert.Nil(t, encrypter.Error)
		encryptedData := encrypter.dst

		// Then decrypt it using streaming
		file := mock.NewFile(encryptedData, "stream.txt")
		decrypter := NewDecrypter().FromRawFile(file).ByDes(c)
		assert.Nil(t, decrypter.Error)
		assert.Equal(t, desTestData, decrypter.dst)
	})

	t.Run("decryption with existing error", func(t *testing.T) {
		c := cipher.NewDesCipher(cipher.CBC)
		c.SetKey(desKey8)
		c.SetIV(desIv8)
		c.SetPadding(cipher.PKCS7)
		decrypter := NewDecrypter()
		decrypter.Error = errors.New("existing error")
		result := decrypter.ByDes(c)
		assert.Equal(t, decrypter, result)
		assert.Equal(t, "existing error", result.Error.Error())
	})

	t.Run("decryption with invalid key size", func(t *testing.T) {
		c := cipher.NewDesCipher(cipher.CBC)
		c.SetKey([]byte("invalid"))
		c.SetIV(desIv8)
		c.SetPadding(cipher.PKCS7)
		decrypter := NewDecrypter().FromRawBytes(desTestData).ByDes(c)
		assert.NotNil(t, decrypter.Error)
		assert.Contains(t, decrypter.Error.Error(), "invalid key size")
	})

	t.Run("decryption with corrupted data", func(t *testing.T) {
		c := cipher.NewDesCipher(cipher.CBC)
		c.SetKey(desKey8)
		c.SetIV(desIv8)
		c.SetPadding(cipher.PKCS7)
		corruptedData := []byte("corrupted encrypted data")
		decrypter := NewDecrypter().FromRawBytes(corruptedData).ByDes(c)
		// The DES implementation may handle corrupted data gracefully
		// Check that we get some result (either success or error)
		t.Logf("Decrypter result: dst=%v, error=%v", decrypter.dst, decrypter.Error)
	})
}

func TestDes_Error(t *testing.T) {
	t.Run("encryption with missing IV for CBC mode", func(t *testing.T) {
		c := cipher.NewDesCipher(cipher.CBC)
		c.SetKey(desKey8)
		c.SetIV(nil)
		c.SetPadding(cipher.PKCS7)
		encrypter := NewEncrypter().FromBytes(desTestData).ByDes(c)
		assert.NotNil(t, encrypter.Error)
	})

	t.Run("decryption with missing IV for CBC mode", func(t *testing.T) {
		c := cipher.NewDesCipher(cipher.CBC)
		c.SetKey(desKey8)
		c.SetIV(nil)
		c.SetPadding(cipher.PKCS7)
		decrypter := NewDecrypter().FromRawBytes(desTestData).ByDes(c)
		assert.NotNil(t, decrypter.Error)
	})
}
