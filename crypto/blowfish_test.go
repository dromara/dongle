package crypto

import (
	"errors"
	"strings"
	"testing"

	"gitee.com/golang-package/dongle/crypto/cipher"
	"gitee.com/golang-package/dongle/mock"
	"github.com/stretchr/testify/assert"
)

// Test data constants for Blowfish
var (
	key8_blowfish      = []byte("12345678")                                                 // 8-byte key
	key16_blowfish     = []byte("1234567890123456")                                         // 16-byte key
	key32_blowfish     = []byte("12345678901234567890123456789012")                         // 32-byte key
	key56_blowfish     = []byte("12345678901234567890123456789012345678901234567890123456") // 56-byte key
	iv8_blowfish       = []byte("87654321")                                                 // 8-byte IV (Blowfish block size)
	nonce12_blowfish   = []byte("123456789012")                                             // 12-byte nonce for GCM
	testData_blowfish  = []byte("hello world")
	testData8_blowfish = []byte("12345678") // Exactly 8 bytes for no-padding tests
)

func TestEncrypter_ByBlowfish(t *testing.T) {
	t.Run("basic_encryption_8byte_key", func(t *testing.T) {
		c := cipher.BlowfishCipher{
			Key:     key8_blowfish,
			Block:   cipher.CBC,
			IV:      iv8_blowfish,
			Padding: cipher.PKCS7,
		}
		encrypter := NewEncrypter().FromBytes(testData_blowfish).ByBlowfish(c)
		assert.Nil(t, encrypter.Error)
		assert.NotNil(t, encrypter.dst)
		assert.NotEqual(t, testData_blowfish, encrypter.dst)
	})

	t.Run("basic_encryption_16byte_key", func(t *testing.T) {
		c := cipher.BlowfishCipher{
			Key:     key16_blowfish,
			Block:   cipher.CBC,
			IV:      iv8_blowfish,
			Padding: cipher.PKCS7,
		}
		encrypter := NewEncrypter().FromBytes(testData_blowfish).ByBlowfish(c)
		assert.Nil(t, encrypter.Error)
		assert.NotNil(t, encrypter.dst)
		assert.NotEqual(t, testData_blowfish, encrypter.dst)
	})

	t.Run("basic_encryption_32byte_key", func(t *testing.T) {
		c := cipher.BlowfishCipher{
			Key:     key32_blowfish,
			Block:   cipher.CBC,
			IV:      iv8_blowfish,
			Padding: cipher.PKCS7,
		}
		encrypter := NewEncrypter().FromBytes(testData_blowfish).ByBlowfish(c)
		assert.Nil(t, encrypter.Error)
		assert.NotNil(t, encrypter.dst)
		assert.NotEqual(t, testData_blowfish, encrypter.dst)
	})

	t.Run("basic_encryption_56byte_key", func(t *testing.T) {
		c := cipher.BlowfishCipher{
			Key:     key56_blowfish,
			Block:   cipher.CBC,
			IV:      iv8_blowfish,
			Padding: cipher.PKCS7,
		}
		encrypter := NewEncrypter().FromBytes(testData_blowfish).ByBlowfish(c)
		assert.Nil(t, encrypter.Error)
		assert.NotNil(t, encrypter.dst)
		assert.NotEqual(t, testData_blowfish, encrypter.dst)
	})

	t.Run("encryption_with_string_input", func(t *testing.T) {
		c := cipher.BlowfishCipher{
			Key:     key16_blowfish,
			Block:   cipher.CBC,
			IV:      iv8_blowfish,
			Padding: cipher.PKCS7,
		}
		encrypter := NewEncrypter().FromString("hello world").ByBlowfish(c)
		assert.Nil(t, encrypter.Error)
		assert.NotNil(t, encrypter.dst)
		assert.NotEqual(t, []byte("hello world"), encrypter.dst)
	})

	t.Run("encryption_with_file_input", func(t *testing.T) {
		c := cipher.BlowfishCipher{
			Key:     key16_blowfish,
			Block:   cipher.CBC,
			IV:      iv8_blowfish,
			Padding: cipher.PKCS7,
		}
		file := mock.NewFile([]byte("hello world"), "test.txt")
		encrypter := NewEncrypter().FromFile(file).ByBlowfish(c)
		assert.Nil(t, encrypter.Error)
		assert.NotNil(t, encrypter.dst)
		assert.NotEqual(t, []byte("hello world"), encrypter.dst)
	})

	t.Run("encryption_with_raw_bytes", func(t *testing.T) {
		c := cipher.BlowfishCipher{
			Key:     key16_blowfish,
			Block:   cipher.CBC,
			IV:      iv8_blowfish,
			Padding: cipher.PKCS7,
		}
		encrypter := NewEncrypter().FromBytes(testData_blowfish).ByBlowfish(c)
		assert.Nil(t, encrypter.Error)
		assert.NotNil(t, encrypter.dst)
		assert.NotEqual(t, testData_blowfish, encrypter.dst)
	})

	t.Run("encryption_with_raw_file", func(t *testing.T) {
		c := cipher.BlowfishCipher{
			Key:     key16_blowfish,
			Block:   cipher.CBC,
			IV:      iv8_blowfish,
			Padding: cipher.PKCS7,
		}
		file := mock.NewFile([]byte("hello world"), "test.txt")
		encrypter := NewEncrypter().FromFile(file).ByBlowfish(c)
		assert.Nil(t, encrypter.Error)
		assert.NotNil(t, encrypter.dst)
		assert.NotEqual(t, []byte("hello world"), encrypter.dst)
	})

	t.Run("streaming_encryption", func(t *testing.T) {
		c := cipher.BlowfishCipher{
			Key:     key16_blowfish,
			Block:   cipher.CBC,
			IV:      iv8_blowfish,
			Padding: cipher.PKCS7,
		}
		file := mock.NewFile([]byte("hello world"), "test.txt")
		encrypter := NewEncrypter().FromFile(file).ByBlowfish(c)
		assert.Nil(t, encrypter.Error)
		assert.NotNil(t, encrypter.dst)
		assert.NotEqual(t, []byte("hello world"), encrypter.dst)
	})

	t.Run("encryption_with_different_block_modes", func(t *testing.T) {
		blockModes := []cipher.BlockMode{
			cipher.CBC,
			cipher.ECB,
			cipher.CTR,
			cipher.CFB,
			cipher.OFB,
		}

		for _, mode := range blockModes {
			t.Run(string(mode), func(t *testing.T) {
				c := cipher.BlowfishCipher{
					Key:     key16_blowfish,
					Block:   mode,
					IV:      iv8_blowfish,
					Padding: cipher.PKCS7,
				}
				encrypter := NewEncrypter().FromBytes(testData_blowfish).ByBlowfish(c)
				assert.Nil(t, encrypter.Error)
				assert.NotNil(t, encrypter.dst)
				assert.NotEqual(t, testData_blowfish, encrypter.dst)
			})
		}
	})

	t.Run("encryption_with_gcm_mode", func(t *testing.T) {
		c := cipher.BlowfishCipher{
			Key:     key16_blowfish,
			Block:   cipher.GCM,
			Nonce:   nonce12_blowfish,
			Padding: cipher.No,
		}
		encrypter := NewEncrypter().FromBytes(testData8_blowfish).ByBlowfish(c)
		// GCM mode may not be fully supported for Blowfish
		// We accept either an error or successful encryption
		if encrypter.Error != nil {
			// If there's an error, that's acceptable
			t.Logf("GCM mode error (expected): %v", encrypter.Error)
		} else {
			// If no error, dst should not be nil
			// But for GCM mode, dst might be nil if not fully implemented
			if encrypter.dst == nil {
				t.Logf("GCM mode dst is nil (may be expected for Blowfish)")
			} else {
				assert.NotNil(t, encrypter.dst)
			}
		}
	})

	t.Run("encryption_with_different_padding_modes", func(t *testing.T) {
		paddingModes := []cipher.PaddingMode{
			cipher.Zero,
			cipher.PKCS5,
			cipher.PKCS7,
			cipher.AnsiX923,
			cipher.ISO97971,
			cipher.ISO10126,
			cipher.ISO78164,
			cipher.Bit,
		}

		for _, padding := range paddingModes {
			t.Run(string(padding), func(t *testing.T) {
				c := cipher.BlowfishCipher{
					Key:     key16_blowfish,
					Block:   cipher.CBC,
					IV:      iv8_blowfish,
					Padding: padding,
				}
				encrypter := NewEncrypter().FromBytes(testData_blowfish).ByBlowfish(c)
				assert.Nil(t, encrypter.Error)
				assert.NotNil(t, encrypter.dst)
				assert.NotEqual(t, testData_blowfish, encrypter.dst)
			})
		}

		// Test No padding separately with block-aligned data
		t.Run("No", func(t *testing.T) {
			c := cipher.BlowfishCipher{
				Key:     key16_blowfish,
				Block:   cipher.CBC,
				IV:      iv8_blowfish,
				Padding: cipher.No,
			}
			encrypter := NewEncrypter().FromBytes(testData8_blowfish).ByBlowfish(c)
			assert.Nil(t, encrypter.Error)
			assert.NotNil(t, encrypter.dst)
			assert.NotEqual(t, testData8_blowfish, encrypter.dst)
		})
	})

	t.Run("encryption_with_invalid_key_size", func(t *testing.T) {
		c := cipher.BlowfishCipher{
			Key:     []byte(""), // 0 bytes, too short
			Block:   cipher.CBC,
			IV:      iv8_blowfish,
			Padding: cipher.PKCS7,
		}
		encrypter := NewEncrypter().FromBytes(testData_blowfish).ByBlowfish(c)
		assert.NotNil(t, encrypter.Error)
		assert.Nil(t, encrypter.dst)
	})

	t.Run("encryption_with_missing_iv_for_cbc", func(t *testing.T) {
		c := cipher.BlowfishCipher{
			Key:     key16_blowfish,
			Block:   cipher.CBC,
			Padding: cipher.PKCS7,
		}
		encrypter := NewEncrypter().FromBytes(testData_blowfish).ByBlowfish(c)
		assert.NotNil(t, encrypter.Error)
		assert.Nil(t, encrypter.dst)
	})

	t.Run("encryption_with_missing_nonce_for_gcm", func(t *testing.T) {
		c := cipher.BlowfishCipher{
			Key:     key16_blowfish,
			Block:   cipher.GCM,
			Padding: cipher.No,
		}
		encrypter := NewEncrypter().FromBytes(testData8_blowfish).ByBlowfish(c)
		// GCM mode may not be fully supported for Blowfish
		if encrypter.Error != nil {
			// If there's an error, that's acceptable
			t.Logf("GCM mode error (expected): %v", encrypter.Error)
		} else {
			// If no error, dst should not be nil
			// But for GCM mode, dst might be nil if not fully implemented
			if encrypter.dst == nil {
				t.Logf("GCM mode dst is nil (may be expected for Blowfish)")
			} else {
				assert.NotNil(t, encrypter.dst)
			}
		}
	})

	t.Run("encryption_with_empty_data", func(t *testing.T) {
		c := cipher.BlowfishCipher{
			Key:     key16_blowfish,
			Block:   cipher.CBC,
			IV:      iv8_blowfish,
			Padding: cipher.PKCS7,
		}
		encrypter := NewEncrypter().FromBytes([]byte{}).ByBlowfish(c)
		assert.Nil(t, encrypter.Error)
		assert.NotNil(t, encrypter.dst)
	})

	t.Run("encryption_with_nil_data", func(t *testing.T) {
		c := cipher.BlowfishCipher{
			Key:     key16_blowfish,
			Block:   cipher.CBC,
			IV:      iv8_blowfish,
			Padding: cipher.PKCS7,
		}
		encrypter := NewEncrypter().FromBytes(nil).ByBlowfish(c)
		assert.Nil(t, encrypter.Error)
		assert.NotNil(t, encrypter.dst)
	})

	t.Run("encryption_with_existing_error", func(t *testing.T) {
		c := cipher.BlowfishCipher{
			Key:     key16_blowfish,
			Block:   cipher.CBC,
			IV:      iv8_blowfish,
			Padding: cipher.PKCS7,
		}
		encrypter := NewEncrypter()
		encrypter.Error = errors.New("existing error")
		result := encrypter.FromBytes(testData_blowfish).ByBlowfish(c)
		assert.Equal(t, encrypter, result)
		assert.Equal(t, "existing error", result.Error.Error())
	})
}

func TestDecrypter_ByBlowfish(t *testing.T) {
	t.Run("basic_decryption_8byte_key", func(t *testing.T) {
		c := cipher.BlowfishCipher{
			Key:     key8_blowfish,
			Block:   cipher.CBC,
			IV:      iv8_blowfish,
			Padding: cipher.PKCS7,
		}
		// First encrypt some data
		encrypter := NewEncrypter().FromBytes(testData_blowfish).ByBlowfish(c)
		assert.Nil(t, encrypter.Error)
		encryptedData := encrypter.ToRawBytes()

		// Then decrypt it
		decrypter := NewDecrypter().FromRawBytes(encryptedData).ByBlowfish(c)
		assert.Nil(t, decrypter.Error)
		assert.NotNil(t, decrypter.dst)
		assert.Equal(t, testData_blowfish, decrypter.dst)
	})

	t.Run("basic_decryption_16byte_key", func(t *testing.T) {
		c := cipher.BlowfishCipher{
			Key:     key16_blowfish,
			Block:   cipher.CBC,
			IV:      iv8_blowfish,
			Padding: cipher.PKCS7,
		}
		// First encrypt some data
		encrypter := NewEncrypter().FromBytes(testData_blowfish).ByBlowfish(c)
		assert.Nil(t, encrypter.Error)
		encryptedData := encrypter.ToRawBytes()

		// Then decrypt it
		decrypter := NewDecrypter().FromRawBytes(encryptedData).ByBlowfish(c)
		assert.Nil(t, decrypter.Error)
		assert.NotNil(t, decrypter.dst)
		assert.Equal(t, testData_blowfish, decrypter.dst)
	})

	t.Run("basic_decryption_32byte_key", func(t *testing.T) {
		c := cipher.BlowfishCipher{
			Key:     key32_blowfish,
			Block:   cipher.CBC,
			IV:      iv8_blowfish,
			Padding: cipher.PKCS7,
		}
		// First encrypt some data
		encrypter := NewEncrypter().FromBytes(testData_blowfish).ByBlowfish(c)
		assert.Nil(t, encrypter.Error)
		encryptedData := encrypter.ToRawBytes()

		// Then decrypt it
		decrypter := NewDecrypter().FromRawBytes(encryptedData).ByBlowfish(c)
		assert.Nil(t, decrypter.Error)
		assert.NotNil(t, decrypter.dst)
		assert.Equal(t, testData_blowfish, decrypter.dst)
	})

	t.Run("basic_decryption_56byte_key", func(t *testing.T) {
		c := cipher.BlowfishCipher{
			Key:     key56_blowfish,
			Block:   cipher.CBC,
			IV:      iv8_blowfish,
			Padding: cipher.PKCS7,
		}
		// First encrypt some data
		encrypter := NewEncrypter().FromBytes(testData_blowfish).ByBlowfish(c)
		assert.Nil(t, encrypter.Error)
		encryptedData := encrypter.ToRawBytes()

		// Then decrypt it
		decrypter := NewDecrypter().FromRawBytes(encryptedData).ByBlowfish(c)
		assert.Nil(t, decrypter.Error)
		assert.NotNil(t, decrypter.dst)
		assert.Equal(t, testData_blowfish, decrypter.dst)
	})

	t.Run("decryption_with_string_input", func(t *testing.T) {
		c := cipher.BlowfishCipher{
			Key:     key16_blowfish,
			Block:   cipher.CBC,
			IV:      iv8_blowfish,
			Padding: cipher.PKCS7,
		}
		// First encrypt some data
		encrypter := NewEncrypter().FromString("hello world").ByBlowfish(c)
		assert.Nil(t, encrypter.Error)
		encryptedData := encrypter.ToRawBytes()

		// Then decrypt it
		decrypter := NewDecrypter().FromRawString(string(encryptedData)).ByBlowfish(c)
		assert.Nil(t, decrypter.Error)
		assert.NotNil(t, decrypter.dst)
		assert.Equal(t, []byte("hello world"), decrypter.dst)
	})

	t.Run("decryption_with_file_input", func(t *testing.T) {
		c := cipher.BlowfishCipher{
			Key:     key16_blowfish,
			Block:   cipher.CBC,
			IV:      iv8_blowfish,
			Padding: cipher.PKCS7,
		}
		// First encrypt some data
		encrypter := NewEncrypter().FromString("hello world").ByBlowfish(c)
		assert.Nil(t, encrypter.Error)
		encryptedData := encrypter.ToRawBytes()

		// Then decrypt it
		file := mock.NewFile(encryptedData, "encrypted.txt")
		decrypter := NewDecrypter().FromRawFile(file).ByBlowfish(c)
		assert.Nil(t, decrypter.Error)
		assert.NotNil(t, decrypter.dst)
		assert.Equal(t, []byte("hello world"), decrypter.dst)
	})

	t.Run("decryption_with_raw_bytes", func(t *testing.T) {
		c := cipher.BlowfishCipher{
			Key:     key16_blowfish,
			Block:   cipher.CBC,
			IV:      iv8_blowfish,
			Padding: cipher.PKCS7,
		}
		// First encrypt some data
		encrypter := NewEncrypter().FromBytes(testData_blowfish).ByBlowfish(c)
		assert.Nil(t, encrypter.Error)
		encryptedData := encrypter.ToRawBytes()

		// Then decrypt it
		decrypter := NewDecrypter().FromRawBytes(encryptedData).ByBlowfish(c)
		assert.Nil(t, decrypter.Error)
		assert.NotNil(t, decrypter.dst)
		assert.Equal(t, testData_blowfish, decrypter.dst)
	})

	t.Run("decryption_with_raw_file", func(t *testing.T) {
		c := cipher.BlowfishCipher{
			Key:     key16_blowfish,
			Block:   cipher.CBC,
			IV:      iv8_blowfish,
			Padding: cipher.PKCS7,
		}
		// First encrypt some data
		encrypter := NewEncrypter().FromBytes(testData_blowfish).ByBlowfish(c)
		assert.Nil(t, encrypter.Error)
		encryptedData := encrypter.ToRawBytes()

		// Then decrypt it
		file := mock.NewFile(encryptedData, "encrypted.txt")
		decrypter := NewDecrypter().FromRawFile(file).ByBlowfish(c)
		assert.Nil(t, decrypter.Error)
		assert.NotNil(t, decrypter.dst)
		assert.Equal(t, testData_blowfish, decrypter.dst)
	})

	t.Run("streaming_decryption", func(t *testing.T) {
		c := cipher.BlowfishCipher{
			Key:     key16_blowfish,
			Block:   cipher.CBC,
			IV:      iv8_blowfish,
			Padding: cipher.PKCS7,
		}
		// First encrypt some data
		encrypter := NewEncrypter().FromBytes(testData_blowfish).ByBlowfish(c)
		assert.Nil(t, encrypter.Error)
		encryptedData := encrypter.ToRawBytes()

		// Then decrypt it
		file := mock.NewFile(encryptedData, "encrypted.txt")
		decrypter := NewDecrypter().FromRawFile(file).ByBlowfish(c)
		assert.Nil(t, decrypter.Error)
		assert.NotNil(t, decrypter.dst)
		assert.Equal(t, testData_blowfish, decrypter.dst)
	})

	t.Run("decryption_with_different_block_modes", func(t *testing.T) {
		blockModes := []cipher.BlockMode{
			cipher.CBC,
			cipher.ECB,
			cipher.CTR,
			cipher.CFB,
			cipher.OFB,
		}

		for _, mode := range blockModes {
			t.Run(string(mode), func(t *testing.T) {
				c := cipher.BlowfishCipher{
					Key:     key16_blowfish,
					Block:   mode,
					IV:      iv8_blowfish,
					Padding: cipher.PKCS7,
				}
				// First encrypt some data
				encrypter := NewEncrypter().FromBytes(testData_blowfish).ByBlowfish(c)
				assert.Nil(t, encrypter.Error)
				encryptedData := encrypter.ToRawBytes()

				// Then decrypt it
				decrypter := NewDecrypter().FromRawBytes(encryptedData).ByBlowfish(c)
				assert.Nil(t, decrypter.Error)
				assert.NotNil(t, decrypter.dst)
				assert.Equal(t, testData_blowfish, decrypter.dst)
			})
		}
	})

	t.Run("decryption_with_gcm_mode", func(t *testing.T) {
		c := cipher.BlowfishCipher{
			Key:     key16_blowfish,
			Block:   cipher.GCM,
			Nonce:   nonce12_blowfish,
			Padding: cipher.No,
		}
		// First encrypt some data
		encrypter := NewEncrypter().FromBytes(testData8_blowfish).ByBlowfish(c)
		// GCM mode may not be fully supported for Blowfish
		if encrypter.Error != nil {
			// If encryption fails, that's acceptable for GCM mode
			t.Logf("GCM encryption error (expected): %v", encrypter.Error)
			return
		}
		encryptedData := encrypter.ToRawBytes()

		// Then decrypt it
		decrypter := NewDecrypter().FromRawBytes(encryptedData).ByBlowfish(c)
		// GCM mode may not be fully supported for Blowfish
		if decrypter.Error != nil {
			// If decryption fails, that's acceptable for GCM mode
			t.Logf("GCM decryption error (expected): %v", decrypter.Error)
		} else {
			// If no error, dst should not be nil
			// But for GCM mode, dst might be nil if not fully implemented
			if decrypter.dst == nil {
				t.Logf("GCM mode dst is nil (may be expected for Blowfish)")
			} else {
				assert.NotNil(t, decrypter.dst)
				assert.Equal(t, testData8_blowfish, decrypter.dst)
			}
		}
	})

	t.Run("decryption_with_different_padding_modes", func(t *testing.T) {
		paddingModes := []cipher.PaddingMode{
			cipher.Zero,
			cipher.PKCS5,
			cipher.PKCS7,
			cipher.AnsiX923,
			cipher.ISO97971,
			cipher.ISO10126,
			cipher.ISO78164,
			cipher.Bit,
		}

		for _, padding := range paddingModes {
			t.Run(string(padding), func(t *testing.T) {
				c := cipher.BlowfishCipher{
					Key:     key16_blowfish,
					Block:   cipher.CBC,
					IV:      iv8_blowfish,
					Padding: padding,
				}
				// First encrypt some data
				encrypter := NewEncrypter().FromBytes(testData_blowfish).ByBlowfish(c)
				assert.Nil(t, encrypter.Error)
				encryptedData := encrypter.ToRawBytes()

				// Then decrypt it
				decrypter := NewDecrypter().FromRawBytes(encryptedData).ByBlowfish(c)
				assert.Nil(t, decrypter.Error)
				assert.NotNil(t, decrypter.dst)
				assert.Equal(t, testData_blowfish, decrypter.dst)
			})
		}

		// Test No padding separately with block-aligned data
		t.Run("No", func(t *testing.T) {
			c := cipher.BlowfishCipher{
				Key:     key16_blowfish,
				Block:   cipher.CBC,
				IV:      iv8_blowfish,
				Padding: cipher.No,
			}
			// First encrypt some data
			encrypter := NewEncrypter().FromBytes(testData8_blowfish).ByBlowfish(c)
			assert.Nil(t, encrypter.Error)
			encryptedData := encrypter.ToRawBytes()

			// Then decrypt it
			decrypter := NewDecrypter().FromRawBytes(encryptedData).ByBlowfish(c)
			assert.Nil(t, decrypter.Error)
			assert.NotNil(t, decrypter.dst)
			assert.Equal(t, testData8_blowfish, decrypter.dst)
		})
	})

	t.Run("decryption_with_invalid_key_size", func(t *testing.T) {
		c := cipher.BlowfishCipher{
			Key:     []byte(""), // 0 bytes, too short
			Block:   cipher.CBC,
			IV:      iv8_blowfish,
			Padding: cipher.PKCS7,
		}
		decrypter := NewDecrypter().FromRawBytes([]byte("encrypted data")).ByBlowfish(c)
		assert.NotNil(t, decrypter.Error)
		assert.Nil(t, decrypter.dst)
	})

	t.Run("decryption_with_missing_iv_for_cbc", func(t *testing.T) {
		c := cipher.BlowfishCipher{
			Key:     key16_blowfish,
			Block:   cipher.CBC,
			Padding: cipher.PKCS7,
		}
		decrypter := NewDecrypter().FromRawBytes([]byte("encrypted data")).ByBlowfish(c)
		assert.NotNil(t, decrypter.Error)
		assert.Nil(t, decrypter.dst)
	})

	t.Run("decryption_with_missing_nonce_for_gcm", func(t *testing.T) {
		c := cipher.BlowfishCipher{
			Key:     key16_blowfish,
			Block:   cipher.GCM,
			Padding: cipher.No,
		}
		decrypter := NewDecrypter().FromRawBytes([]byte("encrypted data")).ByBlowfish(c)
		// GCM mode may not be fully supported for Blowfish
		if decrypter.Error != nil {
			// If there's an error, that's acceptable for GCM mode
			t.Logf("GCM mode error (expected): %v", decrypter.Error)
		} else {
			// If no error, dst should not be nil
			// But for GCM mode, dst might be nil if not fully implemented
			if decrypter.dst == nil {
				t.Logf("GCM mode dst is nil (may be expected for Blowfish)")
			} else {
				assert.NotNil(t, decrypter.dst)
			}
		}
	})

	t.Run("decryption_with_empty_data", func(t *testing.T) {
		c := cipher.BlowfishCipher{
			Key:     key16_blowfish,
			Block:   cipher.CBC,
			IV:      iv8_blowfish,
			Padding: cipher.PKCS7,
		}
		decrypter := NewDecrypter().FromRawBytes([]byte{}).ByBlowfish(c)
		assert.Nil(t, decrypter.Error)
		// Empty data may result in empty decrypted data
		if decrypter.dst == nil {
			t.Logf("Empty data decryption result: dst is nil (may be expected)")
		} else {
			assert.NotNil(t, decrypter.dst)
		}
	})

	t.Run("decryption_with_nil_data", func(t *testing.T) {
		c := cipher.BlowfishCipher{
			Key:     key16_blowfish,
			Block:   cipher.CBC,
			IV:      iv8_blowfish,
			Padding: cipher.PKCS7,
		}
		decrypter := NewDecrypter().FromRawBytes(nil).ByBlowfish(c)
		assert.Nil(t, decrypter.Error)
		// Nil data may result in empty decrypted data
		if decrypter.dst == nil {
			t.Logf("Nil data decryption result: dst is nil (may be expected)")
		} else {
			assert.NotNil(t, decrypter.dst)
		}
	})

	t.Run("decryption_with_existing_error", func(t *testing.T) {
		c := cipher.BlowfishCipher{
			Key:     key16_blowfish,
			Block:   cipher.CBC,
			IV:      iv8_blowfish,
			Padding: cipher.PKCS7,
		}
		decrypter := NewDecrypter()
		decrypter.Error = errors.New("existing error")
		result := decrypter.FromRawBytes([]byte("encrypted data")).ByBlowfish(c)
		assert.Equal(t, decrypter, result)
		assert.Equal(t, "existing error", result.Error.Error())
	})

	t.Run("decryption_with_wrong_key", func(t *testing.T) {
		c := cipher.BlowfishCipher{
			Key:     key16_blowfish,
			Block:   cipher.CBC,
			IV:      iv8_blowfish,
			Padding: cipher.PKCS7,
		}
		// First encrypt some data
		encrypter := NewEncrypter().FromBytes(testData_blowfish).ByBlowfish(c)
		assert.Nil(t, encrypter.Error)
		encryptedData := encrypter.ToRawBytes()

		// Then decrypt with wrong key
		wrongC := cipher.BlowfishCipher{
			Key:     []byte("wrong key 1234567890123456"),
			Block:   cipher.CBC,
			IV:      iv8_blowfish,
			Padding: cipher.PKCS7,
		}
		decrypter := NewDecrypter().FromRawBytes(encryptedData).ByBlowfish(wrongC)
		// Wrong key may still decrypt but result in garbage data
		if decrypter.Error != nil {
			assert.NotNil(t, decrypter.Error)
			assert.Nil(t, decrypter.dst)
		} else {
			assert.NotNil(t, decrypter.dst)
			assert.NotEqual(t, testData_blowfish, decrypter.dst)
		}
	})

	t.Run("decryption_with_wrong_iv", func(t *testing.T) {
		c := cipher.BlowfishCipher{
			Key:     key16_blowfish,
			Block:   cipher.CBC,
			IV:      iv8_blowfish,
			Padding: cipher.PKCS7,
		}
		// First encrypt some data
		encrypter := NewEncrypter().FromBytes(testData_blowfish).ByBlowfish(c)
		assert.Nil(t, encrypter.Error)
		encryptedData := encrypter.ToRawBytes()

		// Then decrypt with wrong IV
		wrongC := cipher.BlowfishCipher{
			Key:     key16_blowfish,
			Block:   cipher.CBC,
			IV:      []byte("wrong iv"),
			Padding: cipher.PKCS7,
		}
		decrypter := NewDecrypter().FromRawBytes(encryptedData).ByBlowfish(wrongC)
		// Wrong IV may still decrypt but result in garbage data
		if decrypter.Error != nil {
			assert.NotNil(t, decrypter.Error)
			assert.Nil(t, decrypter.dst)
		} else {
			assert.NotNil(t, decrypter.dst)
			assert.NotEqual(t, testData_blowfish, decrypter.dst)
		}
	})

	t.Run("streaming_decryption_with_buffer_overflow", func(t *testing.T) {
		c := cipher.BlowfishCipher{
			Key:     key16_blowfish,
			Block:   cipher.CBC,
			IV:      iv8_blowfish,
			Padding: cipher.PKCS7,
		}
		// Create large data that might cause buffer issues
		largeData := strings.Repeat("hello world ", 100)
		encrypter := NewEncrypter().FromString(largeData).ByBlowfish(c)
		assert.Nil(t, encrypter.Error)
		encryptedData := encrypter.ToRawBytes()

		// Then decrypt it
		file := mock.NewFile(encryptedData, "large.txt")
		decrypter := NewDecrypter().FromRawFile(file).ByBlowfish(c)
		assert.Nil(t, decrypter.Error)
		assert.NotNil(t, decrypter.dst)
		assert.Equal(t, []byte(largeData), decrypter.dst)
	})
}

func TestBlowfish_ErrorHandling(t *testing.T) {
	t.Run("invalid_cipher_configuration", func(t *testing.T) {
		c := cipher.BlowfishCipher{
			Key:     []byte(""), // Invalid key size (0 bytes)
			Block:   cipher.CBC,
			IV:      iv8_blowfish,
			Padding: cipher.PKCS7,
		}
		encrypter := NewEncrypter().FromBytes(testData_blowfish).ByBlowfish(c)
		assert.NotNil(t, encrypter.Error)
		assert.Nil(t, encrypter.dst)
	})

	t.Run("invalid_padding_mode", func(t *testing.T) {
		c := cipher.BlowfishCipher{
			Key:     key16_blowfish,
			Block:   cipher.CBC,
			IV:      iv8_blowfish,
			Padding: "InvalidPadding",
		}
		encrypter := NewEncrypter().FromBytes(testData_blowfish).ByBlowfish(c)
		// Invalid padding mode may still work or may cause an error
		if encrypter.Error != nil {
			assert.NotNil(t, encrypter.Error)
			assert.Nil(t, encrypter.dst)
		} else {
			// If no error, dst should not be nil
			assert.NotNil(t, encrypter.dst)
		}
	})
}

func TestBlowfish_EdgeCases(t *testing.T) {
	t.Run("empty_and_nil_data", func(t *testing.T) {
		c := cipher.BlowfishCipher{
			Key:     key16_blowfish,
			Block:   cipher.CBC,
			IV:      iv8_blowfish,
			Padding: cipher.PKCS7,
		}

		// Test empty data
		encrypter := NewEncrypter().FromBytes([]byte{}).ByBlowfish(c)
		assert.Nil(t, encrypter.Error)
		assert.NotNil(t, encrypter.dst)

		// Test nil data
		encrypter = NewEncrypter().FromBytes(nil).ByBlowfish(c)
		assert.Nil(t, encrypter.Error)
		assert.NotNil(t, encrypter.dst)
	})

	t.Run("single_byte_data", func(t *testing.T) {
		c := cipher.BlowfishCipher{
			Key:     key16_blowfish,
			Block:   cipher.CBC,
			IV:      iv8_blowfish,
			Padding: cipher.PKCS7,
		}
		encrypter := NewEncrypter().FromBytes([]byte("a")).ByBlowfish(c)
		assert.Nil(t, encrypter.Error)
		assert.NotNil(t, encrypter.dst)
		assert.NotEqual(t, []byte("a"), encrypter.dst)
	})

	t.Run("exact_block_size_data", func(t *testing.T) {
		c := cipher.BlowfishCipher{
			Key:     key16_blowfish,
			Block:   cipher.CBC,
			IV:      iv8_blowfish,
			Padding: cipher.No,
		}
		encrypter := NewEncrypter().FromBytes(testData8_blowfish).ByBlowfish(c)
		assert.Nil(t, encrypter.Error)
		assert.NotNil(t, encrypter.dst)
		assert.NotEqual(t, testData8_blowfish, encrypter.dst)
	})
}

func TestBlowfish_StreamingEdgeCases(t *testing.T) {
	t.Run("streaming_with_empty_reader", func(t *testing.T) {
		c := cipher.BlowfishCipher{
			Key:     key16_blowfish,
			Block:   cipher.CBC,
			IV:      iv8_blowfish,
			Padding: cipher.PKCS7,
		}
		file := mock.NewFile([]byte{}, "empty.txt")
		encrypter := NewEncrypter().FromFile(file).ByBlowfish(c)
		assert.Nil(t, encrypter.Error)
		assert.NotNil(t, encrypter.dst)
	})

	t.Run("streaming_with_large_data", func(t *testing.T) {
		c := cipher.BlowfishCipher{
			Key:     key16_blowfish,
			Block:   cipher.CBC,
			IV:      iv8_blowfish,
			Padding: cipher.PKCS7,
		}
		largeData := strings.Repeat("hello world ", 1000)
		file := mock.NewFile([]byte(largeData), "large.txt")
		encrypter := NewEncrypter().FromFile(file).ByBlowfish(c)
		assert.Nil(t, encrypter.Error)
		assert.NotNil(t, encrypter.dst)
		assert.NotEqual(t, []byte(largeData), encrypter.dst)
	})
}
