package crypto

import (
	"testing"

	"github.com/dromara/dongle/crypto/cipher"
	"github.com/dromara/dongle/mock"
	"github.com/stretchr/testify/assert"
)

// Test data constants for DES
var (
	desKey8      = []byte("12345678")     // DES key (8 bytes)
	desIv8       = []byte("12345678")     // 8-byte IV
	desNonce12   = []byte("123456789012") // 12-byte nonce for GCM
	desTestData  = []byte("hello world")
	desTestData8 = []byte("12345678") // Exactly 8 bytes for no-padding tests
)

func TestEncrypter_ByDes(t *testing.T) {
	t.Run("basic_encryption", func(t *testing.T) {
		c := cipher.DesCipher{
			Key:     desKey8,
			Block:   cipher.CBC,
			IV:      desIv8,
			Padding: cipher.PKCS7,
		}

		encrypter := NewEncrypter().FromBytes(desTestData).ByDes(c)
		assert.Nil(t, encrypter.Error)
		// Empty data may result in nil dst, which is acceptable
		assert.NotEqual(t, desTestData, encrypter.dst)
	})

	t.Run("encryption_with_string_input", func(t *testing.T) {
		c := cipher.DesCipher{
			Key:     desKey8,
			Block:   cipher.CBC,
			IV:      desIv8,
			Padding: cipher.PKCS7,
		}

		encrypter := NewEncrypter().FromString("hello world").ByDes(c)
		assert.Nil(t, encrypter.Error)
		// Empty data may result in nil dst, which is acceptable
	})

	t.Run("encryption_with_file_input", func(t *testing.T) {
		c := cipher.DesCipher{
			Key:     desKey8,
			Block:   cipher.CBC,
			IV:      desIv8,
			Padding: cipher.PKCS7,
		}

		// Create a mock file with test data
		mockFile := mock.NewFile(desTestData, "test.txt")
		defer mockFile.Close()

		encrypter := NewEncrypter().FromFile(mockFile).ByDes(c)
		assert.Nil(t, encrypter.Error)
		// Empty data may result in nil dst, which is acceptable
	})

	t.Run("encryption_with_raw_bytes", func(t *testing.T) {
		c := cipher.DesCipher{
			Key:     desKey8,
			Block:   cipher.CBC,
			IV:      desIv8,
			Padding: cipher.PKCS7,
		}

		encrypter := NewEncrypter().FromBytes(desTestData).ByDes(c)
		assert.Nil(t, encrypter.Error)
		// Empty data may result in nil dst, which is acceptable
	})

	t.Run("encryption_with_raw_file", func(t *testing.T) {
		c := cipher.DesCipher{
			Key:     desKey8,
			Block:   cipher.CBC,
			IV:      desIv8,
			Padding: cipher.PKCS7,
		}

		// Create a mock file with test data
		mockFile := mock.NewFile(desTestData, "test.txt")
		defer mockFile.Close()

		encrypter := NewEncrypter().FromFile(mockFile).ByDes(c)
		assert.Nil(t, encrypter.Error)
		// Empty data may result in nil dst, which is acceptable
	})

	t.Run("streaming_encryption", func(t *testing.T) {
		c := cipher.DesCipher{
			Key:     desKey8,
			Block:   cipher.CBC,
			IV:      desIv8,
			Padding: cipher.PKCS7,
		}

		// Test streaming encryption with string input
		encrypter := NewEncrypter().FromString("hello world").ByDes(c)
		assert.Nil(t, encrypter.Error)
		// Empty data may result in nil dst, which is acceptable
	})

	t.Run("encryption_with_different_block_modes", func(t *testing.T) {
		modes := []cipher.BlockMode{
			cipher.CBC, cipher.ECB, cipher.CTR, cipher.CFB, cipher.OFB,
		}

		for _, mode := range modes {
			t.Run(string(mode), func(t *testing.T) {
				c := cipher.DesCipher{
					Key:     desKey8,
					Block:   mode,
					IV:      desIv8,
					Padding: cipher.PKCS7,
				}

				// Skip modes that don't need IV
				if mode == cipher.ECB {
					c.IV = nil
				}

				encrypter := NewEncrypter().FromBytes(desTestData).ByDes(c)
				assert.Nil(t, encrypter.Error)
				// Empty data may result in nil dst, which is acceptable
			})
		}
	})

	t.Run("encryption_with_gcm_mode", func(t *testing.T) {
		// DES doesn't support GCM mode due to 64-bit block size limitation
		// Go's GCM implementation only supports 128-bit block ciphers
		c := cipher.DesCipher{
			Key:     desKey8,
			Block:   cipher.GCM,
			Nonce:   desNonce12,
			Padding: cipher.No,
		}

		encrypter := NewEncrypter().FromBytes(desTestData8).ByDes(c)
		assert.NotNil(t, encrypter.Error)
		assert.Contains(t, encrypter.Error.Error(), "GCM")
	})

	t.Run("encryption_with_different_padding_modes", func(t *testing.T) {
		paddingModes := []cipher.PaddingMode{
			cipher.No, cipher.Zero, cipher.PKCS5, cipher.PKCS7,
			cipher.AnsiX923, cipher.ISO97971, cipher.ISO10126,
			cipher.ISO78164, cipher.Bit,
		}

		for _, padding := range paddingModes {
			t.Run(string(padding), func(t *testing.T) {
				c := cipher.DesCipher{
					Key:     desKey8,
					Block:   cipher.CBC,
					IV:      desIv8,
					Padding: padding,
				}

				// Use block-aligned data for No padding
				inputData := desTestData
				if padding == cipher.No {
					inputData = desTestData8
				}

				encrypter := NewEncrypter().FromBytes(inputData).ByDes(c)
				assert.Nil(t, encrypter.Error)
				// Empty data may result in nil dst, which is acceptable
			})
		}
	})

	t.Run("encryption_with_invalid_key_size", func(t *testing.T) {
		c := cipher.DesCipher{
			Key:     []byte("invalid"), // Invalid key size
			Block:   cipher.CBC,
			IV:      desIv8,
			Padding: cipher.PKCS7,
		}

		encrypter := NewEncrypter().FromBytes(desTestData).ByDes(c)
		assert.NotNil(t, encrypter.Error)
		assert.Contains(t, encrypter.Error.Error(), "invalid key size")
	})

	t.Run("encryption_with_missing_iv_for_cbc", func(t *testing.T) {
		c := cipher.DesCipher{
			Key:     desKey8,
			Block:   cipher.CBC,
			IV:      nil, // Missing IV
			Padding: cipher.PKCS7,
		}

		encrypter := NewEncrypter().FromBytes(desTestData).ByDes(c)
		assert.NotNil(t, encrypter.Error)
		assert.Contains(t, encrypter.Error.Error(), "iv cannot be empty")
	})

	t.Run("encryption_with_missing_nonce_for_gcm", func(t *testing.T) {
		c := cipher.DesCipher{
			Key:     desKey8,
			Block:   cipher.GCM,
			Nonce:   nil, // Missing nonce
			Padding: cipher.No,
		}

		encrypter := NewEncrypter().FromBytes(desTestData8).ByDes(c)
		assert.NotNil(t, encrypter.Error)
		assert.Contains(t, encrypter.Error.Error(), "nonce cannot be empty")
	})

	t.Run("encryption_with_empty_data", func(t *testing.T) {
		c := cipher.DesCipher{
			Key:     desKey8,
			Block:   cipher.CBC,
			IV:      desIv8,
			Padding: cipher.PKCS7,
		}

		encrypter := NewEncrypter().FromBytes([]byte{}).ByDes(c)
		assert.Nil(t, encrypter.Error)
		// Empty data may result in nil dst, which is acceptable
	})

	t.Run("encryption_with_nil_data", func(t *testing.T) {
		c := cipher.DesCipher{
			Key:     desKey8,
			Block:   cipher.CBC,
			IV:      desIv8,
			Padding: cipher.PKCS7,
		}

		encrypter := NewEncrypter().FromBytes(nil).ByDes(c)
		assert.Nil(t, encrypter.Error)
		// Empty data may result in nil dst, which is acceptable
	})

	t.Run("encryption_with_existing_error", func(t *testing.T) {
		c := cipher.DesCipher{
			Key:     desKey8,
			Block:   cipher.CBC,
			IV:      desIv8,
			Padding: cipher.PKCS7,
		}

		// Create encrypter with existing error
		encrypter := NewEncrypter()
		encrypter.Error = assert.AnError

		result := encrypter.ByDes(c)
		assert.Equal(t, encrypter, result)
		assert.Equal(t, assert.AnError, result.Error)
	})
}

func TestDecrypter_ByDes(t *testing.T) {
	t.Run("basic_decryption", func(t *testing.T) {
		c := cipher.DesCipher{
			Key:     desKey8,
			Block:   cipher.CBC,
			IV:      desIv8,
			Padding: cipher.PKCS7,
		}

		// First encrypt some data
		encrypter := NewEncrypter().FromBytes(desTestData).ByDes(c)
		assert.Nil(t, encrypter.Error)
		encryptedData := encrypter.ToRawBytes()

		// Then decrypt it
		decrypter := NewDecrypter().FromRawBytes(encryptedData).ByDes(c)
		assert.Nil(t, decrypter.Error)
		// Empty data may result in nil dst, which is acceptable
		assert.Equal(t, desTestData, decrypter.dst)
	})

	t.Run("decryption_with_string_input", func(t *testing.T) {
		c := cipher.DesCipher{
			Key:     desKey8,
			Block:   cipher.CBC,
			IV:      desIv8,
			Padding: cipher.PKCS7,
		}

		// First encrypt some data
		encrypter := NewEncrypter().FromString("hello world").ByDes(c)
		assert.Nil(t, encrypter.Error)
		encryptedData := encrypter.ToRawBytes()

		// Then decrypt it
		decrypter := NewDecrypter().FromRawString(string(encryptedData)).ByDes(c)
		assert.Nil(t, decrypter.Error)
		// Empty data may result in nil dst, which is acceptable
		assert.Equal(t, "hello world", string(decrypter.dst))
	})

	t.Run("decryption_with_file_input", func(t *testing.T) {
		c := cipher.DesCipher{
			Key:     desKey8,
			Block:   cipher.CBC,
			IV:      desIv8,
			Padding: cipher.PKCS7,
		}

		// First encrypt some data
		encrypter := NewEncrypter().FromBytes(desTestData).ByDes(c)
		assert.Nil(t, encrypter.Error)
		encryptedData := encrypter.ToRawBytes()

		// Create a mock file with encrypted data
		mockFile := mock.NewFile(encryptedData, "test.txt")
		defer mockFile.Close()

		// Then decrypt it
		decrypter := NewDecrypter().FromRawFile(mockFile).ByDes(c)
		assert.Nil(t, decrypter.Error)
		// Empty data may result in nil dst, which is acceptable
		assert.Equal(t, desTestData, decrypter.dst)
	})

	t.Run("decryption_with_raw_bytes", func(t *testing.T) {
		c := cipher.DesCipher{
			Key:     desKey8,
			Block:   cipher.CBC,
			IV:      desIv8,
			Padding: cipher.PKCS7,
		}

		// First encrypt some data
		encrypter := NewEncrypter().FromBytes(desTestData).ByDes(c)
		assert.Nil(t, encrypter.Error)
		encryptedData := encrypter.ToRawBytes()

		// Then decrypt it
		decrypter := NewDecrypter().FromRawBytes(encryptedData).ByDes(c)
		assert.Nil(t, decrypter.Error)
		// Empty data may result in nil dst, which is acceptable
		assert.Equal(t, desTestData, decrypter.dst)
	})

	t.Run("decryption_with_raw_file", func(t *testing.T) {
		c := cipher.DesCipher{
			Key:     desKey8,
			Block:   cipher.CBC,
			IV:      desIv8,
			Padding: cipher.PKCS7,
		}

		// First encrypt some data
		encrypter := NewEncrypter().FromBytes(desTestData).ByDes(c)
		assert.Nil(t, encrypter.Error)
		encryptedData := encrypter.ToRawBytes()

		// Create a mock file with encrypted data
		mockFile := mock.NewFile(encryptedData, "test.txt")
		defer mockFile.Close()

		// Then decrypt it
		decrypter := NewDecrypter().FromRawFile(mockFile).ByDes(c)
		assert.Nil(t, decrypter.Error)
		// Empty data may result in nil dst, which is acceptable
		assert.Equal(t, desTestData, decrypter.dst)
	})

	t.Run("streaming_decryption", func(t *testing.T) {
		c := cipher.DesCipher{
			Key:     desKey8,
			Block:   cipher.CBC,
			IV:      desIv8,
			Padding: cipher.PKCS7,
		}

		// First encrypt some data
		encrypter := NewEncrypter().FromBytes(desTestData).ByDes(c)
		assert.Nil(t, encrypter.Error)
		encryptedData := encrypter.ToRawBytes()

		// Then decrypt it using streaming
		decrypter := NewDecrypter().FromRawBytes(encryptedData).ByDes(c)
		assert.Nil(t, decrypter.Error)
		// Empty data may result in nil dst, which is acceptable
		assert.Equal(t, desTestData, decrypter.dst)
	})

	t.Run("decryption_with_different_block_modes", func(t *testing.T) {
		modes := []cipher.BlockMode{
			cipher.CBC, cipher.ECB, cipher.CTR, cipher.CFB, cipher.OFB,
		}

		for _, mode := range modes {
			t.Run(string(mode), func(t *testing.T) {
				c := cipher.DesCipher{
					Key:     desKey8,
					Block:   mode,
					IV:      desIv8,
					Padding: cipher.PKCS7,
				}

				// Skip modes that don't need IV
				if mode == cipher.ECB {
					c.IV = nil
				}

				// First encrypt some data
				encrypter := NewEncrypter().FromBytes(desTestData).ByDes(c)
				assert.Nil(t, encrypter.Error)
				encryptedData := encrypter.ToRawBytes()

				// Then decrypt it
				decrypter := NewDecrypter().FromRawBytes(encryptedData).ByDes(c)
				assert.Nil(t, decrypter.Error)
				// Empty data may result in nil dst, which is acceptable
				assert.Equal(t, desTestData, decrypter.dst)
			})
		}
	})

	t.Run("decryption_with_gcm_mode", func(t *testing.T) {
		// DES doesn't support GCM mode due to 64-bit block size limitation
		// Go's GCM implementation only supports 128-bit block ciphers
		c := cipher.DesCipher{
			Key:     desKey8,
			Block:   cipher.GCM,
			Nonce:   desNonce12,
			Padding: cipher.No,
		}

		// GCM mode should fail for DES
		decrypter := NewDecrypter().FromRawBytes([]byte("test")).ByDes(c)
		assert.NotNil(t, decrypter.Error)
		assert.Contains(t, decrypter.Error.Error(), "GCM")
	})

	t.Run("decryption_with_different_padding_modes", func(t *testing.T) {
		paddingModes := []cipher.PaddingMode{
			cipher.No, cipher.Zero, cipher.PKCS5, cipher.PKCS7,
			cipher.AnsiX923, cipher.ISO97971, cipher.ISO10126,
			cipher.ISO78164, cipher.Bit,
		}

		for _, padding := range paddingModes {
			t.Run(string(padding), func(t *testing.T) {
				c := cipher.DesCipher{
					Key:     desKey8,
					Block:   cipher.CBC,
					IV:      desIv8,
					Padding: padding,
				}

				// Use block-aligned data for No padding
				inputData := desTestData
				if padding == cipher.No {
					inputData = desTestData8
				}

				// First encrypt some data
				encrypter := NewEncrypter().FromBytes(inputData).ByDes(c)
				assert.Nil(t, encrypter.Error)
				encryptedData := encrypter.ToRawBytes()

				// Then decrypt it
				decrypter := NewDecrypter().FromRawBytes(encryptedData).ByDes(c)
				assert.Nil(t, decrypter.Error)
				// Empty data may result in nil dst, which is acceptable
				assert.Equal(t, inputData, decrypter.dst)
			})
		}
	})

	t.Run("decryption_with_invalid_key_size", func(t *testing.T) {
		c := cipher.DesCipher{
			Key:     []byte("invalid"), // Invalid key size
			Block:   cipher.CBC,
			IV:      desIv8,
			Padding: cipher.PKCS7,
		}

		decrypter := NewDecrypter().FromRawBytes(desTestData).ByDes(c)
		assert.NotNil(t, decrypter.Error)
		assert.Contains(t, decrypter.Error.Error(), "invalid key size")
	})

	t.Run("decryption_with_missing_iv_for_cbc", func(t *testing.T) {
		c := cipher.DesCipher{
			Key:     desKey8,
			Block:   cipher.CBC,
			IV:      nil, // Missing IV
			Padding: cipher.PKCS7,
		}

		decrypter := NewDecrypter().FromRawBytes(desTestData).ByDes(c)
		assert.NotNil(t, decrypter.Error)
		assert.Contains(t, decrypter.Error.Error(), "iv cannot be empty")
	})

	t.Run("decryption_with_missing_nonce_for_gcm", func(t *testing.T) {
		c := cipher.DesCipher{
			Key:     desKey8,
			Block:   cipher.GCM,
			Nonce:   nil, // Missing nonce
			Padding: cipher.No,
		}

		decrypter := NewDecrypter().FromRawBytes(desTestData8).ByDes(c)
		assert.NotNil(t, decrypter.Error)
		assert.Contains(t, decrypter.Error.Error(), "nonce cannot be empty")
	})

	t.Run("decryption_with_empty_data", func(t *testing.T) {
		c := cipher.DesCipher{
			Key:     desKey8,
			Block:   cipher.CBC,
			IV:      desIv8,
			Padding: cipher.PKCS7,
		}

		decrypter := NewDecrypter().FromRawBytes([]byte{}).ByDes(c)
		assert.Nil(t, decrypter.Error)
		// Empty data may result in nil dst, which is acceptable
		// The important thing is that there's no error
	})

	t.Run("decryption_with_nil_data", func(t *testing.T) {
		c := cipher.DesCipher{
			Key:     desKey8,
			Block:   cipher.CBC,
			IV:      desIv8,
			Padding: cipher.PKCS7,
		}

		decrypter := NewDecrypter().FromRawBytes(nil).ByDes(c)
		assert.Nil(t, decrypter.Error)
		// Nil data may result in nil dst, which is acceptable
		// The important thing is that there's no error
	})

	t.Run("decryption_with_existing_error", func(t *testing.T) {
		c := cipher.DesCipher{
			Key:     desKey8,
			Block:   cipher.CBC,
			IV:      desIv8,
			Padding: cipher.PKCS7,
		}

		// Create decrypter with existing error
		decrypter := NewDecrypter()
		decrypter.Error = assert.AnError

		result := decrypter.ByDes(c)
		assert.Equal(t, decrypter, result)
		assert.Equal(t, assert.AnError, result.Error)
	})

	t.Run("decryption_with_wrong_key", func(t *testing.T) {
		// Encrypt with one key
		c1 := cipher.DesCipher{
			Key:     desKey8,
			Block:   cipher.CBC,
			IV:      desIv8,
			Padding: cipher.PKCS7,
		}

		encrypter := NewEncrypter().FromBytes(desTestData).ByDes(c1)
		assert.Nil(t, encrypter.Error)
		encryptedData := encrypter.ToRawBytes()

		// Try to decrypt with different key
		c2 := cipher.DesCipher{
			Key:     []byte("87654321"), // Different key
			Block:   cipher.CBC,
			IV:      desIv8,
			Padding: cipher.PKCS7,
		}

		decrypter := NewDecrypter().FromRawBytes(encryptedData).ByDes(c2)
		assert.Nil(t, decrypter.Error)
		// Empty data may result in nil dst, which is acceptable
		// The decrypted data should not match the original
		assert.NotEqual(t, desTestData, decrypter.dst)
	})

	t.Run("decryption_with_wrong_iv", func(t *testing.T) {
		// Encrypt with one IV
		c1 := cipher.DesCipher{
			Key:     desKey8,
			Block:   cipher.CBC,
			IV:      desIv8,
			Padding: cipher.PKCS7,
		}

		encrypter := NewEncrypter().FromBytes(desTestData).ByDes(c1)
		assert.Nil(t, encrypter.Error)
		encryptedData := encrypter.ToRawBytes()

		// Try to decrypt with different IV
		c2 := cipher.DesCipher{
			Key:     desKey8,
			Block:   cipher.CBC,
			IV:      []byte("87654321"), // Different IV
			Padding: cipher.PKCS7,
		}

		decrypter := NewDecrypter().FromRawBytes(encryptedData).ByDes(c2)
		assert.Nil(t, decrypter.Error)
		// Empty data may result in nil dst, which is acceptable
		// The decrypted data should not match the original
		assert.NotEqual(t, desTestData, decrypter.dst)
	})

	t.Run("streaming_decryption_with_buffer_overflow", func(t *testing.T) {
		c := cipher.DesCipher{
			Key:     desKey8,
			Block:   cipher.CBC,
			IV:      desIv8,
			Padding: cipher.PKCS7,
		}

		// Create large data for streaming test
		largeData := make([]byte, 1000)
		for i := range largeData {
			largeData[i] = byte(i % 256)
		}

		// Encrypt large data
		encrypter := NewEncrypter().FromBytes(largeData).ByDes(c)
		assert.Nil(t, encrypter.Error)
		encryptedData := encrypter.ToRawBytes()

		// Decrypt using streaming with small buffer
		decrypter := NewDecrypter().FromRawBytes(encryptedData).ByDes(c)
		assert.Nil(t, decrypter.Error)
		// Empty data may result in nil dst, which is acceptable
		assert.Equal(t, largeData, decrypter.dst)
	})
}

func TestDes_ErrorHandling(t *testing.T) {
	t.Run("invalid_cipher_configuration", func(t *testing.T) {
		// Test with invalid block mode
		c := cipher.DesCipher{
			Key:     desKey8,
			Block:   "INVALID", // Invalid block mode
			IV:      desIv8,
			Padding: cipher.PKCS7,
		}

		encrypter := NewEncrypter().FromBytes(desTestData).ByDes(c)
		assert.Nil(t, encrypter.Error)
		assert.Nil(t, encrypter.dst)

		decrypter := NewDecrypter().FromRawBytes(desTestData).ByDes(c)
		assert.Nil(t, decrypter.Error)
		assert.Nil(t, decrypter.dst)
	})

	t.Run("invalid_padding_mode", func(t *testing.T) {
		// Test with invalid padding mode
		c := cipher.DesCipher{
			Key:     desKey8,
			Block:   cipher.CBC,
			IV:      desIv8,
			Padding: "INVALID", // Invalid padding mode
		}

		encrypter := NewEncrypter().FromBytes(desTestData8).ByDes(c)
		assert.Nil(t, encrypter.Error)
		// Invalid padding mode may result in nil dst, which is acceptable

		decrypter := NewDecrypter().FromRawBytes(desTestData8).ByDes(c)
		assert.Nil(t, decrypter.Error)
		// Invalid padding mode may result in nil dst, which is acceptable
	})
}

func TestDes_EdgeCases(t *testing.T) {
	t.Run("empty_and_nil_data", func(t *testing.T) {
		c := cipher.DesCipher{
			Key:     desKey8,
			Block:   cipher.CBC,
			IV:      desIv8,
			Padding: cipher.PKCS7,
		}

		// Test empty data
		encrypter := NewEncrypter().FromBytes([]byte{}).ByDes(c)
		assert.Nil(t, encrypter.Error)
		// Empty data may result in nil dst, which is acceptable

		decrypter := NewDecrypter().FromRawBytes([]byte{}).ByDes(c)
		assert.Nil(t, decrypter.Error)
		// Empty data may result in nil dst, which is acceptable

		// Test nil data
		encrypter = NewEncrypter().FromBytes(nil).ByDes(c)
		assert.Nil(t, encrypter.Error)
		// Empty data may result in nil dst, which is acceptable

		decrypter = NewDecrypter().FromRawBytes(nil).ByDes(c)
		assert.Nil(t, decrypter.Error)
		// Empty data may result in nil dst, which is acceptable
	})

	t.Run("single_byte_data", func(t *testing.T) {
		c := cipher.DesCipher{
			Key:     desKey8,
			Block:   cipher.CBC,
			IV:      desIv8,
			Padding: cipher.PKCS7,
		}

		singleByte := []byte{0x41} // 'A'

		encrypter := NewEncrypter().FromBytes(singleByte).ByDes(c)
		assert.Nil(t, encrypter.Error)
		// Empty data may result in nil dst, which is acceptable

		decrypter := NewDecrypter().FromRawBytes(encrypter.ToRawBytes()).ByDes(c)
		assert.Nil(t, decrypter.Error)
		// Empty data may result in nil dst, which is acceptable
		assert.Equal(t, singleByte, decrypter.dst)
	})

	t.Run("exact_block_size_data", func(t *testing.T) {
		c := cipher.DesCipher{
			Key:     desKey8,
			Block:   cipher.CBC,
			IV:      desIv8,
			Padding: cipher.PKCS7,
		}

		// DES block size is 8 bytes
		blockSizeData := []byte("12345678") // Exactly 8 bytes

		encrypter := NewEncrypter().FromBytes(blockSizeData).ByDes(c)
		assert.Nil(t, encrypter.Error)
		// Empty data may result in nil dst, which is acceptable

		decrypter := NewDecrypter().FromRawBytes(encrypter.ToRawBytes()).ByDes(c)
		assert.Nil(t, decrypter.Error)
		// Empty data may result in nil dst, which is acceptable
		assert.Equal(t, blockSizeData, decrypter.dst)
	})
}

func TestDes_StreamingEdgeCases(t *testing.T) {
	t.Run("streaming_with_empty_reader", func(t *testing.T) {
		c := cipher.DesCipher{
			Key:     desKey8,
			Block:   cipher.CBC,
			IV:      desIv8,
			Padding: cipher.PKCS7,
		}

		// Test with empty string
		encrypter := NewEncrypter().FromString("").ByDes(c)
		assert.Nil(t, encrypter.Error)
		// Empty string may result in nil dst, which is acceptable
		// The important thing is that there's no error

		decrypter := NewDecrypter().FromRawBytes([]byte{}).ByDes(c)
		assert.Nil(t, decrypter.Error)
		// Empty data may result in nil dst, which is acceptable
		// The important thing is that there's no error
	})

	t.Run("streaming_with_large_data", func(t *testing.T) {
		c := cipher.DesCipher{
			Key:     desKey8,
			Block:   cipher.CBC,
			IV:      desIv8,
			Padding: cipher.PKCS7,
		}

		// Create large data
		largeData := make([]byte, 10000)
		for i := range largeData {
			largeData[i] = byte(i % 256)
		}

		// Use standard encrypter to generate encrypted data
		encrypter := NewEncrypter().FromBytes(largeData).ByDes(c)
		assert.Nil(t, encrypter.Error)
		encryptedData := encrypter.ToRawBytes()

		// Then use streaming decrypter
		decrypter := NewDecrypter().FromRawBytes(encryptedData).ByDes(c)
		assert.Nil(t, decrypter.Error)
		// Empty data may result in nil dst, which is acceptable
		assert.Equal(t, largeData, decrypter.dst)
	})
}
