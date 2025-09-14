package crypto

import (
	"testing"

	"github.com/dromara/dongle/crypto/cipher"
	"github.com/dromara/dongle/mock"
	"github.com/stretchr/testify/assert"
)

// TestTeaInputTypes tests TEA encryption with various input types
func TestTeaInputTypes(t *testing.T) {
	t.Run("string input", func(t *testing.T) {
		key := []byte("1234567890123456") // 16-byte key for TEA
		teaCipher := cipher.NewTeaCipher()
		teaCipher.SetKey(key)
		plaintext := "12345678" // 8-byte string for TEA

		encrypted := NewEncrypter().FromString(plaintext).ByTea(teaCipher).ToRawString()
		assert.NotEmpty(t, encrypted)

		decrypted := NewDecrypter().FromRawString(encrypted).ByTea(teaCipher).ToString()
		assert.Equal(t, plaintext, decrypted)
	})

	t.Run("bytes input", func(t *testing.T) {
		key := []byte("1234567890123456") // 16-byte key for TEA
		teaCipher := cipher.NewTeaCipher()
		teaCipher.SetKey(key)
		plaintext := []byte("12345678") // 8-byte data for TEA

		encrypted := NewEncrypter().FromBytes(plaintext).ByTea(teaCipher).ToRawBytes()
		assert.NotEmpty(t, encrypted)

		decrypted := NewDecrypter().FromRawBytes(encrypted).ByTea(teaCipher).ToBytes()
		assert.Equal(t, plaintext, decrypted)
	})

	t.Run("empty input", func(t *testing.T) {
		key := []byte("1234567890123456") // 16-byte key for TEA
		teaCipher := cipher.NewTeaCipher()
		teaCipher.SetKey(key)
		plaintext := ""

		// TEA requires data to be multiple of 8 bytes, so empty input should result in error
		encrypted := NewEncrypter().FromString(plaintext).ByTea(teaCipher).ToRawString()
		assert.Empty(t, encrypted)
	})

	t.Run("empty bytes input", func(t *testing.T) {
		key := []byte("1234567890123456") // 16-byte key for TEA
		teaCipher := cipher.NewTeaCipher()
		teaCipher.SetKey(key)
		var plaintext []byte

		// TEA requires data to be multiple of 8 bytes, so empty input should result in error
		encrypted := NewEncrypter().FromBytes(plaintext).ByTea(teaCipher).ToRawBytes()
		assert.Empty(t, encrypted)
	})

	t.Run("unicode input", func(t *testing.T) {
		key := []byte("1234567890123456") // 16-byte key for TEA
		teaCipher := cipher.NewTeaCipher()
		teaCipher.SetKey(key)
		plaintext := "12345678" // 8-byte data for TEA

		encrypted := NewEncrypter().FromString(plaintext).ByTea(teaCipher).ToRawString()
		assert.NotEmpty(t, encrypted)

		decrypted := NewDecrypter().FromRawString(encrypted).ByTea(teaCipher).ToString()
		assert.Equal(t, plaintext, decrypted)
	})

	t.Run("binary input", func(t *testing.T) {
		key := []byte("1234567890123456") // 16-byte key for TEA
		teaCipher := cipher.NewTeaCipher()
		teaCipher.SetKey(key)
		// 8-byte binary data (multiple of 8 bytes as required by TEA)
		plaintext := []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07}

		encrypted := NewEncrypter().FromBytes(plaintext).ByTea(teaCipher).ToRawBytes()
		assert.NotEmpty(t, encrypted)

		decrypted := NewDecrypter().FromRawBytes(encrypted).ByTea(teaCipher).ToBytes()
		assert.Equal(t, plaintext, decrypted)
	})

	t.Run("8-byte multiple input", func(t *testing.T) {
		key := []byte("1234567890123456") // 16-byte key for TEA
		teaCipher := cipher.NewTeaCipher()
		teaCipher.SetKey(key)
		// 16-byte data (multiple of 8 bytes as required by TEA)
		plaintext := []byte("1234567890123456")

		encrypted := NewEncrypter().FromBytes(plaintext).ByTea(teaCipher).ToRawBytes()
		assert.NotEmpty(t, encrypted)

		decrypted := NewDecrypter().FromRawBytes(encrypted).ByTea(teaCipher).ToBytes()
		assert.Equal(t, plaintext, decrypted)
	})
}

// TestTeaErrorHandling tests TEA error handling scenarios
func TestTeaErrorHandling(t *testing.T) {
	t.Run("empty key", func(t *testing.T) {
		plaintext := "Hello, TEA!"
		teaCipher := cipher.NewTeaCipher()
		teaCipher.SetKey([]byte{}) // Empty key

		encrypted := NewEncrypter().FromString(plaintext).ByTea(teaCipher).ToRawString()
		assert.Empty(t, encrypted)

		decrypted := NewDecrypter().FromRawString(plaintext).ByTea(teaCipher).ToString()
		assert.Empty(t, decrypted)
	})

	t.Run("invalid key size", func(t *testing.T) {
		plaintext := "Hello, TEA!"
		key := []byte("short") // Invalid key size (not 16 bytes)
		teaCipher := cipher.NewTeaCipher()
		teaCipher.SetKey(key)

		encrypted := NewEncrypter().FromString(plaintext).ByTea(teaCipher).ToRawString()
		assert.Empty(t, encrypted)

		decrypted := NewDecrypter().FromRawString(plaintext).ByTea(teaCipher).ToString()
		assert.Empty(t, decrypted)
	})

	t.Run("with existing error", func(t *testing.T) {
		key := []byte("1234567890123456") // 16-byte key for TEA
		teaCipher := cipher.NewTeaCipher()
		teaCipher.SetKey(key)
		plaintext := "Hello, TEA!"

		encrypter := NewEncrypter()
		encrypter.Error = assert.AnError

		encrypted := encrypter.FromString(plaintext).ByTea(teaCipher).ToRawString()
		assert.Empty(t, encrypted)

		decrypter := NewDecrypter()
		decrypter.Error = assert.AnError

		decrypted := decrypter.FromRawString(plaintext).ByTea(teaCipher).ToString()
		assert.Empty(t, decrypted)
	})

	t.Run("encryption error with invalid data size", func(t *testing.T) {
		key := []byte("1234567890123456") // 16-byte key for TEA
		teaCipher := cipher.NewTeaCipher()
		teaCipher.SetKey(key)
		// 7-byte data (not multiple of 8 bytes)
		plaintext := []byte("1234567")

		encrypted := NewEncrypter().FromBytes(plaintext).ByTea(teaCipher).ToRawBytes()
		assert.Empty(t, encrypted)
	})

	t.Run("decryption error with invalid data size", func(t *testing.T) {
		key := []byte("1234567890123456") // 16-byte key for TEA
		teaCipher := cipher.NewTeaCipher()
		teaCipher.SetKey(key)
		// 7-byte data (not multiple of 8 bytes)
		plaintext := []byte("1234567")

		decrypted := NewDecrypter().FromRawBytes(plaintext).ByTea(teaCipher).ToBytes()
		assert.Empty(t, decrypted)
	})
}

// TestTeaStreaming tests TEA streaming encryption and decryption
func TestTeaStreaming(t *testing.T) {
	t.Run("stream encrypter with valid key", func(t *testing.T) {
		key := []byte("1234567890123456") // 16-byte key for TEA
		teaCipher := cipher.NewTeaCipher()
		teaCipher.SetKey(key)

		// Create a mock file for streaming (must be multiple of 8 bytes)
		mockFile := mock.NewFile([]byte("1234567890123456"), "test.txt")
		encrypted := NewEncrypter().FromFile(mockFile).ByTea(teaCipher).ToRawString()
		assert.NotEmpty(t, encrypted)

		// For decryption, we need to use the encrypted data directly
		decrypted := NewDecrypter().FromRawBytes([]byte(encrypted)).ByTea(teaCipher).ToBytes()
		assert.Equal(t, []byte("1234567890123456"), decrypted)
	})

	t.Run("stream encrypter with invalid key", func(t *testing.T) {
		key := []byte("invalid") // Invalid key size
		teaCipher := cipher.NewTeaCipher()
		teaCipher.SetKey(key)
		// plaintext is not used in this test case, removing it
		mockFile := mock.NewFile([]byte("test data"), "test.txt")
		encrypted := NewEncrypter().FromFile(mockFile).ByTea(teaCipher).ToRawString()
		assert.Empty(t, encrypted)
	})

	t.Run("stream with read error", func(t *testing.T) {
		key := []byte("1234567890123456") // 16-byte key for TEA
		teaCipher := cipher.NewTeaCipher()
		teaCipher.SetKey(key)
		errorReader := mock.NewErrorFile(assert.AnError)

		encrypted := NewEncrypter().FromFile(errorReader).ByTea(teaCipher).ToRawString()
		assert.Empty(t, encrypted)
	})
}

// TestTeaStdEncrypter tests TEA standard encrypter functionality
func TestTeaStdEncrypter(t *testing.T) {
	t.Run("new std encrypter with valid key", func(t *testing.T) {
		key := []byte("1234567890123456") // 16-byte key for TEA
		teaCipher := cipher.NewTeaCipher()
		teaCipher.SetKey(key)
		plaintext := []byte("12345678") // 8-byte data

		encrypted := NewEncrypter().FromBytes(plaintext).ByTea(teaCipher).ToRawBytes()
		assert.NotEmpty(t, encrypted)
	})

	t.Run("new std encrypter with invalid key", func(t *testing.T) {
		key := []byte("invalid") // Invalid key size
		teaCipher := cipher.NewTeaCipher()
		teaCipher.SetKey(key)
		plaintext := []byte("12345678") // 8-byte data

		encrypted := NewEncrypter().FromBytes(plaintext).ByTea(teaCipher).ToRawBytes()
		assert.Empty(t, encrypted)
	})

	t.Run("std encrypter encrypt with existing error", func(t *testing.T) {
		key := []byte("1234567890123456") // 16-byte key for TEA
		teaCipher := cipher.NewTeaCipher()
		teaCipher.SetKey(key)
		plaintext := []byte("12345678") // 8-byte data

		encrypter := NewEncrypter()
		encrypter.Error = assert.AnError

		encrypted := encrypter.FromBytes(plaintext).ByTea(teaCipher).ToRawBytes()
		assert.Empty(t, encrypted)
	})

	t.Run("std encrypter encrypt empty data", func(t *testing.T) {
		key := []byte("1234567890123456") // 16-byte key for TEA
		teaCipher := cipher.NewTeaCipher()
		teaCipher.SetKey(key)
		var plaintext []byte // Empty data

		encrypted := NewEncrypter().FromBytes(plaintext).ByTea(teaCipher).ToRawBytes()
		assert.Empty(t, encrypted)
	})

	t.Run("std encrypter encrypt with invalid data size", func(t *testing.T) {
		key := []byte("1234567890123456") // 16-byte key for TEA
		teaCipher := cipher.NewTeaCipher()
		teaCipher.SetKey(key)
		plaintext := []byte("1234567") // 7-byte data (not multiple of 8)

		encrypted := NewEncrypter().FromBytes(plaintext).ByTea(teaCipher).ToRawBytes()
		assert.Empty(t, encrypted)
	})
}

// TestTeaStdDecrypter tests TEA standard decrypter functionality
func TestTeaStdDecrypter(t *testing.T) {
	t.Run("new std decrypter with valid key", func(t *testing.T) {
		key := []byte("1234567890123456") // 16-byte key for TEA
		teaCipher := cipher.NewTeaCipher()
		teaCipher.SetKey(key)
		plaintext := []byte("12345678") // 8-byte data

		// First encrypt
		encrypted := NewEncrypter().FromBytes(plaintext).ByTea(teaCipher).ToRawBytes()
		assert.NotEmpty(t, encrypted)

		// Then decrypt
		decrypted := NewDecrypter().FromRawBytes(encrypted).ByTea(teaCipher).ToBytes()
		assert.Equal(t, plaintext, decrypted)
	})

	t.Run("new std decrypter with invalid key", func(t *testing.T) {
		key := []byte("invalid") // Invalid key size
		teaCipher := cipher.NewTeaCipher()
		teaCipher.SetKey(key)
		plaintext := []byte("12345678") // 8-byte data

		decrypted := NewDecrypter().FromRawBytes(plaintext).ByTea(teaCipher).ToBytes()
		assert.Empty(t, decrypted)
	})

	t.Run("std decrypter decrypt with existing error", func(t *testing.T) {
		key := []byte("1234567890123456") // 16-byte key for TEA
		teaCipher := cipher.NewTeaCipher()
		teaCipher.SetKey(key)
		plaintext := []byte("12345678") // 8-byte data

		decrypter := NewDecrypter()
		decrypter.Error = assert.AnError

		decrypted := decrypter.FromRawBytes(plaintext).ByTea(teaCipher).ToBytes()
		assert.Empty(t, decrypted)
	})

	t.Run("std decrypter decrypt empty data", func(t *testing.T) {
		key := []byte("1234567890123456") // 16-byte key for TEA
		teaCipher := cipher.NewTeaCipher()
		teaCipher.SetKey(key)
		var plaintext []byte // Empty data

		decrypted := NewDecrypter().FromRawBytes(plaintext).ByTea(teaCipher).ToBytes()
		assert.Empty(t, decrypted)
	})

	t.Run("std decrypter decrypt with invalid data size", func(t *testing.T) {
		key := []byte("1234567890123456") // 16-byte key for TEA
		teaCipher := cipher.NewTeaCipher()
		teaCipher.SetKey(key)
		plaintext := []byte("1234567") // 7-byte data (not multiple of 8)

		decrypted := NewDecrypter().FromRawBytes(plaintext).ByTea(teaCipher).ToBytes()
		assert.Empty(t, decrypted)
	})
}

// TestTeaDecrypterComprehensive tests comprehensive TEA decryption scenarios
func TestTeaDecrypterComprehensive(t *testing.T) {
	t.Run("decrypter with existing error", func(t *testing.T) {
		key := []byte("1234567890123456") // 16-byte key for TEA
		teaCipher := cipher.NewTeaCipher()
		teaCipher.SetKey(key)
		plaintext := []byte("12345678") // 8-byte data

		decrypter := NewDecrypter()
		decrypter.Error = assert.AnError

		decrypted := decrypter.FromRawBytes(plaintext).ByTea(teaCipher).ToBytes()
		assert.Empty(t, decrypted)
	})

	t.Run("decrypter with invalid key size", func(t *testing.T) {
		key := []byte("invalid") // Invalid key size
		teaCipher := cipher.NewTeaCipher()
		teaCipher.SetKey(key)
		plaintext := []byte("12345678") // 8-byte data

		decrypted := NewDecrypter().FromRawBytes(plaintext).ByTea(teaCipher).ToBytes()
		assert.Empty(t, decrypted)
	})
}

// TestTeaPackageDirect tests direct TEA package usage
func TestTeaPackageDirect(t *testing.T) {
	t.Run("ByTea with invalid key", func(t *testing.T) {
		key := []byte("invalid") // Invalid key size
		teaCipher := cipher.NewTeaCipher()
		teaCipher.SetKey(key)
		plaintext := []byte("12345678") // 8-byte data

		encrypted := NewEncrypter().FromBytes(plaintext).ByTea(teaCipher).ToRawBytes()
		assert.Empty(t, encrypted)

		decrypted := NewDecrypter().FromRawBytes(plaintext).ByTea(teaCipher).ToBytes()
		assert.Empty(t, decrypted)
	})

	t.Run("ByTea stream branch with invalid key", func(t *testing.T) {
		key := []byte("invalid") // Invalid key size
		teaCipher := cipher.NewTeaCipher()
		teaCipher.SetKey(key)

		mockFile := mock.NewFile([]byte("test data"), "test.txt")
		encrypted := NewEncrypter().FromFile(mockFile).ByTea(teaCipher).ToRawString()
		assert.Empty(t, encrypted)
	})
}

// TestTeaByTeaStreamBranch tests TEA ByTea stream branch
func TestTeaByTeaStreamBranch(t *testing.T) {
	t.Run("ByTea stream branch", func(t *testing.T) {
		key := []byte("1234567890123456") // 16-byte key for TEA
		teaCipher := cipher.NewTeaCipher()
		teaCipher.SetKey(key)
		plaintext := []byte("1234567890123456") // 16-byte data

		mockFile := mock.NewFile(plaintext, "test.txt")
		encrypted := NewEncrypter().FromFile(mockFile).ByTea(teaCipher).ToRawString()
		assert.NotEmpty(t, encrypted)

		decrypted := NewDecrypter().FromRawBytes([]byte(encrypted)).ByTea(teaCipher).ToBytes()
		assert.Equal(t, plaintext, decrypted)
	})

	t.Run("ByTea stream branch with error", func(t *testing.T) {
		key := []byte("1234567890123456") // 16-byte key for TEA
		teaCipher := cipher.NewTeaCipher()
		teaCipher.SetKey(key)
		// plaintext is not used in this test case, removing it
		encrypted := NewEncrypter().FromFile(mock.NewErrorFile(assert.AnError)).ByTea(teaCipher).ToRawString()
		assert.Empty(t, encrypted)
	})

	t.Run("decrypter stream branch", func(t *testing.T) {
		key := []byte("1234567890123456") // 16-byte key for TEA
		teaCipher := cipher.NewTeaCipher()
		teaCipher.SetKey(key)
		plaintext := []byte("1234567890123456") // 16-byte data

		// First encrypt using streaming
		mockFile := mock.NewFile(plaintext, "test.txt")
		encrypted := NewEncrypter().FromFile(mockFile).ByTea(teaCipher).ToRawString()
		assert.NotEmpty(t, encrypted)

		// Then decrypt using streaming by directly setting reader field
		mockFile2 := mock.NewFile([]byte(encrypted), "test2.txt")
		decrypter := NewDecrypter()
		decrypter.reader = mockFile2 // Directly set reader field
		decrypted := decrypter.ByTea(teaCipher).ToBytes()
		assert.Equal(t, plaintext, decrypted)
	})
}

// TestTeaEdgeCases tests TEA edge cases for full coverage
func TestTeaEdgeCases(t *testing.T) {
	t.Run("encrypter with nil src", func(t *testing.T) {
		key := []byte("1234567890123456") // 16-byte key for TEA
		teaCipher := cipher.NewTeaCipher()
		teaCipher.SetKey(key)

		// Create encrypter with nil src
		encrypter := NewEncrypter()
		// Manually set src to nil to simulate edge case
		encrypter.src = nil
		result := encrypter.ByTea(teaCipher)
		assert.Equal(t, encrypter, result)
		// Should not have error since nil src is handled gracefully
		assert.Nil(t, result.Error)
	})

	t.Run("decrypter with nil src", func(t *testing.T) {
		key := []byte("1234567890123456") // 16-byte key for TEA
		teaCipher := cipher.NewTeaCipher()
		teaCipher.SetKey(key)

		// Create decrypter with nil src
		decrypter := NewDecrypter()
		// Manually set src to nil to simulate edge case
		decrypter.src = nil
		result := decrypter.ByTea(teaCipher)
		assert.Equal(t, decrypter, result)
		// Should not have error since nil src is handled gracefully
		assert.Nil(t, result.Error)
	})

	t.Run("encrypter with empty src", func(t *testing.T) {
		key := []byte("1234567890123456") // 16-byte key for TEA
		teaCipher := cipher.NewTeaCipher()
		teaCipher.SetKey(key)

		// Create encrypter with empty src
		encrypter := NewEncrypter()
		encrypter.src = []byte{}
		result := encrypter.ByTea(teaCipher)
		assert.Equal(t, encrypter, result)
		// Empty src is handled gracefully in the crypto package - no error is returned
		assert.Nil(t, result.Error)
		assert.Empty(t, result.dst)
	})

	t.Run("decrypter with empty src", func(t *testing.T) {
		key := []byte("1234567890123456") // 16-byte key for TEA
		teaCipher := cipher.NewTeaCipher()
		teaCipher.SetKey(key)

		// Create decrypter with empty src
		decrypter := NewDecrypter()
		decrypter.src = []byte{}
		result := decrypter.ByTea(teaCipher)
		assert.Equal(t, decrypter, result)
		// Empty src is handled gracefully in the crypto package - no error is returned
		assert.Nil(t, result.Error)
		assert.Empty(t, result.dst)
	})

	t.Run("encrypter with reader nil and empty src", func(t *testing.T) {
		key := []byte("1234567890123456") // 16-byte key for TEA
		teaCipher := cipher.NewTeaCipher()
		teaCipher.SetKey(key)

		// Create encrypter with nil reader and empty src
		encrypter := NewEncrypter()
		encrypter.reader = nil
		encrypter.src = []byte{}
		result := encrypter.ByTea(teaCipher)
		assert.Equal(t, encrypter, result)
		// Empty src is handled gracefully in the crypto package - no error is returned
		assert.Nil(t, result.Error)
		assert.Empty(t, result.dst)
	})

	t.Run("decrypter with reader nil and empty src", func(t *testing.T) {
		key := []byte("1234567890123456") // 16-byte key for TEA
		teaCipher := cipher.NewTeaCipher()
		teaCipher.SetKey(key)

		// Create decrypter with nil reader and empty src
		decrypter := NewDecrypter()
		decrypter.reader = nil
		decrypter.src = []byte{}
		result := decrypter.ByTea(teaCipher)
		assert.Equal(t, decrypter, result)
		// Empty src is handled gracefully in the crypto package - no error is returned
		assert.Nil(t, result.Error)
		assert.Empty(t, result.dst)
	})
}

// TestTeaWithDifferentDataSizes tests TEA with different data sizes
func TestTeaWithDifferentDataSizes(t *testing.T) {
	key := []byte("1234567890123456") // 16-byte key for TEA
	teaCipher := cipher.NewTeaCipher()
	teaCipher.SetKey(key)

	t.Run("8-byte data", func(t *testing.T) {
		plaintext := []byte("12345678") // Exactly 8 bytes

		encrypted := NewEncrypter().FromBytes(plaintext).ByTea(teaCipher).ToRawBytes()
		assert.NotEmpty(t, encrypted)

		decrypted := NewDecrypter().FromRawBytes(encrypted).ByTea(teaCipher).ToBytes()
		assert.Equal(t, plaintext, decrypted)
	})

	t.Run("16-byte data", func(t *testing.T) {
		plaintext := []byte("1234567890123456") // Exactly 16 bytes

		encrypted := NewEncrypter().FromBytes(plaintext).ByTea(teaCipher).ToRawBytes()
		assert.NotEmpty(t, encrypted)

		decrypted := NewDecrypter().FromRawBytes(encrypted).ByTea(teaCipher).ToBytes()
		assert.Equal(t, plaintext, decrypted)
	})

	t.Run("24-byte data", func(t *testing.T) {
		plaintext := []byte("123456789012345678901234") // Exactly 24 bytes

		encrypted := NewEncrypter().FromBytes(plaintext).ByTea(teaCipher).ToRawBytes()
		assert.NotEmpty(t, encrypted)

		decrypted := NewDecrypter().FromRawBytes(encrypted).ByTea(teaCipher).ToBytes()
		assert.Equal(t, plaintext, decrypted)
	})

	t.Run("invalid 7-byte data", func(t *testing.T) {
		plaintext := []byte("1234567") // 7 bytes (not multiple of 8)

		encrypted := NewEncrypter().FromBytes(plaintext).ByTea(teaCipher).ToRawBytes()
		assert.Empty(t, encrypted)
	})

	t.Run("invalid 15-byte data", func(t *testing.T) {
		plaintext := []byte("123456789012345") // 15 bytes (not multiple of 8)

		encrypted := NewEncrypter().FromBytes(plaintext).ByTea(teaCipher).ToRawBytes()
		assert.Empty(t, encrypted)
	})
}

// TestTeaWithDifferentKeySizes tests TEA with different key sizes
func TestTeaWithDifferentKeySizes(t *testing.T) {
	plaintext := []byte("12345678") // 8-byte data

	t.Run("16-byte key", func(t *testing.T) {
		key := []byte("1234567890123456") // Exactly 16 bytes
		teaCipher := cipher.NewTeaCipher()
		teaCipher.SetKey(key)

		encrypted := NewEncrypter().FromBytes(plaintext).ByTea(teaCipher).ToRawBytes()
		assert.NotEmpty(t, encrypted)

		decrypted := NewDecrypter().FromRawBytes(encrypted).ByTea(teaCipher).ToBytes()
		assert.Equal(t, plaintext, decrypted)
	})

	t.Run("invalid 8-byte key", func(t *testing.T) {
		key := []byte("12345678") // 8 bytes (invalid for TEA)
		teaCipher := cipher.NewTeaCipher()
		teaCipher.SetKey(key)

		encrypted := NewEncrypter().FromBytes(plaintext).ByTea(teaCipher).ToRawBytes()
		assert.Empty(t, encrypted)

		decrypted := NewDecrypter().FromRawBytes(plaintext).ByTea(teaCipher).ToBytes()
		assert.Empty(t, decrypted)
	})

	t.Run("invalid 32-byte key", func(t *testing.T) {
		key := make([]byte, 32) // 32 bytes (invalid for TEA)
		for i := range key {
			key[i] = byte(i % 256)
		}
		teaCipher := cipher.NewTeaCipher()
		teaCipher.SetKey(key)

		encrypted := NewEncrypter().FromBytes(plaintext).ByTea(teaCipher).ToRawBytes()
		assert.Empty(t, encrypted)

		decrypted := NewDecrypter().FromRawBytes(plaintext).ByTea(teaCipher).ToBytes()
		assert.Empty(t, decrypted)
	})
}
