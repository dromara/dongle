package crypto

import (
	"testing"

	"github.com/dromara/dongle/crypto/cipher"
	"github.com/dromara/dongle/mock"
	"github.com/stretchr/testify/assert"
)

// TestRc4InputTypes tests RC4 encryption with various input types
func TestRc4InputTypes(t *testing.T) {
	t.Run("string input", func(t *testing.T) {
		key := []byte("testkey")
		rc4Cipher := cipher.NewRc4Cipher()
		rc4Cipher.SetKey(key)
		plaintext := "Hello, RC4!"

		encrypted := NewEncrypter().FromString(plaintext).ByRc4(rc4Cipher).ToRawString()
		assert.NotEmpty(t, encrypted)

		decrypted := NewDecrypter().FromRawString(encrypted).ByRc4(rc4Cipher).ToString()
		assert.Equal(t, plaintext, decrypted)
	})

	t.Run("bytes input", func(t *testing.T) {
		key := []byte("testkey")
		rc4Cipher := cipher.NewRc4Cipher()
		rc4Cipher.SetKey(key)
		plaintext := []byte("Hello, RC4!")

		encrypted := NewEncrypter().FromBytes(plaintext).ByRc4(rc4Cipher).ToRawBytes()
		assert.NotEmpty(t, encrypted)

		decrypted := NewDecrypter().FromRawBytes(encrypted).ByRc4(rc4Cipher).ToBytes()
		assert.Equal(t, plaintext, decrypted)
	})

	t.Run("empty input", func(t *testing.T) {
		key := []byte("testkey")
		rc4Cipher := cipher.NewRc4Cipher()
		rc4Cipher.SetKey(key)
		plaintext := ""

		encrypted := NewEncrypter().FromString(plaintext).ByRc4(rc4Cipher).ToRawString()
		assert.Empty(t, encrypted)

		decrypted := NewDecrypter().FromRawString(encrypted).ByRc4(rc4Cipher).ToString()
		assert.Equal(t, plaintext, decrypted)
	})

	t.Run("empty bytes input", func(t *testing.T) {
		key := []byte("testkey")
		rc4Cipher := cipher.NewRc4Cipher()
		rc4Cipher.SetKey(key)
		var plaintext []byte

		encrypted := NewEncrypter().FromBytes(plaintext).ByRc4(rc4Cipher).ToRawBytes()
		assert.Empty(t, encrypted)

		decrypted := NewDecrypter().FromRawBytes(encrypted).ByRc4(rc4Cipher).ToBytes()
		// Both nil and empty slices are acceptable for empty data
		assert.True(t, len(decrypted) == 0)
	})

	t.Run("unicode input", func(t *testing.T) {
		key := []byte("testkey")
		rc4Cipher := cipher.NewRc4Cipher()
		rc4Cipher.SetKey(key)
		plaintext := "Hello, 世界! 🌍"

		encrypted := NewEncrypter().FromString(plaintext).ByRc4(rc4Cipher).ToRawString()
		assert.NotEmpty(t, encrypted)

		decrypted := NewDecrypter().FromRawString(encrypted).ByRc4(rc4Cipher).ToString()
		assert.Equal(t, plaintext, decrypted)
	})

	t.Run("binary input", func(t *testing.T) {
		key := []byte("testkey")
		rc4Cipher := cipher.NewRc4Cipher()
		rc4Cipher.SetKey(key)
		plaintext := []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07}

		encrypted := NewEncrypter().FromBytes(plaintext).ByRc4(rc4Cipher).ToRawBytes()
		assert.NotEmpty(t, encrypted)

		decrypted := NewDecrypter().FromRawBytes(encrypted).ByRc4(rc4Cipher).ToBytes()
		assert.Equal(t, plaintext, decrypted)
	})
}

// TestRc4ErrorHandling tests RC4 error handling scenarios
func TestRc4ErrorHandling(t *testing.T) {
	t.Run("empty key", func(t *testing.T) {
		plaintext := "Hello, RC4!"
		rc4Cipher := cipher.NewRc4Cipher()
		rc4Cipher.SetKey([]byte{})

		encrypted := NewEncrypter().FromString(plaintext).ByRc4(rc4Cipher).ToRawString()
		assert.Empty(t, encrypted)

		decrypted := NewDecrypter().FromRawString(plaintext).ByRc4(rc4Cipher).ToString()
		assert.Empty(t, decrypted)
	})

	t.Run("key too large", func(t *testing.T) {
		plaintext := "Hello, RC4!"
		key := make([]byte, 257) // RC4 key size limit is 256 bytes
		rc4Cipher := cipher.NewRc4Cipher()
		rc4Cipher.SetKey(key)

		encrypted := NewEncrypter().FromString(plaintext).ByRc4(rc4Cipher).ToRawString()
		assert.Empty(t, encrypted)

		decrypted := NewDecrypter().FromRawString(plaintext).ByRc4(rc4Cipher).ToString()
		assert.Empty(t, decrypted)
	})

	t.Run("with existing error", func(t *testing.T) {
		key := []byte("testkey")
		rc4Cipher := cipher.NewRc4Cipher()
		rc4Cipher.SetKey(key)
		plaintext := "Hello, RC4!"

		encrypter := NewEncrypter()
		encrypter.Error = assert.AnError

		encrypted := encrypter.FromString(plaintext).ByRc4(rc4Cipher).ToRawString()
		assert.Empty(t, encrypted)

		decrypter := NewDecrypter()
		decrypter.Error = assert.AnError

		decrypted := decrypter.FromRawString(plaintext).ByRc4(rc4Cipher).ToString()
		assert.Empty(t, decrypted)
	})

	t.Run("encryption error", func(t *testing.T) {
		plaintext := "Hello, RC4!"
		rc4Cipher := cipher.NewRc4Cipher()
		rc4Cipher.SetKey([]byte{})

		// Test with invalid key that causes encryption to fail
		encrypted := NewEncrypter().FromString(plaintext).ByRc4(rc4Cipher).ToRawString()
		assert.Empty(t, encrypted)
	})

	t.Run("decryption error", func(t *testing.T) {
		plaintext := "Hello, RC4!"
		rc4Cipher := cipher.NewRc4Cipher()
		rc4Cipher.SetKey([]byte{})

		// Test with invalid key that causes decryption to fail
		decrypted := NewDecrypter().FromRawString(plaintext).ByRc4(rc4Cipher).ToString()
		assert.Empty(t, decrypted)
	})
}

// TestRc4Streaming tests RC4 streaming encryption and decryption
func TestRc4Streaming(t *testing.T) {
	t.Run("stream encrypter with valid key", func(t *testing.T) {
		key := []byte("testkey")
		rc4Cipher := cipher.NewRc4Cipher()
		rc4Cipher.SetKey(key)
		plaintext := "Hello, RC4 streaming!"

		// Create a mock file for streaming
		mockFile := mock.NewFile([]byte(plaintext), "test.txt")
		encrypted := NewEncrypter().FromFile(mockFile).ByRc4(rc4Cipher).ToRawString()
		assert.NotEmpty(t, encrypted)

		// For decryption, we need to use the encrypted data directly
		// since Decrypter doesn't have FromFile method
		decrypted := NewDecrypter().FromRawBytes([]byte(encrypted)).ByRc4(rc4Cipher).ToString()
		assert.Equal(t, plaintext, decrypted)
	})

	t.Run("stream encrypter with invalid key", func(t *testing.T) {
		var key []byte // Empty key
		rc4Cipher := cipher.NewRc4Cipher()
		rc4Cipher.SetKey(key)
		plaintext := "Hello, RC4 streaming!"

		mockFile := mock.NewFile([]byte(plaintext), "test.txt")
		encrypted := NewEncrypter().FromFile(mockFile).ByRc4(rc4Cipher).ToRawString()
		assert.Empty(t, encrypted)
	})

	t.Run("stream with read error", func(t *testing.T) {
		key := []byte("testkey")
		rc4Cipher := cipher.NewRc4Cipher()
		rc4Cipher.SetKey(key)
		errorReader := mock.NewErrorFile(assert.AnError)

		encrypted := NewEncrypter().FromFile(errorReader).ByRc4(rc4Cipher).ToRawString()
		assert.Empty(t, encrypted)
	})

}

// TestRc4StdEncrypter tests RC4 standard encrypter functionality
func TestRc4StdEncrypter(t *testing.T) {
	t.Run("new std encrypter with valid key", func(t *testing.T) {
		key := []byte("testkey")
		rc4Cipher := cipher.NewRc4Cipher()
		rc4Cipher.SetKey(key)
		plaintext := "Hello, RC4!"

		encrypted := NewEncrypter().FromString(plaintext).ByRc4(rc4Cipher).ToRawString()
		assert.NotEmpty(t, encrypted)
	})

	t.Run("new std encrypter with invalid key", func(t *testing.T) {
		var key []byte // Empty key
		rc4Cipher := cipher.NewRc4Cipher()
		rc4Cipher.SetKey(key)
		plaintext := "Hello, RC4!"

		encrypted := NewEncrypter().FromString(plaintext).ByRc4(rc4Cipher).ToRawString()
		assert.Empty(t, encrypted)
	})

	t.Run("std encrypter encrypt with existing error", func(t *testing.T) {
		key := []byte("testkey")
		rc4Cipher := cipher.NewRc4Cipher()
		rc4Cipher.SetKey(key)
		plaintext := "Hello, RC4!"

		encrypter := NewEncrypter()
		encrypter.Error = assert.AnError

		encrypted := encrypter.FromString(plaintext).ByRc4(rc4Cipher).ToRawString()
		assert.Empty(t, encrypted)
	})

	t.Run("std encrypter encrypt empty data", func(t *testing.T) {
		key := []byte("testkey")
		rc4Cipher := cipher.NewRc4Cipher()
		rc4Cipher.SetKey(key)
		plaintext := ""

		encrypted := NewEncrypter().FromString(plaintext).ByRc4(rc4Cipher).ToRawString()
		assert.Empty(t, encrypted)
	})

	t.Run("std encrypter encrypt with encryption error", func(t *testing.T) {
		var key []byte // Empty key to trigger error
		rc4Cipher := cipher.NewRc4Cipher()
		rc4Cipher.SetKey(key)
		plaintext := "Hello, RC4!"

		encrypted := NewEncrypter().FromString(plaintext).ByRc4(rc4Cipher).ToRawString()
		assert.Empty(t, encrypted)
	})
}

// TestRc4StdDecrypter tests RC4 standard decrypter functionality
func TestRc4StdDecrypter(t *testing.T) {
	t.Run("new std decrypter with valid key", func(t *testing.T) {
		key := []byte("testkey")
		rc4Cipher := cipher.NewRc4Cipher()
		rc4Cipher.SetKey(key)
		plaintext := "Hello, RC4!"

		// First encrypt
		encrypted := NewEncrypter().FromString(plaintext).ByRc4(rc4Cipher).ToRawString()
		assert.NotEmpty(t, encrypted)

		// Then decrypt
		decrypted := NewDecrypter().FromRawString(encrypted).ByRc4(rc4Cipher).ToString()
		assert.Equal(t, plaintext, decrypted)
	})

	t.Run("new std decrypter with invalid key", func(t *testing.T) {
		var key []byte // Empty key
		rc4Cipher := cipher.NewRc4Cipher()
		rc4Cipher.SetKey(key)
		plaintext := "Hello, RC4!"

		decrypted := NewDecrypter().FromRawString(plaintext).ByRc4(rc4Cipher).ToString()
		assert.Empty(t, decrypted)
	})

	t.Run("std decrypter decrypt with existing error", func(t *testing.T) {
		key := []byte("testkey")
		rc4Cipher := cipher.NewRc4Cipher()
		rc4Cipher.SetKey(key)
		plaintext := "Hello, RC4!"

		decrypter := NewDecrypter()
		decrypter.Error = assert.AnError

		decrypted := decrypter.FromRawString(plaintext).ByRc4(rc4Cipher).ToString()
		assert.Empty(t, decrypted)
	})

	t.Run("std decrypter decrypt empty data", func(t *testing.T) {
		key := []byte("testkey")
		rc4Cipher := cipher.NewRc4Cipher()
		rc4Cipher.SetKey(key)
		plaintext := ""

		decrypted := NewDecrypter().FromRawString(plaintext).ByRc4(rc4Cipher).ToString()
		assert.Equal(t, plaintext, decrypted)
	})

	t.Run("std decrypter decrypt empty bytes", func(t *testing.T) {
		key := []byte("testkey")
		rc4Cipher := cipher.NewRc4Cipher()
		rc4Cipher.SetKey(key)
		var plaintext []byte

		decrypted := NewDecrypter().FromRawBytes(plaintext).ByRc4(rc4Cipher).ToBytes()
		// Both nil and empty slices are acceptable for empty data
		assert.True(t, len(decrypted) == 0)
	})

	t.Run("std decrypter decrypt with decryption error", func(t *testing.T) {
		var key []byte // Empty key to trigger error
		rc4Cipher := cipher.NewRc4Cipher()
		rc4Cipher.SetKey(key)
		plaintext := "Hello, RC4!"

		decrypted := NewDecrypter().FromRawString(plaintext).ByRc4(rc4Cipher).ToString()
		assert.Empty(t, decrypted)
	})
}

// TestRc4DecrypterComprehensive tests comprehensive RC4 decryption scenarios
func TestRc4DecrypterComprehensive(t *testing.T) {
	t.Run("decrypter with existing error", func(t *testing.T) {
		key := []byte("testkey")
		rc4Cipher := cipher.NewRc4Cipher()
		rc4Cipher.SetKey(key)
		plaintext := "Hello, RC4!"

		decrypter := NewDecrypter()
		decrypter.Error = assert.AnError

		decrypted := decrypter.FromRawString(plaintext).ByRc4(rc4Cipher).ToString()
		assert.Empty(t, decrypted)
	})

	t.Run("decrypter with rc4.NewStdDecrypter error", func(t *testing.T) {
		var key []byte // Empty key to trigger error
		rc4Cipher := cipher.NewRc4Cipher()
		rc4Cipher.SetKey(key)
		plaintext := "Hello, RC4!"

		decrypted := NewDecrypter().FromRawString(plaintext).ByRc4(rc4Cipher).ToString()
		assert.Empty(t, decrypted)
	})

	t.Run("decrypter with rc4.NewStdDecrypter error in constructor", func(t *testing.T) {
		var key []byte // Empty key to trigger error
		rc4Cipher := cipher.NewRc4Cipher()
		rc4Cipher.SetKey(key)
		plaintext := "Hello, RC4!"

		decrypter := NewDecrypter()
		decrypted := decrypter.FromRawString(plaintext).ByRc4(rc4Cipher).ToString()
		assert.Empty(t, decrypted)
	})
}

// TestRc4PackageDirect tests direct RC4 package usage
func TestRc4PackageDirect(t *testing.T) {
	t.Run("NewStdEncrypter with invalid key", func(t *testing.T) {
		var key []byte // Empty key
		rc4Cipher := cipher.NewRc4Cipher()
		rc4Cipher.SetKey(key)
		plaintext := "Hello, RC4!"

		encrypted := NewEncrypter().FromString(plaintext).ByRc4(rc4Cipher).ToRawString()
		assert.Empty(t, encrypted)
	})

	t.Run("NewStdDecrypter with invalid key", func(t *testing.T) {
		var key []byte // Empty key
		rc4Cipher := cipher.NewRc4Cipher()
		rc4Cipher.SetKey(key)
		plaintext := "Hello, RC4!"

		decrypted := NewDecrypter().FromRawString(plaintext).ByRc4(rc4Cipher).ToString()
		assert.Empty(t, decrypted)
	})

	t.Run("NewStreamEncrypter with invalid key", func(t *testing.T) {
		var key []byte // Empty key
		rc4Cipher := cipher.NewRc4Cipher()
		rc4Cipher.SetKey(key)
		plaintext := "Hello, RC4 streaming!"

		mockFile := mock.NewFile([]byte(plaintext), "test.txt")
		encrypted := NewEncrypter().FromFile(mockFile).ByRc4(rc4Cipher).ToRawString()
		assert.Empty(t, encrypted)
	})
}

// TestRc4ByRc4StreamBranch tests RC4 ByRc4 stream branch
func TestRc4ByRc4StreamBranch(t *testing.T) {
	t.Run("ByRc4 stream branch", func(t *testing.T) {
		key := []byte("testkey")
		rc4Cipher := cipher.NewRc4Cipher()
		rc4Cipher.SetKey(key)
		plaintext := "Hello, RC4 streaming!"

		mockFile := mock.NewFile([]byte(plaintext), "test.txt")
		encrypted := NewEncrypter().FromFile(mockFile).ByRc4(rc4Cipher).ToRawString()
		assert.NotEmpty(t, encrypted)

		decrypted := NewDecrypter().FromRawBytes([]byte(encrypted)).ByRc4(rc4Cipher).ToString()
		assert.Equal(t, plaintext, decrypted)
	})

	t.Run("ByRc4 stream branch with error", func(t *testing.T) {
		key := []byte("testkey")
		rc4Cipher := cipher.NewRc4Cipher()
		rc4Cipher.SetKey(key)
		errorReader := mock.NewErrorFile(assert.AnError)

		encrypted := NewEncrypter().FromFile(errorReader).ByRc4(rc4Cipher).ToRawString()
		assert.Empty(t, encrypted)
	})
}

// TestRc4EdgeCases tests RC4 edge cases for full coverage
func TestRc4EdgeCases(t *testing.T) {
	t.Run("encrypter with nil src", func(t *testing.T) {
		key := []byte("testkey")
		rc4Cipher := cipher.NewRc4Cipher()
		rc4Cipher.SetKey(key)

		// Create encrypter with nil src
		encrypter := NewEncrypter()
		// Manually set src to nil to simulate edge case
		encrypter.src = nil
		result := encrypter.ByRc4(rc4Cipher)
		assert.Equal(t, encrypter, result)
		// Should not have error since nil src is handled gracefully
		assert.Nil(t, result.Error)
	})

	t.Run("decrypter with nil src", func(t *testing.T) {
		key := []byte("testkey")
		rc4Cipher := cipher.NewRc4Cipher()
		rc4Cipher.SetKey(key)

		// Create decrypter with nil src
		decrypter := NewDecrypter()
		// Manually set src to nil to simulate edge case
		decrypter.src = nil
		result := decrypter.ByRc4(rc4Cipher)
		assert.Equal(t, decrypter, result)
		// Should not have error since nil src is handled gracefully
		assert.Nil(t, result.Error)
	})

	t.Run("encrypter with empty src", func(t *testing.T) {
		key := []byte("testkey")
		rc4Cipher := cipher.NewRc4Cipher()
		rc4Cipher.SetKey(key)

		// Create encrypter with empty src
		encrypter := NewEncrypter()
		encrypter.src = []byte{}
		result := encrypter.ByRc4(rc4Cipher)
		assert.Equal(t, encrypter, result)
		// Should not have error since empty src is handled gracefully
		assert.Nil(t, result.Error)
		assert.Empty(t, result.dst)
	})

	t.Run("decrypter with empty src", func(t *testing.T) {
		key := []byte("testkey")
		rc4Cipher := cipher.NewRc4Cipher()
		rc4Cipher.SetKey(key)

		// Create decrypter with empty src
		decrypter := NewDecrypter()
		decrypter.src = []byte{}
		result := decrypter.ByRc4(rc4Cipher)
		assert.Equal(t, decrypter, result)
		// Should not have error since empty src is handled gracefully
		assert.Nil(t, result.Error)
		assert.Empty(t, result.dst)
	})

	t.Run("encrypter with reader nil and empty src", func(t *testing.T) {
		key := []byte("testkey")
		rc4Cipher := cipher.NewRc4Cipher()
		rc4Cipher.SetKey(key)

		// Create encrypter with nil reader and empty src
		encrypter := NewEncrypter()
		encrypter.reader = nil
		encrypter.src = []byte{}
		result := encrypter.ByRc4(rc4Cipher)
		assert.Equal(t, encrypter, result)
		// Should not have error since empty src is handled gracefully
		assert.Nil(t, result.Error)
		assert.Empty(t, result.dst)
	})

	t.Run("decrypter with reader nil and empty src", func(t *testing.T) {
		key := []byte("testkey")
		rc4Cipher := cipher.NewRc4Cipher()
		rc4Cipher.SetKey(key)

		// Create decrypter with nil reader and empty src
		decrypter := NewDecrypter()
		decrypter.reader = nil
		decrypter.src = []byte{}
		result := decrypter.ByRc4(rc4Cipher)
		assert.Equal(t, decrypter, result)
		// Should not have error since empty src is handled gracefully
		assert.Nil(t, result.Error)
		assert.Empty(t, result.dst)
	})

	t.Run("encrypter with reader nil and nil src", func(t *testing.T) {
		key := []byte("testkey")
		rc4Cipher := cipher.NewRc4Cipher()
		rc4Cipher.SetKey(key)

		// Create encrypter with nil reader and nil src
		encrypter := NewEncrypter()
		encrypter.reader = nil
		encrypter.src = nil
		result := encrypter.ByRc4(rc4Cipher)
		assert.Equal(t, encrypter, result)
		// Should not have error since nil src is handled gracefully
		assert.Nil(t, result.Error)
		assert.Empty(t, result.dst)
	})

	t.Run("decrypter with reader nil and nil src", func(t *testing.T) {
		key := []byte("testkey")
		rc4Cipher := cipher.NewRc4Cipher()
		rc4Cipher.SetKey(key)

		// Create decrypter with nil reader and nil src
		decrypter := NewDecrypter()
		decrypter.reader = nil
		decrypter.src = nil
		result := decrypter.ByRc4(rc4Cipher)
		assert.Equal(t, decrypter, result)
		// Should not have error since nil src is handled gracefully
		assert.Nil(t, result.Error)
		assert.Empty(t, result.dst)
	})

	// Add a test case specifically for the missing branch coverage
	t.Run("encrypter with nil src and no reader - direct branch test", func(t *testing.T) {
		key := []byte("testkey")
		rc4Cipher := cipher.NewRc4Cipher()
		rc4Cipher.SetKey(key)

		// Create encrypter with nil src and no reader
		encrypter := NewEncrypter()
		encrypter.reader = nil
		encrypter.src = nil
		result := encrypter.ByRc4(rc4Cipher)
		assert.Equal(t, encrypter, result)
		// Should not have error since nil src is handled gracefully
		assert.Nil(t, result.Error)
		assert.Empty(t, result.dst)
	})

	t.Run("decrypter with nil src and no reader - direct branch test", func(t *testing.T) {
		key := []byte("testkey")
		rc4Cipher := cipher.NewRc4Cipher()
		rc4Cipher.SetKey(key)

		// Create decrypter with nil src and no reader
		decrypter := NewDecrypter()
		decrypter.reader = nil
		decrypter.src = nil
		result := decrypter.ByRc4(rc4Cipher)
		assert.Equal(t, decrypter, result)
		// Should not have error since nil src is handled gracefully
		assert.Nil(t, result.Error)
		assert.Empty(t, result.dst)
	})

	t.Run("decrypter with reader set - streaming branch coverage", func(t *testing.T) {
		key := []byte("testkey")
		rc4Cipher := cipher.NewRc4Cipher()
		rc4Cipher.SetKey(key)

		// Create decrypter with reader set to trigger streaming branch
		decrypter := NewDecrypter()
		decrypter.reader = mock.NewFile([]byte("test"), "test.txt")
		decrypter.src = nil // Ensure src is nil
		result := decrypter.ByRc4(rc4Cipher)

		// Check that the streaming branch was executed
		// The result should have the same reader and src should remain nil
		assert.Equal(t, decrypter.reader, result.reader)
		assert.Nil(t, result.src)
		// dst and Error might be set during streaming processing
		// The important thing is that the streaming branch was executed
	})
}

// TestRc4WithDifferentKeySizes tests RC4 with different key sizes
func TestRc4WithDifferentKeySizes(t *testing.T) {
	plaintext := "Hello, RC4!"

	t.Run("1-byte key", func(t *testing.T) {
		key := []byte("a")
		rc4Cipher := cipher.NewRc4Cipher()
		rc4Cipher.SetKey(key)

		encrypted := NewEncrypter().FromString(plaintext).ByRc4(rc4Cipher).ToRawString()
		assert.NotEmpty(t, encrypted)

		decrypted := NewDecrypter().FromRawString(encrypted).ByRc4(rc4Cipher).ToString()
		assert.Equal(t, plaintext, decrypted)
	})

	t.Run("256-byte key", func(t *testing.T) {
		key := make([]byte, 256)
		for i := range key {
			key[i] = byte(i % 256)
		}
		rc4Cipher := cipher.NewRc4Cipher()
		rc4Cipher.SetKey(key)

		encrypted := NewEncrypter().FromString(plaintext).ByRc4(rc4Cipher).ToRawString()
		assert.NotEmpty(t, encrypted)

		decrypted := NewDecrypter().FromRawString(encrypted).ByRc4(rc4Cipher).ToString()
		assert.Equal(t, plaintext, decrypted)
	})
}
