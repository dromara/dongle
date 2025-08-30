package hash

import (
	"errors"
	"strings"
	"testing"

	"github.com/dromara/dongle/mock"
	"github.com/stretchr/testify/assert"
)

func TestHasher_BySm3(t *testing.T) {
	t.Run("hash string", func(t *testing.T) {
		hasher := NewHasher().FromString("hello").BySm3()
		assert.Nil(t, hasher.Error)
		assert.NotNil(t, hasher.dst)
		assert.Equal(t, 32, len(hasher.dst)) // SM3 produces 32-byte hash

		// Verify the actual hash value
		expectedHash := "becbbfaae6548b8bf0cfcad5a27183cd1be6093b1cceccc303d9c61d0a645268"
		actualHash := hasher.ToHexString()
		assert.Equal(t, expectedHash, actualHash, "SM3 hash of 'hello' should match expected value")
	})

	t.Run("hash bytes", func(t *testing.T) {
		hasher := NewHasher().FromBytes([]byte("hello")).BySm3()
		assert.Nil(t, hasher.Error)
		assert.NotNil(t, hasher.dst)
		assert.Equal(t, 32, len(hasher.dst)) // SM3 produces 32-byte hash

		// Verify the actual hash value
		expectedHash := "becbbfaae6548b8bf0cfcad5a27183cd1be6093b1cceccc303d9c61d0a645268"
		actualHash := hasher.ToHexString()
		assert.Equal(t, expectedHash, actualHash, "SM3 hash of 'hello' bytes should match expected value")
	})

	t.Run("hash file", func(t *testing.T) {
		file := mock.NewFile([]byte("hello"), "test.txt")
		hasher := NewHasher().FromFile(file).BySm3()
		assert.Nil(t, hasher.Error)
		assert.NotNil(t, hasher.dst)
		assert.Equal(t, 32, len(hasher.dst)) // SM3 produces 32-byte hash

		// Verify the actual hash value
		expectedHash := "becbbfaae6548b8bf0cfcad5a27183cd1be6093b1cceccc303d9c61d0a645268"
		actualHash := hasher.ToHexString()
		assert.Equal(t, expectedHash, actualHash, "SM3 hash of 'hello' file should match expected value")
	})

	t.Run("empty string", func(t *testing.T) {
		hasher := NewHasher().FromString("").BySm3()
		assert.Nil(t, hasher.Error)
		assert.Nil(t, hasher.dst) // Empty input returns nil
	})

	t.Run("empty bytes", func(t *testing.T) {
		hasher := NewHasher().FromBytes([]byte{}).BySm3()
		assert.Nil(t, hasher.Error)
		assert.Nil(t, hasher.dst) // Empty input returns nil
	})

	t.Run("nil bytes", func(t *testing.T) {
		hasher := NewHasher().FromBytes(nil).BySm3()
		assert.Nil(t, hasher.Error)
		assert.Nil(t, hasher.dst) // Empty input returns nil
	})

	t.Run("large data", func(t *testing.T) {
		data := strings.Repeat("a", 10000)
		hasher := NewHasher().FromString(data).BySm3()
		assert.Nil(t, hasher.Error)
		assert.NotNil(t, hasher.dst)
		assert.Equal(t, 32, len(hasher.dst)) // SM3 produces 32-byte hash

		// Verify the hash is not all zeros and is consistent
		allZero := true
		for _, b := range hasher.dst {
			if b != 0 {
				allZero = false
				break
			}
		}
		assert.False(t, allZero, "SM3 hash of large data should not be all zeros")

		// Test consistency - same input should produce same hash
		hasher2 := NewHasher().FromString(data).BySm3()
		assert.Equal(t, hasher.dst, hasher2.dst, "Same input should produce consistent hash")
	})

	t.Run("unicode data", func(t *testing.T) {
		hasher := NewHasher().FromString("你好世界").BySm3()
		assert.Nil(t, hasher.Error)
		assert.NotNil(t, hasher.dst)
		assert.Equal(t, 32, len(hasher.dst)) // SM3 produces 32-byte hash

		// Verify the hash is not all zeros
		allZero := true
		for _, b := range hasher.dst {
			if b != 0 {
				allZero = false
				break
			}
		}
		assert.False(t, allZero, "SM3 hash of unicode data should not be all zeros")
	})

	t.Run("binary data", func(t *testing.T) {
		binaryData := []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f}
		hasher := NewHasher().FromBytes(binaryData).BySm3()
		assert.Nil(t, hasher.Error)
		assert.NotNil(t, hasher.dst)
		assert.Equal(t, 32, len(hasher.dst)) // SM3 produces 32-byte hash

		// Verify the hash is not all zeros
		allZero := true
		for _, b := range hasher.dst {
			if b != 0 {
				allZero = false
				break
			}
		}
		assert.False(t, allZero, "SM3 hash of binary data should not be all zeros")
	})

	t.Run("empty file", func(t *testing.T) {
		file := mock.NewFile([]byte{}, "empty.txt")
		hasher := NewHasher().FromFile(file).BySm3()
		assert.Nil(t, hasher.Error)
		assert.Equal(t, []byte{}, hasher.dst) // Empty file returns empty slice
	})

	t.Run("no data no reader no key", func(t *testing.T) {
		hasher := NewHasher().BySm3()
		assert.Nil(t, hasher.Error)
		assert.Nil(t, hasher.dst) // No data, no reader, no key returns nil
	})
}

func TestHasher_BySm3_HMAC(t *testing.T) {
	t.Run("hmac with key", func(t *testing.T) {
		hasher := NewHasher().FromString("hello").WithKey([]byte("secret")).BySm3()
		assert.Nil(t, hasher.Error)
		assert.NotNil(t, hasher.dst)
		assert.Equal(t, 32, len(hasher.dst)) // HMAC-SM3 produces 32-byte hash

		// Verify the HMAC is not all zeros
		allZero := true
		for _, b := range hasher.dst {
			if b != 0 {
				allZero = false
				break
			}
		}
		assert.False(t, allZero, "HMAC-SM3 should not be all zeros")
	})

	t.Run("hmac with bytes", func(t *testing.T) {
		hasher := NewHasher().FromBytes([]byte("hello")).WithKey([]byte("secret")).BySm3()
		assert.Nil(t, hasher.Error)
		assert.NotNil(t, hasher.dst)
		assert.Equal(t, 32, len(hasher.dst)) // HMAC-SM3 produces 32-byte hash

		// Verify the HMAC is not all zeros
		allZero := true
		for _, b := range hasher.dst {
			if b != 0 {
				allZero = false
				break
			}
		}
		assert.False(t, allZero, "HMAC-SM3 should not be all zeros")
	})

	t.Run("hmac with file", func(t *testing.T) {
		file := mock.NewFile([]byte("hello"), "test.txt")
		hasher := NewHasher().FromFile(file).WithKey([]byte("secret")).BySm3()
		assert.Nil(t, hasher.Error)
		assert.NotNil(t, hasher.dst)
		assert.Equal(t, 32, len(hasher.dst)) // HMAC-SM3 produces 32-byte hash

		// Verify the HMAC is not all zeros
		allZero := true
		for _, b := range hasher.dst {
			if b != 0 {
				allZero = false
				break
			}
		}
		assert.False(t, allZero, "HMAC-SM3 should not be all zeros")
	})

	t.Run("hmac with large key", func(t *testing.T) {
		key := make([]byte, 1000)
		for i := range key {
			key[i] = byte(i % 256)
		}
		hasher := NewHasher().FromString("hello").WithKey(key).BySm3()
		assert.Nil(t, hasher.Error)
		assert.NotNil(t, hasher.dst)
		assert.Equal(t, 32, len(hasher.dst)) // HMAC-SM3 produces 32-byte hash

		// Verify the HMAC is not all zeros
		allZero := true
		for _, b := range hasher.dst {
			if b != 0 {
				allZero = false
				break
			}
		}
		assert.False(t, allZero, "HMAC-SM3 should not be all zeros")
	})
}

func TestHasher_BySm3_Error(t *testing.T) {
	t.Run("file read error", func(t *testing.T) {
		file := mock.NewErrorFile(errors.New("file read error"))
		hasher := NewHasher().FromFile(file).BySm3()
		assert.NotNil(t, hasher.Error)
		assert.Contains(t, hasher.Error.Error(), "file read error")
	})

	t.Run("file read error after partial read", func(t *testing.T) {
		file := mock.NewErrorFile(errors.New("partial read error"))
		hasher := NewHasher().FromFile(file).BySm3()
		assert.NotNil(t, hasher.Error)
		assert.Contains(t, hasher.Error.Error(), "partial read error")
	})

	t.Run("error with key", func(t *testing.T) {
		hasher := NewHasher()
		hasher.Error = errors.New("existing error")
		result := hasher.WithKey([]byte("secret")).BySm3()
		assert.Equal(t, hasher, result)
		assert.Equal(t, errors.New("existing error"), result.Error)
	})

	t.Run("error propagation", func(t *testing.T) {
		hasher := NewHasher()
		hasher.Error = errors.New("test error")
		result := hasher.BySm3()
		assert.Equal(t, hasher, result)
		assert.Equal(t, errors.New("test error"), result.Error)
	})

	t.Run("file with error", func(t *testing.T) {
		file := mock.NewErrorFile(errors.New("read error"))
		hasher := NewHasher().FromFile(file).BySm3()
		assert.NotNil(t, hasher.Error)
		assert.Contains(t, hasher.Error.Error(), "read error")
	})

	t.Run("hmac with empty key", func(t *testing.T) {
		hasher := NewHasher().FromString("hello").WithKey([]byte{}).BySm3()
		assert.NotNil(t, hasher.Error)
		assert.Contains(t, hasher.Error.Error(), "hmac: key cannot be empty")
	})

	t.Run("hmac with nil key", func(t *testing.T) {
		hasher := NewHasher().FromString("hello").WithKey(nil).BySm3()
		assert.NotNil(t, hasher.Error)
		assert.Contains(t, hasher.Error.Error(), "hmac: key cannot be empty")
	})
}
