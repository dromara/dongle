package hash

import (
	"errors"
	"strings"
	"testing"

	"gitee.com/golang-package/dongle/mock"
	"github.com/stretchr/testify/assert"
)

func TestHasher_BySha2(t *testing.T) {
	t.Run("hash string SHA2-224", func(t *testing.T) {
		hasher := NewHasher().FromString("hello").BySha2(224)
		assert.Nil(t, hasher.Error)
		expected := []byte{0xea, 0x09, 0xae, 0x9c, 0xc6, 0x76, 0x8c, 0x50, 0xfc, 0xee, 0x90, 0x3e, 0xd0, 0x54, 0x55, 0x6e, 0x5b, 0xfc, 0x83, 0x47, 0x90, 0x7f, 0x12, 0x59, 0x8a, 0xa2, 0x41, 0x93}
		assert.Equal(t, expected, hasher.dst)
	})

	t.Run("hash string SHA2-256", func(t *testing.T) {
		hasher := NewHasher().FromString("hello").BySha2(256)
		assert.Nil(t, hasher.Error)
		expected := []byte{0x2c, 0xf2, 0x4d, 0xba, 0x5f, 0xb0, 0xa3, 0x0e, 0x26, 0xe8, 0x3b, 0x2a, 0xc5, 0xb9, 0xe2, 0x9e, 0x1b, 0x16, 0x1e, 0x5c, 0x1f, 0xa7, 0x42, 0x5e, 0x73, 0x04, 0x33, 0x62, 0x93, 0x8b, 0x98, 0x24}
		assert.Equal(t, expected, hasher.dst)
	})

	t.Run("hash string SHA2-384", func(t *testing.T) {
		hasher := NewHasher().FromString("hello").BySha2(384)
		assert.Nil(t, hasher.Error)
		expected := []byte{0x59, 0xe1, 0x74, 0x87, 0x77, 0x44, 0x8c, 0x69, 0xde, 0x6b, 0x80, 0x0d, 0x7a, 0x33, 0xbb, 0xfb, 0x9f, 0xf1, 0xb4, 0x63, 0xe4, 0x43, 0x54, 0xc3, 0x55, 0x3b, 0xcd, 0xb9, 0xc6, 0x66, 0xfa, 0x90, 0x12, 0x5a, 0x3c, 0x79, 0xf9, 0x03, 0x97, 0xbd, 0xf5, 0xf6, 0xa1, 0x3d, 0xe8, 0x28, 0x68, 0x4f}
		assert.Equal(t, expected, hasher.dst)
	})

	t.Run("hash string SHA2-512", func(t *testing.T) {
		hasher := NewHasher().FromString("hello").BySha2(512)
		assert.Nil(t, hasher.Error)
		expected := []byte{0x9b, 0x71, 0xd2, 0x24, 0xbd, 0x62, 0xf3, 0x78, 0x5d, 0x96, 0xd4, 0x6a, 0xd3, 0xea, 0x3d, 0x73, 0x31, 0x9b, 0xfb, 0xc2, 0x89, 0x0c, 0xaa, 0xda, 0xe2, 0xdf, 0xf7, 0x25, 0x19, 0x67, 0x3c, 0xa7, 0x23, 0x23, 0xc3, 0xd9, 0x9b, 0xa5, 0xc1, 0x1d, 0x7c, 0x7a, 0xcc, 0x6e, 0x14, 0xb8, 0xc5, 0xda, 0x0c, 0x46, 0x63, 0x47, 0x5c, 0x2e, 0x5c, 0x3a, 0xde, 0xf4, 0x6f, 0x73, 0xbc, 0xde, 0xc0, 0x43}
		assert.Equal(t, expected, hasher.dst)
	})

	t.Run("hash bytes SHA2-256", func(t *testing.T) {
		hasher := NewHasher().FromBytes([]byte("hello")).BySha2(256)
		assert.Nil(t, hasher.Error)
		expected := []byte{0x2c, 0xf2, 0x4d, 0xba, 0x5f, 0xb0, 0xa3, 0x0e, 0x26, 0xe8, 0x3b, 0x2a, 0xc5, 0xb9, 0xe2, 0x9e, 0x1b, 0x16, 0x1e, 0x5c, 0x1f, 0xa7, 0x42, 0x5e, 0x73, 0x04, 0x33, 0x62, 0x93, 0x8b, 0x98, 0x24}
		assert.Equal(t, expected, hasher.dst)
	})

	t.Run("hash file SHA2-256", func(t *testing.T) {
		file := mock.NewFile([]byte("hello"), "test.txt")
		hasher := NewHasher().FromFile(file).BySha2(256)
		assert.Nil(t, hasher.Error)
		expected := []byte{0x2c, 0xf2, 0x4d, 0xba, 0x5f, 0xb0, 0xa3, 0x0e, 0x26, 0xe8, 0x3b, 0x2a, 0xc5, 0xb9, 0xe2, 0x9e, 0x1b, 0x16, 0x1e, 0x5c, 0x1f, 0xa7, 0x42, 0x5e, 0x73, 0x04, 0x33, 0x62, 0x93, 0x8b, 0x98, 0x24}
		assert.Equal(t, expected, hasher.dst)
	})

	t.Run("empty string SHA2-224", func(t *testing.T) {
		hasher := NewHasher().FromString("").BySha2(224)
		assert.Nil(t, hasher.Error)
		assert.Nil(t, hasher.dst) // Empty input returns nil
	})

	t.Run("empty string SHA2-256", func(t *testing.T) {
		hasher := NewHasher().FromString("").BySha2(256)
		assert.Nil(t, hasher.Error)
		assert.Nil(t, hasher.dst) // Empty input returns nil
	})

	t.Run("empty string SHA2-384", func(t *testing.T) {
		hasher := NewHasher().FromString("").BySha2(384)
		assert.Nil(t, hasher.Error)
		assert.Nil(t, hasher.dst) // Empty input returns nil
	})

	t.Run("empty string SHA2-512", func(t *testing.T) {
		hasher := NewHasher().FromString("").BySha2(512)
		assert.Nil(t, hasher.Error)
		assert.Nil(t, hasher.dst) // Empty input returns nil
	})

	t.Run("empty bytes SHA2-256", func(t *testing.T) {
		hasher := NewHasher().FromBytes([]byte{}).BySha2(256)
		assert.Nil(t, hasher.Error)
		assert.Nil(t, hasher.dst) // Empty input returns nil
	})

	t.Run("nil bytes SHA2-256", func(t *testing.T) {
		hasher := NewHasher().FromBytes(nil).BySha2(256)
		assert.Nil(t, hasher.Error)
		assert.Nil(t, hasher.dst) // Empty input returns nil
	})

	t.Run("large data SHA2-256", func(t *testing.T) {
		data := strings.Repeat("a", 10000)
		hasher := NewHasher().FromString(data).BySha2(256)
		assert.Nil(t, hasher.Error)
		assert.Equal(t, 32, len(hasher.dst)) // SHA2-256 produces 32 bytes
	})

	t.Run("unicode data SHA2-256", func(t *testing.T) {
		hasher := NewHasher().FromString("你好世界").BySha2(256)
		assert.Nil(t, hasher.Error)
		assert.Equal(t, 32, len(hasher.dst))
	})

	t.Run("binary data SHA2-256", func(t *testing.T) {
		binaryData := []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f}
		hasher := NewHasher().FromBytes(binaryData).BySha2(256)
		assert.Nil(t, hasher.Error)
		assert.Equal(t, 32, len(hasher.dst))
	})

	t.Run("empty file SHA2-256", func(t *testing.T) {
		file := mock.NewFile([]byte{}, "empty.txt")
		hasher := NewHasher().FromFile(file).BySha2(256)
		assert.Nil(t, hasher.Error)
		assert.Equal(t, []byte{}, hasher.dst) // Empty file returns empty slice
	})
}

func TestHasher_BySha2_HMAC(t *testing.T) {
	t.Run("hmac with key SHA2-256", func(t *testing.T) {
		hasher := NewHasher().FromString("hello").WithKey([]byte("secret")).BySha2(256)
		assert.Nil(t, hasher.Error)
		assert.Equal(t, 32, len(hasher.dst))
	})

	t.Run("hmac different input types SHA2-256", func(t *testing.T) {
		// String input
		hasher1 := NewHasher().FromString("hello").WithKey([]byte("secret")).BySha2(256)
		assert.Nil(t, hasher1.Error)
		assert.Equal(t, 32, len(hasher1.dst))

		// Bytes input
		hasher2 := NewHasher().FromBytes([]byte("hello")).WithKey([]byte("secret")).BySha2(256)
		assert.Nil(t, hasher2.Error)
		assert.Equal(t, 32, len(hasher2.dst))

		// Should produce same result
		assert.Equal(t, hasher1.dst, hasher2.dst)
	})

	t.Run("hmac large key SHA2-256", func(t *testing.T) {
		largeKey := strings.Repeat("secret", 100)
		hasher := NewHasher().FromString("hello").WithKey([]byte(largeKey)).BySha2(256)
		assert.Nil(t, hasher.Error)
		assert.Equal(t, 32, len(hasher.dst))
	})

	t.Run("hmac with file SHA2-256", func(t *testing.T) {
		file := mock.NewFile([]byte("hello"), "test.txt")
		hasher := NewHasher().FromFile(file).WithKey([]byte("secret")).BySha2(256)
		assert.Nil(t, hasher.Error)
		assert.Equal(t, 32, len(hasher.dst))
	})

	t.Run("hmac with empty file SHA2-256", func(t *testing.T) {
		file := mock.NewFile([]byte{}, "empty.txt")
		hasher := NewHasher().FromFile(file).WithKey([]byte("secret")).BySha2(256)
		assert.Nil(t, hasher.Error)
		assert.Equal(t, []byte{}, hasher.dst)
	})

	t.Run("hmac all sizes", func(t *testing.T) {
		sizes := []int{224, 256, 384, 512}
		expectedLengths := []int{28, 32, 48, 64}

		for i, size := range sizes {
			hasher := NewHasher().FromString("hello").WithKey([]byte("secret")).BySha2(size)
			assert.Nil(t, hasher.Error)
			assert.Equal(t, expectedLengths[i], len(hasher.dst))
		}
	})
}

func TestHasher_BySha2_Error(t *testing.T) {
	t.Run("file read error SHA2-256", func(t *testing.T) {
		file := mock.NewErrorFile(errors.New("read error"))
		hasher := NewHasher().FromFile(file).BySha2(256)
		assert.NotNil(t, hasher.Error)
		assert.Contains(t, hasher.Error.Error(), "read error")
	})

	t.Run("existing error SHA2-256", func(t *testing.T) {
		hasher := NewHasher()
		hasher.Error = errors.New("existing error")
		result := hasher.BySha2(256)
		assert.Equal(t, "existing error", result.Error.Error())
		assert.Nil(t, result.dst)
	})

	t.Run("invalid size with error", func(t *testing.T) {
		hasher := NewHasher()
		hasher.Error = errors.New("existing error")
		result := hasher.BySha2(128)
		assert.Equal(t, "existing error", result.Error.Error())
		assert.Nil(t, result.dst)
	})

	t.Run("error propagation", func(t *testing.T) {
		hasher := NewHasher()
		hasher.Error = errors.New("test error")
		result := hasher.BySha2(256)
		assert.Equal(t, hasher, result)
		assert.Equal(t, errors.New("test error"), result.Error)
	})

	t.Run("file with error SHA2-256", func(t *testing.T) {
		file := mock.NewErrorFile(errors.New("read error"))
		hasher := NewHasher().FromFile(file).BySha2(256)
		assert.NotNil(t, hasher.Error)
		assert.Contains(t, hasher.Error.Error(), "read error")
	})

	t.Run("unsupported size", func(t *testing.T) {
		hasher := NewHasher().FromString("hello").BySha2(128)
		assert.NotNil(t, hasher.Error)
		assert.Contains(t, hasher.Error.Error(), "unsupported SHA2 size: 128")
		assert.Contains(t, hasher.Error.Error(), "supported sizes are 224, 256, 384, 512")
	})

	t.Run("hmac with empty key SHA2-256", func(t *testing.T) {
		hasher := NewHasher().FromString("hello").WithKey([]byte{}).BySha2(256)
		assert.NotNil(t, hasher.Error)
		assert.Contains(t, hasher.Error.Error(), "hmac: key cannot be empty")
	})

	t.Run("hmac with nil key SHA2-256", func(t *testing.T) {
		hasher := NewHasher().FromString("hello").WithKey(nil).BySha2(256)
		assert.NotNil(t, hasher.Error)
		assert.Contains(t, hasher.Error.Error(), "hmac: key cannot be empty")
	})
}
