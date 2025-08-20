package hash

import (
	"errors"
	"strings"
	"testing"

	"gitee.com/golang-package/dongle/mock"
	"github.com/stretchr/testify/assert"
)

func TestHasher_BySha3(t *testing.T) {
	t.Run("hash string SHA3-224", func(t *testing.T) {
		hasher := NewHasher().FromString("hello").BySha3(224)
		assert.Nil(t, hasher.Error)
		expected := []byte{0xb8, 0x7f, 0x88, 0xc7, 0x27, 0x02, 0xff, 0xf1, 0x74, 0x8e, 0x58, 0xb8, 0x7e, 0x91, 0x41, 0xa4, 0x2c, 0x0d, 0xbe, 0xdc, 0x29, 0xa7, 0x8c, 0xb0, 0xd4, 0xa5, 0xcd, 0x81}
		assert.Equal(t, expected, hasher.dst)
	})

	t.Run("hash string SHA3-256", func(t *testing.T) {
		hasher := NewHasher().FromString("hello").BySha3(256)
		assert.Nil(t, hasher.Error)
		expected := []byte{0x33, 0x38, 0xbe, 0x69, 0x4f, 0x50, 0xc5, 0xf3, 0x38, 0x81, 0x49, 0x86, 0xcd, 0xf0, 0x68, 0x64, 0x53, 0xa8, 0x88, 0xb8, 0x4f, 0x42, 0x4d, 0x79, 0x2a, 0xf4, 0xb9, 0x20, 0x23, 0x98, 0xf3, 0x92}
		assert.Equal(t, expected, hasher.dst)
	})

	t.Run("hash string SHA3-384", func(t *testing.T) {
		hasher := NewHasher().FromString("hello").BySha3(384)
		assert.Nil(t, hasher.Error)
		expected := []byte{0x72, 0x0a, 0xea, 0x11, 0x01, 0x9e, 0xf0, 0x64, 0x40, 0xfb, 0xf0, 0x5d, 0x87, 0xaa, 0x24, 0x68, 0x0a, 0x21, 0x53, 0xdf, 0x39, 0x07, 0xb2, 0x36, 0x31, 0xe7, 0x17, 0x7c, 0xe6, 0x20, 0xfa, 0x13, 0x30, 0xff, 0x07, 0xc0, 0xfd, 0xde, 0xe5, 0x46, 0x99, 0xa4, 0xc3, 0xee, 0x0e, 0xe9, 0xd8, 0x87}
		assert.Equal(t, expected, hasher.dst)
	})

	t.Run("hash string SHA3-512", func(t *testing.T) {
		hasher := NewHasher().FromString("hello").BySha3(512)
		assert.Nil(t, hasher.Error)
		expected := []byte{0x75, 0xd5, 0x27, 0xc3, 0x68, 0xf2, 0xef, 0xe8, 0x48, 0xec, 0xf6, 0xb0, 0x73, 0xa3, 0x67, 0x67, 0x80, 0x08, 0x05, 0xe9, 0xee, 0xf2, 0xb1, 0x85, 0x7d, 0x5f, 0x98, 0x4f, 0x03, 0x6e, 0xb6, 0xdf, 0x89, 0x1d, 0x75, 0xf7, 0x2d, 0x9b, 0x15, 0x45, 0x18, 0xc1, 0xcd, 0x58, 0x83, 0x52, 0x86, 0xd1, 0xda, 0x9a, 0x38, 0xde, 0xba, 0x3d, 0xe9, 0x8b, 0x5a, 0x53, 0xe5, 0xed, 0x78, 0xa8, 0x49, 0x76}
		assert.Equal(t, expected, hasher.dst)
	})

	t.Run("hash bytes SHA3-256", func(t *testing.T) {
		hasher := NewHasher().FromBytes([]byte("hello")).BySha3(256)
		assert.Nil(t, hasher.Error)
		expected := []byte{0x33, 0x38, 0xbe, 0x69, 0x4f, 0x50, 0xc5, 0xf3, 0x38, 0x81, 0x49, 0x86, 0xcd, 0xf0, 0x68, 0x64, 0x53, 0xa8, 0x88, 0xb8, 0x4f, 0x42, 0x4d, 0x79, 0x2a, 0xf4, 0xb9, 0x20, 0x23, 0x98, 0xf3, 0x92}
		assert.Equal(t, expected, hasher.dst)
	})

	t.Run("hash file SHA3-256", func(t *testing.T) {
		file := mock.NewFile([]byte("hello"), "test.txt")
		hasher := NewHasher().FromFile(file).BySha3(256)
		assert.Nil(t, hasher.Error)
		expected := []byte{0x33, 0x38, 0xbe, 0x69, 0x4f, 0x50, 0xc5, 0xf3, 0x38, 0x81, 0x49, 0x86, 0xcd, 0xf0, 0x68, 0x64, 0x53, 0xa8, 0x88, 0xb8, 0x4f, 0x42, 0x4d, 0x79, 0x2a, 0xf4, 0xb9, 0x20, 0x23, 0x98, 0xf3, 0x92}
		assert.Equal(t, expected, hasher.dst)
	})

	t.Run("empty string SHA3-224", func(t *testing.T) {
		hasher := NewHasher().FromString("").BySha3(224)
		assert.Nil(t, hasher.Error)
		assert.Nil(t, hasher.dst) // Empty input returns nil
	})

	t.Run("empty string SHA3-256", func(t *testing.T) {
		hasher := NewHasher().FromString("").BySha3(256)
		assert.Nil(t, hasher.Error)
		assert.Nil(t, hasher.dst) // Empty input returns nil
	})

	t.Run("empty string SHA3-384", func(t *testing.T) {
		hasher := NewHasher().FromString("").BySha3(384)
		assert.Nil(t, hasher.Error)
		assert.Nil(t, hasher.dst) // Empty input returns nil
	})

	t.Run("empty string SHA3-512", func(t *testing.T) {
		hasher := NewHasher().FromString("").BySha3(512)
		assert.Nil(t, hasher.Error)
		assert.Nil(t, hasher.dst) // Empty input returns nil
	})

	t.Run("empty bytes SHA3-256", func(t *testing.T) {
		hasher := NewHasher().FromBytes([]byte{}).BySha3(256)
		assert.Nil(t, hasher.Error)
		assert.Nil(t, hasher.dst) // Empty input returns nil
	})

	t.Run("nil bytes SHA3-256", func(t *testing.T) {
		hasher := NewHasher().FromBytes(nil).BySha3(256)
		assert.Nil(t, hasher.Error)
		assert.Nil(t, hasher.dst) // Empty input returns nil
	})

	t.Run("large data SHA3-256", func(t *testing.T) {
		data := strings.Repeat("a", 10000)
		hasher := NewHasher().FromString(data).BySha3(256)
		assert.Nil(t, hasher.Error)
		assert.Equal(t, 32, len(hasher.dst)) // SHA3-256 produces 32 bytes
	})

	t.Run("unicode data SHA3-256", func(t *testing.T) {
		hasher := NewHasher().FromString("你好世界").BySha3(256)
		assert.Nil(t, hasher.Error)
		assert.Equal(t, 32, len(hasher.dst))
	})

	t.Run("binary data SHA3-256", func(t *testing.T) {
		binaryData := []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f}
		hasher := NewHasher().FromBytes(binaryData).BySha3(256)
		assert.Nil(t, hasher.Error)
		assert.Equal(t, 32, len(hasher.dst))
	})

	t.Run("empty file SHA3-256", func(t *testing.T) {
		file := mock.NewFile([]byte{}, "empty.txt")
		hasher := NewHasher().FromFile(file).BySha3(256)
		assert.Nil(t, hasher.Error)
		assert.Equal(t, []byte{}, hasher.dst) // Empty file returns empty slice
	})
}

func TestHasher_BySha3_HMAC(t *testing.T) {
	t.Run("hmac with key SHA3-256", func(t *testing.T) {
		hasher := NewHasher().FromString("hello").WithKey([]byte("secret")).BySha3(256)
		assert.Nil(t, hasher.Error)
		assert.Equal(t, 32, len(hasher.dst))
	})

	t.Run("hmac different input types SHA3-256", func(t *testing.T) {
		// String input
		hasher1 := NewHasher().FromString("hello").WithKey([]byte("secret")).BySha3(256)
		assert.Nil(t, hasher1.Error)
		assert.Equal(t, 32, len(hasher1.dst))

		// Bytes input
		hasher2 := NewHasher().FromBytes([]byte("hello")).WithKey([]byte("secret")).BySha3(256)
		assert.Nil(t, hasher2.Error)
		assert.Equal(t, 32, len(hasher2.dst))

		// Should produce same result
		assert.Equal(t, hasher1.dst, hasher2.dst)
	})

	t.Run("hmac large key SHA3-256", func(t *testing.T) {
		largeKey := strings.Repeat("secret", 100)
		hasher := NewHasher().FromString("hello").WithKey([]byte(largeKey)).BySha3(256)
		assert.Nil(t, hasher.Error)
		assert.Equal(t, 32, len(hasher.dst))
	})

	t.Run("hmac with file SHA3-256", func(t *testing.T) {
		file := mock.NewFile([]byte("hello"), "test.txt")
		hasher := NewHasher().FromFile(file).WithKey([]byte("secret")).BySha3(256)
		assert.Nil(t, hasher.Error)
		assert.Equal(t, 32, len(hasher.dst))
	})

	t.Run("hmac with empty file SHA3-256", func(t *testing.T) {
		file := mock.NewFile([]byte{}, "empty.txt")
		hasher := NewHasher().FromFile(file).WithKey([]byte("secret")).BySha3(256)
		assert.Nil(t, hasher.Error)
		assert.Equal(t, []byte{}, hasher.dst)
	})

	t.Run("hmac all sizes", func(t *testing.T) {
		sizes := []int{224, 256, 384, 512}
		expectedLengths := []int{28, 32, 48, 64}

		for i, size := range sizes {
			hasher := NewHasher().FromString("hello").WithKey([]byte("secret")).BySha3(size)
			assert.Nil(t, hasher.Error)
			assert.Equal(t, expectedLengths[i], len(hasher.dst))
		}
	})
}

func TestHasher_BySha3_Error(t *testing.T) {
	t.Run("file read error SHA3-256", func(t *testing.T) {
		file := mock.NewErrorFile(errors.New("read error"))
		hasher := NewHasher().FromFile(file).BySha3(256)
		assert.NotNil(t, hasher.Error)
		assert.Contains(t, hasher.Error.Error(), "read error")
	})

	t.Run("existing error SHA3-256", func(t *testing.T) {
		hasher := NewHasher()
		hasher.Error = errors.New("existing error")
		result := hasher.BySha3(256)
		assert.Equal(t, "existing error", result.Error.Error())
		assert.Nil(t, result.dst)
	})

	t.Run("invalid size with error", func(t *testing.T) {
		hasher := NewHasher()
		hasher.Error = errors.New("existing error")
		result := hasher.BySha3(128)
		assert.Equal(t, "existing error", result.Error.Error())
		assert.Nil(t, result.dst)
	})

	t.Run("error propagation", func(t *testing.T) {
		hasher := NewHasher()
		hasher.Error = errors.New("test error")
		result := hasher.BySha3(256)
		assert.Equal(t, hasher, result)
		assert.Equal(t, errors.New("test error"), result.Error)
	})

	t.Run("file with error SHA3-256", func(t *testing.T) {
		file := mock.NewErrorFile(errors.New("read error"))
		hasher := NewHasher().FromFile(file).BySha3(256)
		assert.NotNil(t, hasher.Error)
		assert.Contains(t, hasher.Error.Error(), "read error")
	})

	t.Run("unsupported size", func(t *testing.T) {
		hasher := NewHasher().FromString("hello").BySha3(128)
		assert.NotNil(t, hasher.Error)
		assert.Contains(t, hasher.Error.Error(), "unsupported SHA3 size: 128")
		assert.Contains(t, hasher.Error.Error(), "supported sizes are 224, 256, 384, 512")
	})

	t.Run("hmac with empty key SHA3-256", func(t *testing.T) {
		hasher := NewHasher().FromString("hello").WithKey([]byte{}).BySha3(256)
		assert.NotNil(t, hasher.Error)
		assert.Contains(t, hasher.Error.Error(), "hmac: key cannot be empty")
	})

	t.Run("hmac with nil key SHA3-256", func(t *testing.T) {
		hasher := NewHasher().FromString("hello").WithKey(nil).BySha3(256)
		assert.NotNil(t, hasher.Error)
		assert.Contains(t, hasher.Error.Error(), "hmac: key cannot be empty")
	})
}
