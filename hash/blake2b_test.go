package hash

import (
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/dromara/dongle/mock"
)

func TestHasher_ByBlake2b(t *testing.T) {
	t.Run("hash string BLAKE2b-256", func(t *testing.T) {
		hasher := NewHasher().FromString("hello").ByBlake2b(256)
		assert.Nil(t, hasher.Error)
		expected := []byte{0x32, 0x4d, 0xcf, 0x2, 0x7d, 0xd4, 0xa3, 0xa, 0x93, 0x2c, 0x44, 0x1f, 0x36, 0x5a, 0x25, 0xe8, 0x6b, 0x17, 0x3d, 0xef, 0xa4, 0xb8, 0xe5, 0x89, 0x48, 0x25, 0x34, 0x71, 0xb8, 0x1b, 0x72, 0xcf}
		assert.Equal(t, expected, hasher.dst)
	})

	t.Run("hash string BLAKE2b-384", func(t *testing.T) {
		hasher := NewHasher().FromString("hello").ByBlake2b(384)
		assert.Nil(t, hasher.Error)
		expected := []byte{0x85, 0xf1, 0x91, 0x70, 0xbe, 0x54, 0x1e, 0x77, 0x74, 0xda, 0x19, 0x7c, 0x12, 0xce, 0x95, 0x9b, 0x91, 0xa2, 0x80, 0xb2, 0xf2, 0x3e, 0x31, 0x13, 0xd6, 0x63, 0x8a, 0x33, 0x35, 0x50, 0x7e, 0xd7, 0x2d, 0xdc, 0x30, 0xf8, 0x12, 0x44, 0xdb, 0xe9, 0xfa, 0x8d, 0x19, 0x5c, 0x23, 0xbc, 0xeb, 0x7e}
		assert.Equal(t, expected, hasher.dst)
	})

	t.Run("hash string BLAKE2b-512", func(t *testing.T) {
		hasher := NewHasher().FromString("hello").ByBlake2b(512)
		assert.Nil(t, hasher.Error)
		expected := []byte{0xe4, 0xcf, 0xa3, 0x9a, 0x3d, 0x37, 0xbe, 0x31, 0xc5, 0x96, 0x9, 0xe8, 0x7, 0x97, 0x7, 0x99, 0xca, 0xa6, 0x8a, 0x19, 0xbf, 0xaa, 0x15, 0x13, 0x5f, 0x16, 0x50, 0x85, 0xe0, 0x1d, 0x41, 0xa6, 0x5b, 0xa1, 0xe1, 0xb1, 0x46, 0xae, 0xb6, 0xbd, 0x0, 0x92, 0xb4, 0x9e, 0xac, 0x21, 0x4c, 0x10, 0x3c, 0xcf, 0xa3, 0xa3, 0x65, 0x95, 0x4b, 0xbb, 0xe5, 0x2f, 0x74, 0xa2, 0xb3, 0x62, 0xc, 0x94}
		assert.Equal(t, expected, hasher.dst)
	})

	t.Run("hash bytes BLAKE2b-256", func(t *testing.T) {
		hasher := NewHasher().FromBytes([]byte("hello")).ByBlake2b(256)
		assert.Nil(t, hasher.Error)
		expected := []byte{0x32, 0x4d, 0xcf, 0x02, 0x7d, 0xd4, 0xa3, 0x0a, 0x93, 0x2c, 0x44, 0x1f, 0x36, 0x5a, 0x25, 0xe8, 0x6b, 0x17, 0x3d, 0xef, 0xa4, 0xb8, 0xe5, 0x89, 0x48, 0x25, 0x34, 0x71, 0xb8, 0x1b, 0x72, 0xcf}
		assert.Equal(t, expected, hasher.dst)
	})

	t.Run("hash file BLAKE2b-256", func(t *testing.T) {
		file := mock.NewFile([]byte("hello"), "test.txt")
		hasher := NewHasher().FromFile(file).ByBlake2b(256)
		assert.Nil(t, hasher.Error)
		expected := []byte{0x32, 0x4d, 0xcf, 0x02, 0x7d, 0xd4, 0xa3, 0x0a, 0x93, 0x2c, 0x44, 0x1f, 0x36, 0x5a, 0x25, 0xe8, 0x6b, 0x17, 0x3d, 0xef, 0xa4, 0xb8, 0xe5, 0x89, 0x48, 0x25, 0x34, 0x71, 0xb8, 0x1b, 0x72, 0xcf}
		assert.Equal(t, expected, hasher.dst)
	})

	t.Run("empty string BLAKE2b-256", func(t *testing.T) {
		hasher := NewHasher().FromString("").ByBlake2b(256)
		assert.Nil(t, hasher.Error)
		assert.Nil(t, hasher.dst) // Empty input returns nil
	})

	t.Run("empty string BLAKE2b-384", func(t *testing.T) {
		hasher := NewHasher().FromString("").ByBlake2b(384)
		assert.Nil(t, hasher.Error)
		assert.Nil(t, hasher.dst) // Empty input returns nil
	})

	t.Run("empty string BLAKE2b-512", func(t *testing.T) {
		hasher := NewHasher().FromString("").ByBlake2b(512)
		assert.Nil(t, hasher.Error)
		assert.Nil(t, hasher.dst) // Empty input returns nil
	})

	t.Run("empty bytes BLAKE2b-256", func(t *testing.T) {
		hasher := NewHasher().FromBytes([]byte{}).ByBlake2b(256)
		assert.Nil(t, hasher.Error)
		assert.Nil(t, hasher.dst) // Empty input returns nil
	})

	t.Run("nil bytes BLAKE2b-256", func(t *testing.T) {
		hasher := NewHasher().FromBytes(nil).ByBlake2b(256)
		assert.Nil(t, hasher.Error)
		assert.Nil(t, hasher.dst) // Empty input returns nil
	})

	t.Run("large data BLAKE2b-256", func(t *testing.T) {
		data := strings.Repeat("a", 10000)
		hasher := NewHasher().FromString(data).ByBlake2b(256)
		assert.Nil(t, hasher.Error)
		expected := []byte{0xf7, 0xc9, 0xec, 0x1e, 0x1f, 0xff, 0x64, 0x91, 0xcd, 0x1f, 0xb3, 0xbe, 0x9d, 0x12, 0x09, 0xc2, 0x44, 0x4c, 0x8f, 0x09, 0x52, 0x31, 0xa6, 0xb1, 0xf1, 0xdf, 0x21, 0x5f, 0x89, 0xe8, 0x85, 0xb0}
		assert.Equal(t, expected, hasher.dst)
	})

	t.Run("unicode data BLAKE2b-256", func(t *testing.T) {
		hasher := NewHasher().FromString("你好世界").ByBlake2b(256)
		assert.Nil(t, hasher.Error)
		expected := []byte{0xb4, 0xac, 0xed, 0xb8, 0xa2, 0xab, 0x84, 0x62, 0x2e, 0xfb, 0x1c, 0x50, 0xfa, 0x13, 0x33, 0xf9, 0x3b, 0xf8, 0xd5, 0x3a, 0xd7, 0x63, 0x44, 0x24, 0xe1, 0xf9, 0x6c, 0x57, 0x00, 0x9e, 0x6f, 0x8e}
		assert.Equal(t, expected, hasher.dst)
	})

	t.Run("binary data BLAKE2b-256", func(t *testing.T) {
		binaryData := []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f}
		hasher := NewHasher().FromBytes(binaryData).ByBlake2b(256)
		assert.Nil(t, hasher.Error)
		expected := []byte{0xc7, 0xcb, 0x5d, 0x1a, 0x1a, 0x21, 0x4f, 0x1d, 0x83, 0x3a, 0x21, 0xfe, 0x6c, 0x7b, 0x24, 0x20, 0xe4, 0x17, 0xc2, 0xf2, 0x20, 0x78, 0x4c, 0xbe, 0x90, 0x07, 0x29, 0x75, 0x13, 0x1b, 0xc3, 0x67}
		assert.Equal(t, expected, hasher.dst)
	})

	t.Run("empty file BLAKE2b-256", func(t *testing.T) {
		file := mock.NewFile([]byte{}, "empty.txt")
		hasher := NewHasher().FromFile(file).ByBlake2b(256)
		assert.Nil(t, hasher.Error)
		assert.Equal(t, []byte{}, hasher.dst) // Empty file returns empty slice
	})

	t.Run("no data no reader no key", func(t *testing.T) {
		hasher := NewHasher().ByBlake2b(256)
		assert.Nil(t, hasher.Error)
		assert.Nil(t, hasher.dst) // No data, no reader, no key returns nil
	})
}

func TestHasher_ByBlake2b_HMAC(t *testing.T) {
	t.Run("hmac with key BLAKE2b-256", func(t *testing.T) {
		hasher := NewHasher().FromString("hello").WithKey([]byte("secret")).ByBlake2b(256)
		assert.Nil(t, hasher.Error)
		assert.Equal(t, 32, len(hasher.dst))
	})

	t.Run("hmac different input types BLAKE2b-256", func(t *testing.T) {
		// String input
		hasher1 := NewHasher().FromString("hello").WithKey([]byte("secret")).ByBlake2b(256)
		assert.Nil(t, hasher1.Error)
		assert.Equal(t, 32, len(hasher1.dst))

		// Bytes input
		hasher2 := NewHasher().FromBytes([]byte("hello")).WithKey([]byte("secret")).ByBlake2b(256)
		assert.Nil(t, hasher2.Error)
		assert.Equal(t, 32, len(hasher2.dst))

		// Should produce same result
		assert.Equal(t, hasher1.dst, hasher2.dst)
	})

	t.Run("hmac large key BLAKE2b-256", func(t *testing.T) {
		largeKey := strings.Repeat("secret", 100)
		hasher := NewHasher().FromString("hello").WithKey([]byte(largeKey)).ByBlake2b(256)
		assert.Nil(t, hasher.Error)
		assert.Equal(t, 32, len(hasher.dst))
	})

	t.Run("hmac with file BLAKE2b-256", func(t *testing.T) {
		file := mock.NewFile([]byte("hello"), "test.txt")
		hasher := NewHasher().FromFile(file).WithKey([]byte("secret")).ByBlake2b(256)
		assert.Nil(t, hasher.Error)
		assert.Equal(t, 32, len(hasher.dst))
	})

	t.Run("hmac with empty file BLAKE2b-256", func(t *testing.T) {
		file := mock.NewFile([]byte{}, "empty.txt")
		hasher := NewHasher().FromFile(file).WithKey([]byte("secret")).ByBlake2b(256)
		assert.Nil(t, hasher.Error)
		assert.Equal(t, []byte{}, hasher.dst)
	})

	t.Run("hmac all sizes", func(t *testing.T) {
		sizes := []int{256, 384, 512}
		expectedLengths := []int{32, 48, 64}

		for i, size := range sizes {
			hasher := NewHasher().FromString("hello").WithKey([]byte("secret")).ByBlake2b(size)
			assert.Nil(t, hasher.Error)
			assert.Equal(t, expectedLengths[i], len(hasher.dst))
		}
	})
}

func TestHasher_ByBlake2b_Error(t *testing.T) {
	t.Run("file read error BLAKE2b-256", func(t *testing.T) {
		file := mock.NewErrorFile(errors.New("read error"))
		hasher := NewHasher().FromFile(file).ByBlake2b(256)
		assert.NotNil(t, hasher.Error)
		assert.Contains(t, hasher.Error.Error(), "read error")
	})

	t.Run("existing error BLAKE2b-256", func(t *testing.T) {
		hasher := NewHasher()
		hasher.Error = errors.New("existing error")
		result := hasher.ByBlake2b(256)
		assert.Equal(t, "existing error", result.Error.Error())
		assert.Nil(t, result.dst)
	})

	t.Run("invalid size with error", func(t *testing.T) {
		hasher := NewHasher()
		hasher.Error = errors.New("existing error")
		result := hasher.ByBlake2b(224)
		assert.Equal(t, "existing error", result.Error.Error())
		assert.Nil(t, result.dst)
	})

	t.Run("error propagation", func(t *testing.T) {
		hasher := NewHasher()
		hasher.Error = errors.New("test error")
		result := hasher.ByBlake2b(256)
		assert.Equal(t, hasher, result)
		assert.Equal(t, errors.New("test error"), result.Error)
	})

	t.Run("file with error BLAKE2b-256", func(t *testing.T) {
		file := mock.NewErrorFile(errors.New("read error"))
		hasher := NewHasher().FromFile(file).ByBlake2b(256)
		assert.NotNil(t, hasher.Error)
		assert.Contains(t, hasher.Error.Error(), "read error")
	})

	t.Run("unsupported size", func(t *testing.T) {
		hasher := NewHasher().FromString("hello").ByBlake2b(224)
		assert.NotNil(t, hasher.Error)
		assert.Contains(t, hasher.Error.Error(), "unsupported size: 224")
		assert.Contains(t, hasher.Error.Error(), "supported sizes are 256, 384, 512")
	})

	t.Run("hmac with empty key BLAKE2b-256", func(t *testing.T) {
		hasher := NewHasher().FromString("hello").WithKey([]byte{}).ByBlake2b(256)
		assert.NotNil(t, hasher.Error)
		assert.Contains(t, hasher.Error.Error(), "hmac: key cannot be empty")
	})

	t.Run("hmac with nil key BLAKE2b-256", func(t *testing.T) {
		hasher := NewHasher().FromString("hello").WithKey(nil).ByBlake2b(256)
		assert.NotNil(t, hasher.Error)
		assert.Contains(t, hasher.Error.Error(), "hmac: key cannot be empty")
	})
}
