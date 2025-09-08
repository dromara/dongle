package hash

import (
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/dromara/dongle/mock"
)

func TestHasher_ByBlake2s(t *testing.T) {
	t.Run("hash string BLAKE2s-128 with key", func(t *testing.T) {
		hasher := NewHasher().FromString("hello").WithKey([]byte("secret")).ByBlake2s(128)
		assert.Nil(t, hasher.Error)
		expected := []byte{0xac, 0x47, 0x9a, 0x13, 0xd2, 0x64, 0x4a, 0xd5, 0x2d, 0xa7, 0xd0, 0xed, 0xf6, 0x05, 0x13, 0x42}
		assert.Equal(t, expected, hasher.dst)
	})

	t.Run("hash string BLAKE2s-256", func(t *testing.T) {
		hasher := NewHasher().FromString("hello").ByBlake2s(256)
		assert.Nil(t, hasher.Error)
		expected := []byte{0x19, 0x21, 0x3b, 0xac, 0xc5, 0x8d, 0xee, 0x6d, 0xbd, 0xe3, 0xce, 0xb9, 0xa4, 0x7c, 0xbb, 0x33, 0x0b, 0x3d, 0x86, 0xf8, 0xcc, 0xa8, 0x99, 0x7e, 0xb0, 0x0b, 0xe4, 0x56, 0xf1, 0x40, 0xca, 0x25}
		assert.Equal(t, expected, hasher.dst)
	})

	t.Run("hash bytes BLAKE2s-256", func(t *testing.T) {
		hasher := NewHasher().FromBytes([]byte("hello")).ByBlake2s(256)
		assert.Nil(t, hasher.Error)
		expected := []byte{0x19, 0x21, 0x3b, 0xac, 0xc5, 0x8d, 0xee, 0x6d, 0xbd, 0xe3, 0xce, 0xb9, 0xa4, 0x7c, 0xbb, 0x33, 0x0b, 0x3d, 0x86, 0xf8, 0xcc, 0xa8, 0x99, 0x7e, 0xb0, 0x0b, 0xe4, 0x56, 0xf1, 0x40, 0xca, 0x25}
		assert.Equal(t, expected, hasher.dst)
	})

	t.Run("hash file BLAKE2s-256", func(t *testing.T) {
		file := mock.NewFile([]byte("hello"), "test.txt")
		hasher := NewHasher().FromFile(file).ByBlake2s(256)
		assert.Nil(t, hasher.Error)
		expected := []byte{0x19, 0x21, 0x3b, 0xac, 0xc5, 0x8d, 0xee, 0x6d, 0xbd, 0xe3, 0xce, 0xb9, 0xa4, 0x7c, 0xbb, 0x33, 0x0b, 0x3d, 0x86, 0xf8, 0xcc, 0xa8, 0x99, 0x7e, 0xb0, 0x0b, 0xe4, 0x56, 0xf1, 0x40, 0xca, 0x25}
		assert.Equal(t, expected, hasher.dst)
	})

	t.Run("empty string BLAKE2s-128 with key", func(t *testing.T) {
		hasher := NewHasher().FromString("").WithKey([]byte("secret")).ByBlake2s(128)
		assert.Nil(t, hasher.Error)
		assert.Equal(t, []byte{}, hasher.dst) // Empty input returns empty slice
	})

	t.Run("empty string BLAKE2s-256", func(t *testing.T) {
		hasher := NewHasher().FromString("").ByBlake2s(256)
		assert.Nil(t, hasher.Error)
		assert.Nil(t, hasher.dst) // Empty input returns nil
	})

	t.Run("empty bytes BLAKE2s-256", func(t *testing.T) {
		hasher := NewHasher().FromBytes([]byte{}).ByBlake2s(256)
		assert.Nil(t, hasher.Error)
		assert.Nil(t, hasher.dst) // Empty input returns nil
	})

	t.Run("nil bytes BLAKE2s-256", func(t *testing.T) {
		hasher := NewHasher().FromBytes(nil).ByBlake2s(256)
		assert.Nil(t, hasher.Error)
		assert.Nil(t, hasher.dst) // Empty input returns nil
	})

	t.Run("large data BLAKE2s-256", func(t *testing.T) {
		data := strings.Repeat("a", 10000)
		hasher := NewHasher().FromString(data).ByBlake2s(256)
		assert.Nil(t, hasher.Error)
		expected := []byte{0xb9, 0x91, 0xc3, 0x17, 0x0f, 0xdd, 0xfe, 0x4c, 0x1e, 0x36, 0x74, 0xe0, 0x67, 0x4f, 0xaf, 0xd6, 0xd9, 0x3b, 0x1d, 0x59, 0xe7, 0x67, 0x48, 0x57, 0x76, 0x14, 0x50, 0x52, 0x72, 0x82, 0x21, 0x6f}
		assert.Equal(t, expected, hasher.dst)
	})

	t.Run("unicode data BLAKE2s-256", func(t *testing.T) {
		hasher := NewHasher().FromString("你好世界").ByBlake2s(256)
		assert.Nil(t, hasher.Error)
		expected := []byte{0x2f, 0x25, 0x46, 0x0b, 0xc8, 0x85, 0x06, 0x5b, 0xb5, 0x6f, 0x87, 0xff, 0x72, 0xb4, 0x0d, 0xfb, 0xec, 0x0d, 0xba, 0x4e, 0xe3, 0xbe, 0xe3, 0x9f, 0x24, 0x88, 0x22, 0x72, 0xfa, 0x37, 0x4e, 0x50}
		assert.Equal(t, expected, hasher.dst)
	})

	t.Run("binary data BLAKE2s-256", func(t *testing.T) {
		binaryData := []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f}
		hasher := NewHasher().FromBytes(binaryData).ByBlake2s(256)
		assert.Nil(t, hasher.Error)
		expected := []byte{0xef, 0xc0, 0x4c, 0xdc, 0x39, 0x1c, 0x7e, 0x91, 0x19, 0xbd, 0x38, 0x66, 0x8a, 0x53, 0x4e, 0x65, 0xfe, 0x31, 0x03, 0x6d, 0x6a, 0x62, 0x11, 0x2e, 0x44, 0xeb, 0xeb, 0x11, 0xf9, 0xc5, 0x70, 0x80}
		assert.Equal(t, expected, hasher.dst)
	})

	t.Run("empty file BLAKE2s-256", func(t *testing.T) {
		file := mock.NewFile([]byte{}, "empty.txt")
		hasher := NewHasher().FromFile(file).ByBlake2s(256)
		assert.Nil(t, hasher.Error)
		assert.Equal(t, []byte{}, hasher.dst) // Empty file returns empty slice
	})

	t.Run("no data no reader no key", func(t *testing.T) {
		hasher := NewHasher().ByBlake2s(256)
		assert.Nil(t, hasher.Error)
		assert.Nil(t, hasher.dst) // No data, no reader, no key returns nil
	})
}

func TestHasher_ByBlake2s_HMAC(t *testing.T) {
	t.Run("hmac with key BLAKE2s-256", func(t *testing.T) {
		hasher := NewHasher().FromString("hello").WithKey([]byte("secret")).ByBlake2s(256)
		assert.Nil(t, hasher.Error)
		assert.Equal(t, 32, len(hasher.dst))
	})

	t.Run("hmac with key BLAKE2s-128", func(t *testing.T) {
		hasher := NewHasher().FromString("hello").WithKey([]byte("secret")).ByBlake2s(128)
		assert.Nil(t, hasher.Error)
		assert.Equal(t, 16, len(hasher.dst))
	})

	t.Run("hmac different input types BLAKE2s-256", func(t *testing.T) {
		// String input
		hasher1 := NewHasher().FromString("hello").WithKey([]byte("secret")).ByBlake2s(256)
		assert.Nil(t, hasher1.Error)
		assert.Equal(t, 32, len(hasher1.dst))

		// Bytes input
		hasher2 := NewHasher().FromBytes([]byte("hello")).WithKey([]byte("secret")).ByBlake2s(256)
		assert.Nil(t, hasher2.Error)
		assert.Equal(t, 32, len(hasher2.dst))

		// Should produce same result
		assert.Equal(t, hasher1.dst, hasher2.dst)
	})

	t.Run("hmac large key BLAKE2s-256", func(t *testing.T) {
		largeKey := strings.Repeat("secret", 100)
		hasher := NewHasher().FromString("hello").WithKey([]byte(largeKey)).ByBlake2s(256)
		assert.Nil(t, hasher.Error)
		assert.Equal(t, 32, len(hasher.dst))
	})

	t.Run("hmac with file BLAKE2s-256", func(t *testing.T) {
		file := mock.NewFile([]byte("hello"), "test.txt")
		hasher := NewHasher().FromFile(file).WithKey([]byte("secret")).ByBlake2s(256)
		assert.Nil(t, hasher.Error)
		assert.Equal(t, 32, len(hasher.dst))
	})

	t.Run("hmac with empty file BLAKE2s-256", func(t *testing.T) {
		file := mock.NewFile([]byte{}, "empty.txt")
		hasher := NewHasher().FromFile(file).WithKey([]byte("secret")).ByBlake2s(256)
		assert.Nil(t, hasher.Error)
		assert.Equal(t, []byte{}, hasher.dst)
	})

	t.Run("hmac all sizes", func(t *testing.T) {
		sizes := []int{128, 256}
		expectedLengths := []int{16, 32}

		for i, size := range sizes {
			hasher := NewHasher().FromString("hello").WithKey([]byte("secret")).ByBlake2s(size)
			assert.Nil(t, hasher.Error)
			assert.Equal(t, expectedLengths[i], len(hasher.dst))
		}
	})
}

func TestHasher_ByBlake2s_Error(t *testing.T) {
	t.Run("file read error BLAKE2s-256", func(t *testing.T) {
		file := mock.NewErrorFile(errors.New("read error"))
		hasher := NewHasher().FromFile(file).ByBlake2s(256)
		assert.NotNil(t, hasher.Error)
		assert.Contains(t, hasher.Error.Error(), "read error")
	})

	t.Run("existing error BLAKE2s-256", func(t *testing.T) {
		hasher := NewHasher()
		hasher.Error = errors.New("existing error")
		result := hasher.ByBlake2s(256)
		assert.Equal(t, "existing error", result.Error.Error())
		assert.Nil(t, result.dst)
	})

	t.Run("invalid size with error", func(t *testing.T) {
		hasher := NewHasher()
		hasher.Error = errors.New("existing error")
		result := hasher.ByBlake2s(128)
		assert.Equal(t, "existing error", result.Error.Error())
		assert.Nil(t, result.dst)
	})

	t.Run("error propagation", func(t *testing.T) {
		hasher := NewHasher()
		hasher.Error = errors.New("test error")
		result := hasher.ByBlake2s(256)
		assert.Equal(t, hasher, result)
		assert.Equal(t, errors.New("test error"), result.Error)
	})

	t.Run("file with error BLAKE2s-256", func(t *testing.T) {
		file := mock.NewErrorFile(errors.New("read error"))
		hasher := NewHasher().FromFile(file).ByBlake2s(256)
		assert.NotNil(t, hasher.Error)
		assert.Contains(t, hasher.Error.Error(), "read error")
	})

	t.Run("unsupported size", func(t *testing.T) {
		hasher := NewHasher().FromString("hello").ByBlake2s(64)
		assert.NotNil(t, hasher.Error)
		assert.Contains(t, hasher.Error.Error(), "unsupported size: 64")
		assert.Contains(t, hasher.Error.Error(), "supported sizes are 128, 256")
	})

	t.Run("unsupported size 512", func(t *testing.T) {
		hasher := NewHasher().FromString("hello").ByBlake2s(512)
		assert.NotNil(t, hasher.Error)
		assert.Contains(t, hasher.Error.Error(), "unsupported size: 512")
		assert.Contains(t, hasher.Error.Error(), "supported sizes are 128, 256")
	})

	t.Run("hmac with empty key BLAKE2s-256", func(t *testing.T) {
		hasher := NewHasher().FromString("hello").WithKey([]byte{}).ByBlake2s(256)
		assert.NotNil(t, hasher.Error)
		assert.Contains(t, hasher.Error.Error(), "hmac: key cannot be empty")
	})

	t.Run("hmac with nil key BLAKE2s-256", func(t *testing.T) {
		hasher := NewHasher().FromString("hello").WithKey(nil).ByBlake2s(256)
		assert.NotNil(t, hasher.Error)
		assert.Contains(t, hasher.Error.Error(), "hmac: key cannot be empty")
	})

	t.Run("BLAKE2s-128 without key", func(t *testing.T) {
		hasher := NewHasher().FromString("hello").ByBlake2s(128)
		assert.NotNil(t, hasher.Error)
		assert.Contains(t, hasher.Error.Error(), "BLAKE2s-128 requires a key for security reasons")
	})

	t.Run("BLAKE2s-128 with empty key", func(t *testing.T) {
		hasher := NewHasher().FromString("hello").WithKey([]byte{}).ByBlake2s(128)
		assert.NotNil(t, hasher.Error)
		assert.Contains(t, hasher.Error.Error(), "hmac: key cannot be empty")
	})

	t.Run("BLAKE2s-128 with nil key", func(t *testing.T) {
		hasher := NewHasher().FromString("hello").WithKey(nil).ByBlake2s(128)
		assert.NotNil(t, hasher.Error)
		assert.Contains(t, hasher.Error.Error(), "hmac: key cannot be empty")
	})

	t.Run("BLAKE2s-128 with file", func(t *testing.T) {
		file := mock.NewFile([]byte("hello"), "test.txt")
		hasher := NewHasher().FromFile(file).WithKey([]byte("secret")).ByBlake2s(128)
		assert.Nil(t, hasher.Error)
		assert.Equal(t, 16, len(hasher.dst))
	})

	t.Run("BLAKE2s-256 with file", func(t *testing.T) {
		file := mock.NewFile([]byte("hello"), "test.txt")
		hasher := NewHasher().FromFile(file).ByBlake2s(256)
		assert.Nil(t, hasher.Error)
		assert.Equal(t, 32, len(hasher.dst))
	})
}
