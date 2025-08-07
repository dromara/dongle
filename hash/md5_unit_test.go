package hash

import (
	"errors"
	"strings"
	"testing"

	"github.com/dromara/dongle/mock"
	"github.com/stretchr/testify/assert"
)

func TestHasher_ByMd5(t *testing.T) {
	t.Run("hash string", func(t *testing.T) {
		hasher := NewHasher().FromString("hello").ByMd5()
		assert.Nil(t, hasher.Error)
		assert.Equal(t, []byte{0x5d, 0x41, 0x40, 0x2a, 0xbc, 0x4b, 0x2a, 0x76, 0xb9, 0x71, 0x9d, 0x91, 0x10, 0x17, 0xc5, 0x92}, hasher.dst)
	})

	t.Run("hash bytes", func(t *testing.T) {
		hasher := NewHasher().FromBytes([]byte("hello")).ByMd5()
		assert.Nil(t, hasher.Error)
		assert.Equal(t, []byte{0x5d, 0x41, 0x40, 0x2a, 0xbc, 0x4b, 0x2a, 0x76, 0xb9, 0x71, 0x9d, 0x91, 0x10, 0x17, 0xc5, 0x92}, hasher.dst)
	})

	t.Run("hash file", func(t *testing.T) {
		file := mock.NewFile([]byte("hello"), "test.txt")
		hasher := NewHasher().FromFile(file).ByMd5()
		assert.Nil(t, hasher.Error)
		assert.Equal(t, []byte{0x5d, 0x41, 0x40, 0x2a, 0xbc, 0x4b, 0x2a, 0x76, 0xb9, 0x71, 0x9d, 0x91, 0x10, 0x17, 0xc5, 0x92}, hasher.dst)
	})

	t.Run("empty string", func(t *testing.T) {
		hasher := NewHasher().FromString("").ByMd5()
		assert.Nil(t, hasher.Error)
		assert.Nil(t, hasher.dst) // Empty input returns nil
	})

	t.Run("empty bytes", func(t *testing.T) {
		hasher := NewHasher().FromBytes([]byte{}).ByMd5()
		assert.Nil(t, hasher.Error)
		assert.Nil(t, hasher.dst) // Empty input returns nil
	})

	t.Run("nil bytes", func(t *testing.T) {
		hasher := NewHasher().FromBytes(nil).ByMd5()
		assert.Nil(t, hasher.Error)
		assert.Nil(t, hasher.dst) // Empty input returns nil
	})

	t.Run("large data", func(t *testing.T) {
		data := strings.Repeat("a", 10000)
		hasher := NewHasher().FromString(data).ByMd5()
		assert.Nil(t, hasher.Error)
		assert.Equal(t, 16, len(hasher.dst))
	})

	t.Run("unicode data", func(t *testing.T) {
		hasher := NewHasher().FromString("你好世界").ByMd5()
		assert.Nil(t, hasher.Error)
		assert.Equal(t, 16, len(hasher.dst))
	})

	t.Run("binary data", func(t *testing.T) {
		binaryData := []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f}
		hasher := NewHasher().FromBytes(binaryData).ByMd5()
		assert.Nil(t, hasher.Error)
		assert.Equal(t, 16, len(hasher.dst))
	})

	t.Run("empty file", func(t *testing.T) {
		file := mock.NewFile([]byte{}, "empty.txt")
		hasher := NewHasher().FromFile(file).ByMd5()
		assert.Nil(t, hasher.Error)
		assert.Equal(t, []byte{}, hasher.dst) // Empty file returns empty slice
	})
}

func TestHasher_ByMd5_HMAC(t *testing.T) {
	t.Run("hmac with key", func(t *testing.T) {
		hasher := NewHasher().FromString("hello").WithKey([]byte("secret")).ByMd5()
		assert.Nil(t, hasher.Error)
		assert.Equal(t, 16, len(hasher.dst))
	})

	t.Run("hmac with bytes", func(t *testing.T) {
		hasher := NewHasher().FromBytes([]byte("hello")).WithKey([]byte("secret")).ByMd5()
		assert.Nil(t, hasher.Error)
		assert.Equal(t, 16, len(hasher.dst))
	})

	t.Run("hmac with file", func(t *testing.T) {
		file := mock.NewFile([]byte("hello"), "test.txt")
		hasher := NewHasher().FromFile(file).WithKey([]byte("secret")).ByMd5()
		assert.Nil(t, hasher.Error)
		assert.Equal(t, 16, len(hasher.dst))
	})

	t.Run("hmac with large key", func(t *testing.T) {
		key := make([]byte, 1000)
		for i := range key {
			key[i] = byte(i % 256)
		}
		hasher := NewHasher().FromString("hello").WithKey(key).ByMd5()
		assert.Nil(t, hasher.Error)
		assert.Equal(t, 16, len(hasher.dst))
	})
}

func TestHasher_ByMd5_Error(t *testing.T) {
	t.Run("file read error", func(t *testing.T) {
		file := mock.NewErrorFile(errors.New("file read error"))
		hasher := NewHasher().FromFile(file).ByMd5()
		assert.NotNil(t, hasher.Error)
		assert.Contains(t, hasher.Error.Error(), "file read error")
	})

	t.Run("file read error after partial read", func(t *testing.T) {
		file := mock.NewErrorFile(errors.New("partial read error"))
		hasher := NewHasher().FromFile(file).ByMd5()
		assert.NotNil(t, hasher.Error)
		assert.Contains(t, hasher.Error.Error(), "partial read error")
	})

	t.Run("error with key", func(t *testing.T) {
		hasher := NewHasher()
		hasher.Error = errors.New("existing error")
		result := hasher.WithKey([]byte("secret")).ByMd5()
		assert.Equal(t, hasher, result)
		assert.Equal(t, errors.New("existing error"), result.Error)
	})

	t.Run("error propagation", func(t *testing.T) {
		hasher := NewHasher()
		hasher.Error = errors.New("test error")
		result := hasher.ByMd5()
		assert.Equal(t, hasher, result)
		assert.Equal(t, errors.New("test error"), result.Error)
	})

	t.Run("file with error", func(t *testing.T) {
		file := mock.NewErrorFile(errors.New("read error"))
		hasher := NewHasher().FromFile(file).ByMd5()
		assert.NotNil(t, hasher.Error)
		assert.Contains(t, hasher.Error.Error(), "read error")
	})

	t.Run("hmac with empty key", func(t *testing.T) {
		hasher := NewHasher().FromString("hello").WithKey([]byte{}).ByMd5()
		assert.NotNil(t, hasher.Error)
		assert.Contains(t, hasher.Error.Error(), "hmac: key cannot be empty")
	})

	t.Run("hmac with nil key", func(t *testing.T) {
		hasher := NewHasher().FromString("hello").WithKey(nil).ByMd5()
		assert.NotNil(t, hasher.Error)
		assert.Contains(t, hasher.Error.Error(), "hmac: key cannot be empty")
	})
}
