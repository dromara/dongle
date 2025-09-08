package hash

import (
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/dromara/dongle/mock"
)

func TestHasher_BySha1(t *testing.T) {
	t.Run("hash string", func(t *testing.T) {
		hasher := NewHasher().FromString("hello").BySha1()
		assert.Nil(t, hasher.Error)
		assert.Equal(t, []byte{0xaa, 0xf4, 0xc6, 0x1d, 0xdc, 0xc5, 0xe8, 0xa2, 0xda, 0xbe, 0xde, 0x0f, 0x3b, 0x48, 0x2c, 0xd9, 0xae, 0xa9, 0x43, 0x4d}, hasher.dst)
	})

	t.Run("hash bytes", func(t *testing.T) {
		hasher := NewHasher().FromBytes([]byte("hello")).BySha1()
		assert.Nil(t, hasher.Error)
		assert.Equal(t, []byte{0xaa, 0xf4, 0xc6, 0x1d, 0xdc, 0xc5, 0xe8, 0xa2, 0xda, 0xbe, 0xde, 0x0f, 0x3b, 0x48, 0x2c, 0xd9, 0xae, 0xa9, 0x43, 0x4d}, hasher.dst)
	})

	t.Run("hash file", func(t *testing.T) {
		file := mock.NewFile([]byte("hello"), "test.txt")
		hasher := NewHasher().FromFile(file).BySha1()
		assert.Nil(t, hasher.Error)
		assert.Equal(t, []byte{0xaa, 0xf4, 0xc6, 0x1d, 0xdc, 0xc5, 0xe8, 0xa2, 0xda, 0xbe, 0xde, 0x0f, 0x3b, 0x48, 0x2c, 0xd9, 0xae, 0xa9, 0x43, 0x4d}, hasher.dst)
	})

	t.Run("empty string", func(t *testing.T) {
		hasher := NewHasher().FromString("").BySha1()
		assert.Nil(t, hasher.Error)
		assert.Nil(t, hasher.dst) // Empty input returns nil
	})

	t.Run("empty bytes", func(t *testing.T) {
		hasher := NewHasher().FromBytes([]byte{}).BySha1()
		assert.Nil(t, hasher.Error)
		assert.Nil(t, hasher.dst) // Empty input returns nil
	})

	t.Run("nil bytes", func(t *testing.T) {
		hasher := NewHasher().FromBytes(nil).BySha1()
		assert.Nil(t, hasher.Error)
		assert.Nil(t, hasher.dst) // Empty input returns nil
	})

	t.Run("large data", func(t *testing.T) {
		data := strings.Repeat("a", 10000)
		hasher := NewHasher().FromString(data).BySha1()
		assert.Nil(t, hasher.Error)
		assert.Equal(t, 20, len(hasher.dst)) // SHA1 produces 20 bytes
	})

	t.Run("unicode data", func(t *testing.T) {
		hasher := NewHasher().FromString("你好世界").BySha1()
		assert.Nil(t, hasher.Error)
		assert.Equal(t, 20, len(hasher.dst))
	})

	t.Run("binary data", func(t *testing.T) {
		binaryData := []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f}
		hasher := NewHasher().FromBytes(binaryData).BySha1()
		assert.Nil(t, hasher.Error)
		assert.Equal(t, 20, len(hasher.dst))
	})

	t.Run("empty file", func(t *testing.T) {
		file := mock.NewFile([]byte{}, "empty.txt")
		hasher := NewHasher().FromFile(file).BySha1()
		assert.Nil(t, hasher.Error)
		assert.Equal(t, []byte{}, hasher.dst) // Empty file returns empty slice
	})
}

func TestHasher_BySha1_HMAC(t *testing.T) {
	t.Run("hmac with key", func(t *testing.T) {
		hasher := NewHasher().FromString("hello").WithKey([]byte("secret")).BySha1()
		assert.Nil(t, hasher.Error)
		assert.Equal(t, 20, len(hasher.dst))
	})

	t.Run("hmac with bytes", func(t *testing.T) {
		hasher := NewHasher().FromBytes([]byte("hello")).WithKey([]byte("secret")).BySha1()
		assert.Nil(t, hasher.Error)
		assert.Equal(t, 20, len(hasher.dst))
	})

	t.Run("hmac with file", func(t *testing.T) {
		file := mock.NewFile([]byte("hello"), "test.txt")
		hasher := NewHasher().FromFile(file).WithKey([]byte("secret")).BySha1()
		assert.Nil(t, hasher.Error)
		assert.Equal(t, 20, len(hasher.dst))
	})

	t.Run("hmac with large key", func(t *testing.T) {
		key := make([]byte, 1000)
		for i := range key {
			key[i] = byte(i % 256)
		}
		hasher := NewHasher().FromString("hello").WithKey(key).BySha1()
		assert.Nil(t, hasher.Error)
		assert.Equal(t, 20, len(hasher.dst))
	})
}

func TestHasher_BySha1_Error(t *testing.T) {
	t.Run("file read error", func(t *testing.T) {
		file := mock.NewErrorFile(errors.New("file read error"))
		hasher := NewHasher().FromFile(file).BySha1()
		assert.NotNil(t, hasher.Error)
		assert.Contains(t, hasher.Error.Error(), "file read error")
	})

	t.Run("file read error after partial read", func(t *testing.T) {
		file := mock.NewErrorFile(errors.New("partial read error"))
		hasher := NewHasher().FromFile(file).BySha1()
		assert.NotNil(t, hasher.Error)
		assert.Contains(t, hasher.Error.Error(), "partial read error")
	})

	t.Run("error with key", func(t *testing.T) {
		hasher := NewHasher()
		hasher.Error = errors.New("existing error")
		result := hasher.WithKey([]byte("secret")).BySha1()
		assert.Equal(t, hasher, result)
		assert.Equal(t, errors.New("existing error"), result.Error)
	})

	t.Run("error propagation", func(t *testing.T) {
		hasher := NewHasher()
		hasher.Error = errors.New("test error")
		result := hasher.BySha1()
		assert.Equal(t, hasher, result)
		assert.Equal(t, errors.New("test error"), result.Error)
	})

	t.Run("file with error", func(t *testing.T) {
		file := mock.NewErrorFile(errors.New("read error"))
		hasher := NewHasher().FromFile(file).BySha1()
		assert.NotNil(t, hasher.Error)
		assert.Contains(t, hasher.Error.Error(), "read error")
	})

	t.Run("hmac with empty key", func(t *testing.T) {
		hasher := NewHasher().FromString("hello").WithKey([]byte{}).BySha1()
		assert.NotNil(t, hasher.Error)
		assert.Contains(t, hasher.Error.Error(), "hmac: key cannot be empty")
	})

	t.Run("hmac with nil key", func(t *testing.T) {
		hasher := NewHasher().FromString("hello").WithKey(nil).BySha1()
		assert.NotNil(t, hasher.Error)
		assert.Contains(t, hasher.Error.Error(), "hmac: key cannot be empty")
	})
}
