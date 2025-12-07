package hash

import (
	"errors"
	"strings"
	"testing"

	"github.com/dromara/dongle/internal/mock"
	"github.com/stretchr/testify/assert"
)

// Test data for hash-ripemd160 (generated using Python pycryptodome library)
var (
	ripemd160HashSrc       = []byte("hello world")
	ripemd160HashHexDst    = "98c615784ccb5fe5936fbc0cbe9dfdb408d92f0f"
	ripemd160HashBase64Dst = "mMYVeEzLX+WTb7wMvp39tAjZLw8="
)

// Test data for hmac-ripemd160 (generated using Python pycryptodome library)
var (
	ripemd160HmacKey       = []byte("dongle")
	ripemd160HmacSrc       = []byte("hello world")
	ripemd160HmacHexDst    = "3691ad040e80c43dc6e8ffe9bc6ef3d5bd8786b8"
	ripemd160HmacBase64Dst = "NpGtBA6AxD3G6P/pvG7z1b2Hhrg="
)

func TestHasher_ByRipemd160_Hash(t *testing.T) {
	t.Run("hash string", func(t *testing.T) {
		hasher := NewHasher().FromString(string(ripemd160HashSrc)).ByRipemd160()
		assert.Nil(t, hasher.Error)
		assert.Equal(t, ripemd160HashHexDst, hasher.ToHexString())
		assert.Equal(t, ripemd160HashBase64Dst, hasher.ToBase64String())
	})

	t.Run("hash bytes", func(t *testing.T) {
		hasher := NewHasher().FromBytes(ripemd160HashSrc).ByRipemd160()
		assert.Nil(t, hasher.Error)
		assert.Equal(t, ripemd160HashHexDst, hasher.ToHexString())
		assert.Equal(t, ripemd160HashBase64Dst, hasher.ToBase64String())
	})

	t.Run("hash file", func(t *testing.T) {
		file := mock.NewFile(ripemd160HashSrc, "test.txt")
		defer file.Close()
		hasher := NewHasher().FromFile(file).ByRipemd160()
		assert.Nil(t, hasher.Error)
		assert.Equal(t, ripemd160HashHexDst, hasher.ToHexString())
		assert.Equal(t, ripemd160HashBase64Dst, hasher.ToBase64String())
	})

	t.Run("empty string", func(t *testing.T) {
		hasher := NewHasher().FromString("").ByRipemd160()
		assert.Nil(t, hasher.Error)
		assert.Empty(t, hasher.ToHexString())
		assert.Empty(t, hasher.ToBase64String())
	})

	t.Run("empty bytes", func(t *testing.T) {
		hasher := NewHasher().FromBytes([]byte{}).ByRipemd160()
		assert.Nil(t, hasher.Error)
		assert.Empty(t, hasher.ToHexString())
		assert.Empty(t, hasher.ToBase64String())
	})

	t.Run("nil bytes", func(t *testing.T) {
		hasher := NewHasher().FromBytes(nil).ByRipemd160()
		assert.Nil(t, hasher.Error)
		assert.Empty(t, hasher.ToHexString())
		assert.Empty(t, hasher.ToBase64String())
	})

	t.Run("large data", func(t *testing.T) {
		data := strings.Repeat("a", 10000)
		hasher := NewHasher().FromString(data).ByRipemd160()
		assert.Nil(t, hasher.Error)
		assert.NotEmpty(t, hasher.ToHexString())
	})

	t.Run("unicode data", func(t *testing.T) {
		unicodeData := "你好世界"
		hasher := NewHasher().FromString(unicodeData).ByRipemd160()
		assert.Nil(t, hasher.Error)
		assert.NotEmpty(t, hasher.ToHexString())
	})

	t.Run("binary data", func(t *testing.T) {
		binaryData := []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f}
		hasher := NewHasher().FromBytes(binaryData).ByRipemd160()
		assert.Nil(t, hasher.Error)
		assert.NotEmpty(t, hasher.ToHexString())
	})

	t.Run("empty file", func(t *testing.T) {
		file := mock.NewFile([]byte{}, "empty.txt")
		defer file.Close()
		hasher := NewHasher().FromFile(file).ByRipemd160()
		assert.Nil(t, hasher.Error)
		assert.Empty(t, hasher.ToHexString())
		assert.Empty(t, hasher.ToBase64String())
	})

	t.Run("no data no reader no key", func(t *testing.T) {
		hasher := NewHasher().ByRipemd160()
		assert.Nil(t, hasher.Error)
		assert.Empty(t, hasher.ToHexString())
		assert.Empty(t, hasher.ToBase64String())
	})
}

func TestHasher_ByRipemd160_HMAC(t *testing.T) {
	t.Run("hmac string", func(t *testing.T) {
		hasher := NewHasher().FromString(string(ripemd160HmacSrc)).WithKey(ripemd160HmacKey).ByRipemd160()
		assert.Nil(t, hasher.Error)
		assert.Equal(t, ripemd160HmacHexDst, hasher.ToHexString())
		assert.Equal(t, ripemd160HmacBase64Dst, hasher.ToBase64String())
	})

	t.Run("hmac bytes", func(t *testing.T) {
		hasher := NewHasher().FromBytes(ripemd160HmacSrc).WithKey(ripemd160HmacKey).ByRipemd160()
		assert.Nil(t, hasher.Error)
		assert.Equal(t, ripemd160HmacHexDst, hasher.ToHexString())
		assert.Equal(t, ripemd160HmacBase64Dst, hasher.ToBase64String())
	})

	t.Run("hmac file", func(t *testing.T) {
		file := mock.NewFile(ripemd160HmacSrc, "test.txt")
		defer file.Close()
		hasher := NewHasher().FromFile(file).WithKey(ripemd160HmacKey).ByRipemd160()
		assert.Nil(t, hasher.Error)
		assert.Equal(t, ripemd160HmacHexDst, hasher.ToHexString())
		assert.Equal(t, ripemd160HmacBase64Dst, hasher.ToBase64String())
	})

	t.Run("hmac empty string", func(t *testing.T) {
		hasher := NewHasher().FromString("").WithKey(ripemd160HmacKey).ByRipemd160()
		assert.Nil(t, hasher.Error)
		assert.Empty(t, hasher.ToHexString())
		assert.Empty(t, hasher.ToBase64String())
	})

	t.Run("hmac empty bytes", func(t *testing.T) {
		hasher := NewHasher().FromBytes([]byte{}).WithKey(ripemd160HmacKey).ByRipemd160()
		assert.Nil(t, hasher.Error)
		assert.Empty(t, hasher.ToHexString())
		assert.Empty(t, hasher.ToBase64String())
	})

	t.Run("hmac large data", func(t *testing.T) {
		data := strings.Repeat("a", 10000)
		hasher := NewHasher().FromString(data).WithKey(ripemd160HmacKey).ByRipemd160()
		assert.Nil(t, hasher.Error)
		assert.NotEmpty(t, hasher.ToHexString())
	})

	t.Run("hmac unicode data", func(t *testing.T) {
		unicodeData := "你好世界"
		hasher := NewHasher().FromString(unicodeData).WithKey(ripemd160HmacKey).ByRipemd160()
		assert.Nil(t, hasher.Error)
		assert.NotEmpty(t, hasher.ToHexString())
	})

	t.Run("hmac binary data", func(t *testing.T) {
		binaryData := []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f}
		hasher := NewHasher().FromBytes(binaryData).WithKey(ripemd160HmacKey).ByRipemd160()
		assert.Nil(t, hasher.Error)
		assert.NotEmpty(t, hasher.ToHexString())
	})

	t.Run("hmac empty file", func(t *testing.T) {
		file := mock.NewFile([]byte{}, "empty.txt")
		defer file.Close()
		hasher := NewHasher().FromFile(file).WithKey(ripemd160HmacKey).ByRipemd160()
		assert.Nil(t, hasher.Error)
		assert.Empty(t, hasher.ToHexString())
	})

	t.Run("hmac with large key", func(t *testing.T) {
		key := make([]byte, 1000)
		for i := range key {
			key[i] = byte(i % 256)
		}
		hasher := NewHasher().FromString(string(ripemd160HmacSrc)).WithKey(key).ByRipemd160()
		assert.Nil(t, hasher.Error)
		assert.NotEmpty(t, hasher.ToHexString())
	})
}

func TestHasher_ByRipemd160_Error(t *testing.T) {
	t.Run("existing error", func(t *testing.T) {
		hasher := NewHasher()
		hasher.Error = errors.New("existing error")
		result := hasher.ByRipemd160()
		assert.Equal(t, hasher, result)
		assert.Equal(t, errors.New("existing error"), result.Error)
	})
}
