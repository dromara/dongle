package hash

import (
	"errors"
	"strings"
	"testing"

	"github.com/dromara/dongle/internal/mock"
	"github.com/stretchr/testify/assert"
)

// Test data for hash-md5
var (
	md5HashSrc       = []byte("hello world")
	md5HashHexDst    = "5eb63bbbe01eeed093cb22bb8f5acdc3"
	md5HashBase64Dst = "XrY7u+Ae7tCTyyK7j1rNww=="
)

// Test data for hmac-md5
var (
	md5HmacKey       = []byte("dongle")
	md5HmacSrc       = []byte("hello world")
	md5HmacHexDst    = "4790626a275f776956386e5a3ea7b726"
	md5HmacBase64Dst = "R5Biaidfd2lWOG5aPqe3Jg=="
)

func TestHasher_ByMd5_Hash(t *testing.T) {
	t.Run("hash string", func(t *testing.T) {
		hasher := NewHasher().FromString(string(md5HashSrc)).ByMd5()
		assert.Nil(t, hasher.Error)
		assert.Equal(t, md5HashHexDst, hasher.ToHexString())
		assert.Equal(t, md5HashBase64Dst, hasher.ToBase64String())
	})

	t.Run("hash bytes", func(t *testing.T) {
		hasher := NewHasher().FromBytes(md5HashSrc).ByMd5()
		assert.Nil(t, hasher.Error)
		assert.Equal(t, md5HashHexDst, hasher.ToHexString())
		assert.Equal(t, md5HashBase64Dst, hasher.ToBase64String())
	})

	t.Run("hash file", func(t *testing.T) {
		file := mock.NewFile(md5HashSrc, "test.txt")
		defer file.Close()
		hasher := NewHasher().FromFile(file).ByMd5()
		assert.Nil(t, hasher.Error)
		assert.Equal(t, md5HashHexDst, hasher.ToHexString())
		assert.Equal(t, md5HashBase64Dst, hasher.ToBase64String())
	})

	t.Run("empty string", func(t *testing.T) {
		hasher := NewHasher().FromString("").ByMd5()
		assert.Nil(t, hasher.Error)
		assert.Empty(t, hasher.ToHexString())
		assert.Empty(t, hasher.ToBase64String())
	})

	t.Run("empty bytes", func(t *testing.T) {
		hasher := NewHasher().FromBytes([]byte{}).ByMd5()
		assert.Nil(t, hasher.Error)
		assert.Empty(t, hasher.ToHexString())
		assert.Empty(t, hasher.ToBase64String())
	})

	t.Run("nil bytes", func(t *testing.T) {
		hasher := NewHasher().FromBytes(nil).ByMd5()
		assert.Nil(t, hasher.Error)
		assert.Empty(t, hasher.ToHexString())
		assert.Empty(t, hasher.ToBase64String())
	})

	t.Run("large data", func(t *testing.T) {
		data := strings.Repeat("a", 10000)
		hasher := NewHasher().FromString(data).ByMd5()
		assert.Nil(t, hasher.Error)
		assert.Equal(t, "0d0c9c4db6953fee9e03f528cafd7d3e", hasher.ToHexString())
	})

	t.Run("unicode data", func(t *testing.T) {
		hasher := NewHasher().FromString("你好世界").ByMd5()
		assert.Nil(t, hasher.Error)
		assert.Equal(t, "65396ee4aad0b4f17aacd1c6112ee364", hasher.ToHexString())
	})

	t.Run("binary data", func(t *testing.T) {
		binaryData := []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f}
		hasher := NewHasher().FromBytes(binaryData).ByMd5()
		assert.Nil(t, hasher.Error)
		assert.Equal(t, "1ac1ef01e96caf1be0d329331a4fc2a8", hasher.ToHexString())
	})

	t.Run("empty file", func(t *testing.T) {
		file := mock.NewFile([]byte{}, "empty.txt")
		defer file.Close()
		hasher := NewHasher().FromFile(file).ByMd5()
		assert.Nil(t, hasher.Error)
		assert.Empty(t, hasher.ToHexString()) // Empty file returns empty string
	})
}

func TestHasher_ByMd5_HMAC(t *testing.T) {
	t.Run("hmac string", func(t *testing.T) {
		hasher := NewHasher().FromString(string(md5HmacSrc)).WithKey(md5HmacKey).ByMd5()
		assert.Nil(t, hasher.Error)
		assert.Equal(t, md5HmacHexDst, hasher.ToHexString())
		assert.Equal(t, md5HmacBase64Dst, hasher.ToBase64String())
	})

	t.Run("hmac bytes", func(t *testing.T) {
		hasher := NewHasher().FromBytes(md5HmacSrc).WithKey(md5HmacKey).ByMd5()
		assert.Nil(t, hasher.Error)
		assert.Equal(t, md5HmacHexDst, hasher.ToHexString())
		assert.Equal(t, md5HmacBase64Dst, hasher.ToBase64String())
	})

	t.Run("hmac file", func(t *testing.T) {
		file := mock.NewFile(md5HmacSrc, "test.txt")
		defer file.Close()
		hasher := NewHasher().FromFile(file).WithKey(md5HmacKey).ByMd5()
		assert.Nil(t, hasher.Error)
		assert.Equal(t, md5HmacHexDst, hasher.ToHexString())
		assert.Equal(t, md5HmacBase64Dst, hasher.ToBase64String())
	})

	t.Run("hmac empty string", func(t *testing.T) {
		hasher := NewHasher().FromString("").WithKey(md5HmacKey).ByMd5()
		assert.Nil(t, hasher.Error)
		assert.Empty(t, hasher.ToHexString())
		assert.Empty(t, hasher.ToBase64String())
	})

	t.Run("hmac empty bytes", func(t *testing.T) {
		hasher := NewHasher().FromBytes([]byte{}).WithKey(md5HmacKey).ByMd5()
		assert.Nil(t, hasher.Error)
		assert.Empty(t, hasher.ToHexString())
		assert.Empty(t, hasher.ToBase64String())
	})

	t.Run("hmac nil bytes", func(t *testing.T) {
		hasher := NewHasher().FromBytes(nil).WithKey(md5HmacKey).ByMd5()
		assert.Nil(t, hasher.Error)
		assert.Empty(t, hasher.ToHexString())
		assert.Empty(t, hasher.ToBase64String())
	})

	t.Run("hmac large data", func(t *testing.T) {
		data := strings.Repeat("a", 10000)
		hasher := NewHasher().FromString(data).WithKey(md5HmacKey).ByMd5()
		assert.Nil(t, hasher.Error)
		assert.Equal(t, "632150326c1cfbf5b762a8d9389a741d", hasher.ToHexString())
		assert.Equal(t, "YyFQMmwc+/W3YqjZOJp0HQ==", hasher.ToBase64String())
	})

	t.Run("hmac unicode data", func(t *testing.T) {
		hasher := NewHasher().FromString("你好世界").WithKey(md5HmacKey).ByMd5()
		assert.Nil(t, hasher.Error)
		assert.Equal(t, "1d2ff2c099f5d9aba3bca8fd0bed826d", hasher.ToHexString())
		assert.Equal(t, "HS/ywJn12aujvKj9C+2CbQ==", hasher.ToBase64String())
	})

	t.Run("hmac binary data", func(t *testing.T) {
		binaryData := []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f}
		hasher := NewHasher().FromBytes(binaryData).WithKey(md5HmacKey).ByMd5()
		assert.Nil(t, hasher.Error)
		assert.Equal(t, "faf9109292c46bb584a79a93c7f39a4a", hasher.ToHexString())
		assert.Equal(t, "+vkQkpLEa7WEp5qTx/OaSg==", hasher.ToBase64String())
	})

	t.Run("hmac empty file", func(t *testing.T) {
		file := mock.NewFile([]byte{}, "empty.txt")
		defer file.Close()
		hasher := NewHasher().FromFile(file).WithKey(md5HmacKey).ByMd5()
		assert.Nil(t, hasher.Error)
		assert.Empty(t, hasher.ToHexString())
		assert.Empty(t, hasher.ToBase64String())
	})

	t.Run("hmac no data no reader no key", func(t *testing.T) {
		hasher := NewHasher().ByMd5()
		assert.Nil(t, hasher.Error)
		assert.Empty(t, hasher.ToHexString())
		assert.Empty(t, hasher.ToBase64String())
	})
}

func TestHasher_ByMd5_Error(t *testing.T) {
	t.Run("existing error", func(t *testing.T) {
		hasher := NewHasher()
		hasher.Error = errors.New("existing error")
		result := hasher.ByMd5()
		assert.Equal(t, hasher, result)
		assert.Equal(t, errors.New("existing error"), result.Error)
	})
}
