package hash

import (
	"errors"
	"strings"
	"testing"

	"github.com/dromara/dongle/mock"
	"github.com/stretchr/testify/assert"
)

// Test data for hash-sm3 (generated using Python gmssl library)
var (
	sm3HashSrc       = []byte("hello world")
	sm3HashHexDst    = "44f0061e69fa6fdfc290c494654a05dc0c053da7e5c52b84ef93a9d67d3fff88"
	sm3HashBase64Dst = "RPAGHmn6b9/CkMSUZUoF3AwFPaflxSuE75Op1n0//4g="
)

// Test data for hmac-sm3 (generated using Python gmssl library with custom HMAC-SM3 implementation)
var (
	sm3HmacKey       = []byte("dongle")
	sm3HmacSrc       = []byte("hello world")
	sm3HmacHexDst    = "8c733aae1d553c466a08c3e9e5daac3e99ae220181c7c1bc8c2564961de751b3"
	sm3HmacBase64Dst = "jHM6rh1VPEZqCMPp5dqsPpmuIgGBx8G8jCVklh3nUbM="
)

func TestHasher_BySm3_Hash(t *testing.T) {
	t.Run("hash string", func(t *testing.T) {
		hasher := NewHasher().FromString(string(sm3HashSrc)).BySm3()
		assert.Nil(t, hasher.Error)
		assert.Equal(t, sm3HashHexDst, hasher.ToHexString())

		hasher2 := NewHasher().FromString(string(sm3HashSrc)).BySm3()
		assert.Nil(t, hasher2.Error)
		assert.Equal(t, sm3HashBase64Dst, hasher2.ToBase64String())
	})

	t.Run("hash bytes", func(t *testing.T) {
		hasher := NewHasher().FromBytes(sm3HashSrc).BySm3()
		assert.Nil(t, hasher.Error)
		assert.Equal(t, sm3HashHexDst, hasher.ToHexString())

		hasher2 := NewHasher().FromBytes(sm3HashSrc).BySm3()
		assert.Nil(t, hasher2.Error)
		assert.Equal(t, sm3HashBase64Dst, hasher2.ToBase64String())
	})

	t.Run("hash file", func(t *testing.T) {
		file := mock.NewFile(sm3HashSrc, "test.txt")
		hasher := NewHasher().FromFile(file).BySm3()
		assert.Nil(t, hasher.Error)
		assert.Equal(t, sm3HashHexDst, hasher.ToHexString())

		file2 := mock.NewFile(sm3HashSrc, "test2.txt")
		hasher2 := NewHasher().FromFile(file2).BySm3()
		assert.Nil(t, hasher2.Error)
		assert.Equal(t, sm3HashBase64Dst, hasher2.ToBase64String())
	})

	t.Run("empty string", func(t *testing.T) {
		hasher := NewHasher().FromString("").BySm3()
		assert.Nil(t, hasher.Error)
		assert.Empty(t, hasher.ToHexString())
		assert.Empty(t, hasher.ToBase64String())
	})

	t.Run("empty bytes", func(t *testing.T) {
		hasher := NewHasher().FromBytes([]byte{}).BySm3()
		assert.Nil(t, hasher.Error)
		assert.Empty(t, hasher.ToHexString())
		assert.Empty(t, hasher.ToBase64String())
	})

	t.Run("nil bytes", func(t *testing.T) {
		hasher := NewHasher().FromBytes(nil).BySm3()
		assert.Nil(t, hasher.Error)
		assert.Empty(t, hasher.ToHexString())
		assert.Empty(t, hasher.ToBase64String())
	})

	t.Run("large data", func(t *testing.T) {
		data := strings.Repeat("a", 10000)
		hasher := NewHasher().FromString(data).BySm3()
		assert.Nil(t, hasher.Error)
		// Calculate expected hash for large data using the same method
		expectedHasher := NewHasher().FromString(data).BySm3()
		assert.Nil(t, expectedHasher.Error)
		expectedHex := expectedHasher.ToHexString()
		assert.Equal(t, expectedHex, hasher.ToHexString())
	})

	t.Run("unicode data", func(t *testing.T) {
		unicodeData := "你好世界"
		hasher := NewHasher().FromString(unicodeData).BySm3()
		assert.Nil(t, hasher.Error)
		// Calculate expected hash for unicode data using the same method
		expectedHasher := NewHasher().FromString(unicodeData).BySm3()
		assert.Nil(t, expectedHasher.Error)
		expectedHex := expectedHasher.ToHexString()
		assert.Equal(t, expectedHex, hasher.ToHexString())
	})

	t.Run("binary data", func(t *testing.T) {
		binaryData := []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f}
		hasher := NewHasher().FromBytes(binaryData).BySm3()
		assert.Nil(t, hasher.Error)
		// Calculate expected hash for binary data using the same method
		expectedHasher := NewHasher().FromBytes(binaryData).BySm3()
		assert.Nil(t, expectedHasher.Error)
		expectedHex := expectedHasher.ToHexString()
		assert.Equal(t, expectedHex, hasher.ToHexString())
	})

	t.Run("empty file", func(t *testing.T) {
		file := mock.NewFile([]byte{}, "empty.txt")
		hasher := NewHasher().FromFile(file).BySm3()
		assert.Nil(t, hasher.Error)
		assert.Empty(t, hasher.ToHexString())
		assert.Empty(t, hasher.ToBase64String())
	})

	t.Run("no data no reader no key", func(t *testing.T) {
		hasher := NewHasher().BySm3()
		assert.Nil(t, hasher.Error)
		assert.Empty(t, hasher.ToHexString())
		assert.Empty(t, hasher.ToBase64String())
	})
}

func TestHasher_BySm3_HMAC(t *testing.T) {
	t.Run("hmac string", func(t *testing.T) {
		hasher := NewHasher().FromString(string(sm3HmacSrc)).WithKey(sm3HmacKey).BySm3()
		assert.Nil(t, hasher.Error)
		assert.Equal(t, sm3HmacHexDst, hasher.ToHexString())

		hasher2 := NewHasher().FromString(string(sm3HmacSrc)).WithKey(sm3HmacKey).BySm3()
		assert.Nil(t, hasher2.Error)
		assert.Equal(t, sm3HmacBase64Dst, hasher2.ToBase64String())
	})

	t.Run("hmac bytes", func(t *testing.T) {
		hasher := NewHasher().FromBytes(sm3HmacSrc).WithKey(sm3HmacKey).BySm3()
		assert.Nil(t, hasher.Error)
		assert.Equal(t, sm3HmacHexDst, hasher.ToHexString())

		hasher2 := NewHasher().FromBytes(sm3HmacSrc).WithKey(sm3HmacKey).BySm3()
		assert.Nil(t, hasher2.Error)
		assert.Equal(t, sm3HmacBase64Dst, hasher2.ToBase64String())
	})

	t.Run("hmac file", func(t *testing.T) {
		file := mock.NewFile(sm3HmacSrc, "test.txt")
		hasher := NewHasher().FromFile(file).WithKey(sm3HmacKey).BySm3()
		assert.Nil(t, hasher.Error)
		assert.Equal(t, sm3HmacHexDst, hasher.ToHexString())

		file2 := mock.NewFile(sm3HmacSrc, "test2.txt")
		hasher2 := NewHasher().FromFile(file2).WithKey(sm3HmacKey).BySm3()
		assert.Nil(t, hasher2.Error)
		assert.Equal(t, sm3HmacBase64Dst, hasher2.ToBase64String())
	})

	t.Run("hmac empty string", func(t *testing.T) {
		hasher := NewHasher().FromString("").WithKey(sm3HmacKey).BySm3()
		assert.Nil(t, hasher.Error)
		assert.Empty(t, hasher.ToHexString())
		assert.Empty(t, hasher.ToBase64String())
	})

	t.Run("hmac empty bytes", func(t *testing.T) {
		hasher := NewHasher().FromBytes([]byte{}).WithKey(sm3HmacKey).BySm3()
		assert.Nil(t, hasher.Error)
		assert.Empty(t, hasher.ToHexString())
		assert.Empty(t, hasher.ToBase64String())
	})

	t.Run("hmac large data", func(t *testing.T) {
		data := strings.Repeat("a", 10000)
		hasher := NewHasher().FromString(data).WithKey(sm3HmacKey).BySm3()
		assert.Nil(t, hasher.Error)
		// Calculate expected HMAC for large data using the same method
		expectedHasher := NewHasher().FromString(data).WithKey(sm3HmacKey).BySm3()
		assert.Nil(t, expectedHasher.Error)
		expectedHex := expectedHasher.ToHexString()
		assert.Equal(t, expectedHex, hasher.ToHexString())
	})

	t.Run("hmac unicode data", func(t *testing.T) {
		unicodeData := "你好世界"
		hasher := NewHasher().FromString(unicodeData).WithKey(sm3HmacKey).BySm3()
		assert.Nil(t, hasher.Error)
		// Calculate expected HMAC for unicode data using the same method
		expectedHasher := NewHasher().FromString(unicodeData).WithKey(sm3HmacKey).BySm3()
		assert.Nil(t, expectedHasher.Error)
		expectedHex := expectedHasher.ToHexString()
		assert.Equal(t, expectedHex, hasher.ToHexString())
	})

	t.Run("hmac binary data", func(t *testing.T) {
		binaryData := []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f}
		hasher := NewHasher().FromBytes(binaryData).WithKey(sm3HmacKey).BySm3()
		assert.Nil(t, hasher.Error)
		// Calculate expected HMAC for binary data using the same method
		expectedHasher := NewHasher().FromBytes(binaryData).WithKey(sm3HmacKey).BySm3()
		assert.Nil(t, expectedHasher.Error)
		expectedHex := expectedHasher.ToHexString()
		assert.Equal(t, expectedHex, hasher.ToHexString())
	})

	t.Run("hmac empty file", func(t *testing.T) {
		file := mock.NewFile([]byte{}, "empty.txt")
		hasher := NewHasher().FromFile(file).WithKey(sm3HmacKey).BySm3()
		assert.Nil(t, hasher.Error)
		// Calculate expected HMAC for empty file using the same method
		file2 := mock.NewFile([]byte{}, "empty2.txt")
		expectedHasher := NewHasher().FromFile(file2).WithKey(sm3HmacKey).BySm3()
		assert.Nil(t, expectedHasher.Error)
		expectedHex := expectedHasher.ToHexString()
		assert.Equal(t, expectedHex, hasher.ToHexString())
	})

	t.Run("hmac with large key", func(t *testing.T) {
		key := make([]byte, 1000)
		for i := range key {
			key[i] = byte(i % 256)
		}
		hasher := NewHasher().FromString(string(sm3HmacSrc)).WithKey(key).BySm3()
		assert.Nil(t, hasher.Error)
		// Calculate expected HMAC for large key using the same method
		expectedHasher := NewHasher().FromString(string(sm3HmacSrc)).WithKey(key).BySm3()
		assert.Nil(t, expectedHasher.Error)
		expectedHex := expectedHasher.ToHexString()
		assert.Equal(t, expectedHex, hasher.ToHexString())
	})
}

func TestHasher_BySm3_Error(t *testing.T) {
	t.Run("existing error", func(t *testing.T) {
		hasher := NewHasher()
		hasher.Error = errors.New("existing error")
		result := hasher.BySm3()
		assert.Equal(t, hasher, result)
		assert.Equal(t, errors.New("existing error"), result.Error)
	})
}
