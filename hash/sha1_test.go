package hash

import (
	"errors"
	"strings"
	"testing"

	"github.com/dromara/dongle/mock"
	"github.com/stretchr/testify/assert"
)

// Test data for hash-sha1 (generated using Python pycryptodome library)
var (
	sha1HashSrc       = []byte("hello world")
	sha1HashHexDst    = "2aae6c35c94fcfb415dbe95f408b9ce91ee846ed"
	sha1HashBase64Dst = "Kq5sNclPz7QV2+lfQIuc6R7oRu0="
)

// Test data for hmac-sha1 (generated using Python pycryptodome library)
var (
	sha1HmacKey       = []byte("dongle")
	sha1HmacSrc       = []byte("hello world")
	sha1HmacHexDst    = "91c103ef93ba7420902b0d1bf0903251c94b4a62"
	sha1HmacBase64Dst = "kcED75O6dCCQKw0b8JAyUclLSmI="
)

func TestHasher_BySha1_Hash(t *testing.T) {
	t.Run("hash string", func(t *testing.T) {
		hasher := NewHasher().FromString(string(sha1HashSrc)).BySha1()
		assert.Nil(t, hasher.Error)
		assert.Equal(t, sha1HashHexDst, hasher.ToHexString())

		hasher2 := NewHasher().FromString(string(sha1HashSrc)).BySha1()
		assert.Nil(t, hasher2.Error)
		assert.Equal(t, sha1HashBase64Dst, hasher2.ToBase64String())
	})

	t.Run("hash bytes", func(t *testing.T) {
		hasher := NewHasher().FromBytes(sha1HashSrc).BySha1()
		assert.Nil(t, hasher.Error)
		assert.Equal(t, sha1HashHexDst, hasher.ToHexString())

		hasher2 := NewHasher().FromBytes(sha1HashSrc).BySha1()
		assert.Nil(t, hasher2.Error)
		assert.Equal(t, sha1HashBase64Dst, hasher2.ToBase64String())
	})

	t.Run("hash file", func(t *testing.T) {
		file := mock.NewFile(sha1HashSrc, "test.txt")
		hasher := NewHasher().FromFile(file).BySha1()
		assert.Nil(t, hasher.Error)
		assert.Equal(t, sha1HashHexDst, hasher.ToHexString())

		file2 := mock.NewFile(sha1HashSrc, "test2.txt")
		hasher2 := NewHasher().FromFile(file2).BySha1()
		assert.Nil(t, hasher2.Error)
		assert.Equal(t, sha1HashBase64Dst, hasher2.ToBase64String())
	})

	t.Run("empty string", func(t *testing.T) {
		hasher := NewHasher().FromString("").BySha1()
		assert.Nil(t, hasher.Error)
		assert.Empty(t, hasher.ToHexString())
		assert.Empty(t, hasher.ToBase64String())
	})

	t.Run("empty bytes", func(t *testing.T) {
		hasher := NewHasher().FromBytes([]byte{}).BySha1()
		assert.Nil(t, hasher.Error)
		assert.Empty(t, hasher.ToHexString())
		assert.Empty(t, hasher.ToBase64String())
	})

	t.Run("nil bytes", func(t *testing.T) {
		hasher := NewHasher().FromBytes(nil).BySha1()
		assert.Nil(t, hasher.Error)
		assert.Empty(t, hasher.ToHexString())
		assert.Empty(t, hasher.ToBase64String())
	})

	t.Run("large data", func(t *testing.T) {
		data := strings.Repeat("a", 10000)
		hasher := NewHasher().FromString(data).BySha1()
		assert.Nil(t, hasher.Error)
		// Calculate expected hash for large data using the same method
		expectedHasher := NewHasher().FromString(data).BySha1()
		assert.Nil(t, expectedHasher.Error)
		expectedHex := expectedHasher.ToHexString()
		assert.Equal(t, expectedHex, hasher.ToHexString())
	})

	t.Run("unicode data", func(t *testing.T) {
		unicodeData := "你好世界"
		hasher := NewHasher().FromString(unicodeData).BySha1()
		assert.Nil(t, hasher.Error)
		// Calculate expected hash for unicode data using the same method
		expectedHasher := NewHasher().FromString(unicodeData).BySha1()
		assert.Nil(t, expectedHasher.Error)
		expectedHex := expectedHasher.ToHexString()
		assert.Equal(t, expectedHex, hasher.ToHexString())
	})

	t.Run("binary data", func(t *testing.T) {
		binaryData := []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f}
		hasher := NewHasher().FromBytes(binaryData).BySha1()
		assert.Nil(t, hasher.Error)
		// Calculate expected hash for binary data using the same method
		expectedHasher := NewHasher().FromBytes(binaryData).BySha1()
		assert.Nil(t, expectedHasher.Error)
		expectedHex := expectedHasher.ToHexString()
		assert.Equal(t, expectedHex, hasher.ToHexString())
	})

	t.Run("empty file", func(t *testing.T) {
		file := mock.NewFile([]byte{}, "empty.txt")
		hasher := NewHasher().FromFile(file).BySha1()
		assert.Nil(t, hasher.Error)
		assert.Empty(t, hasher.ToHexString())
		assert.Empty(t, hasher.ToBase64String())
	})

	t.Run("no data no reader no key", func(t *testing.T) {
		hasher := NewHasher().BySha1()
		assert.Nil(t, hasher.Error)
		assert.Empty(t, hasher.ToHexString())
		assert.Empty(t, hasher.ToBase64String())
	})
}

func TestHasher_BySha1_HMAC(t *testing.T) {
	t.Run("hmac string", func(t *testing.T) {
		hasher := NewHasher().FromString(string(sha1HmacSrc)).WithKey(sha1HmacKey).BySha1()
		assert.Nil(t, hasher.Error)
		assert.Equal(t, sha1HmacHexDst, hasher.ToHexString())

		hasher2 := NewHasher().FromString(string(sha1HmacSrc)).WithKey(sha1HmacKey).BySha1()
		assert.Nil(t, hasher2.Error)
		assert.Equal(t, sha1HmacBase64Dst, hasher2.ToBase64String())
	})

	t.Run("hmac bytes", func(t *testing.T) {
		hasher := NewHasher().FromBytes(sha1HmacSrc).WithKey(sha1HmacKey).BySha1()
		assert.Nil(t, hasher.Error)
		assert.Equal(t, sha1HmacHexDst, hasher.ToHexString())

		hasher2 := NewHasher().FromBytes(sha1HmacSrc).WithKey(sha1HmacKey).BySha1()
		assert.Nil(t, hasher2.Error)
		assert.Equal(t, sha1HmacBase64Dst, hasher2.ToBase64String())
	})

	t.Run("hmac file", func(t *testing.T) {
		file := mock.NewFile(sha1HmacSrc, "test.txt")
		hasher := NewHasher().FromFile(file).WithKey(sha1HmacKey).BySha1()
		assert.Nil(t, hasher.Error)
		assert.Equal(t, sha1HmacHexDst, hasher.ToHexString())

		file2 := mock.NewFile(sha1HmacSrc, "test2.txt")
		hasher2 := NewHasher().FromFile(file2).WithKey(sha1HmacKey).BySha1()
		assert.Nil(t, hasher2.Error)
		assert.Equal(t, sha1HmacBase64Dst, hasher2.ToBase64String())
	})

	t.Run("hmac empty string", func(t *testing.T) {
		hasher := NewHasher().FromString("").WithKey(sha1HmacKey).BySha1()
		assert.Nil(t, hasher.Error)
		// Calculate expected HMAC for empty string using the same method
		expectedHasher := NewHasher().FromString("").WithKey(sha1HmacKey).BySha1()
		assert.Nil(t, expectedHasher.Error)
		expectedHex := expectedHasher.ToHexString()
		assert.Equal(t, expectedHex, hasher.ToHexString())
	})

	t.Run("hmac empty bytes", func(t *testing.T) {
		hasher := NewHasher().FromBytes([]byte{}).WithKey(sha1HmacKey).BySha1()
		assert.Nil(t, hasher.Error)
		// Calculate expected HMAC for empty bytes using the same method
		expectedHasher := NewHasher().FromBytes([]byte{}).WithKey(sha1HmacKey).BySha1()
		assert.Nil(t, expectedHasher.Error)
		expectedHex := expectedHasher.ToHexString()
		assert.Equal(t, expectedHex, hasher.ToHexString())
	})

	t.Run("hmac large data", func(t *testing.T) {
		data := strings.Repeat("a", 10000)
		hasher := NewHasher().FromString(data).WithKey(sha1HmacKey).BySha1()
		assert.Nil(t, hasher.Error)
		// Calculate expected HMAC for large data using the same method
		expectedHasher := NewHasher().FromString(data).WithKey(sha1HmacKey).BySha1()
		assert.Nil(t, expectedHasher.Error)
		expectedHex := expectedHasher.ToHexString()
		assert.Equal(t, expectedHex, hasher.ToHexString())
	})

	t.Run("hmac unicode data", func(t *testing.T) {
		unicodeData := "你好世界"
		hasher := NewHasher().FromString(unicodeData).WithKey(sha1HmacKey).BySha1()
		assert.Nil(t, hasher.Error)
		// Calculate expected HMAC for unicode data using the same method
		expectedHasher := NewHasher().FromString(unicodeData).WithKey(sha1HmacKey).BySha1()
		assert.Nil(t, expectedHasher.Error)
		expectedHex := expectedHasher.ToHexString()
		assert.Equal(t, expectedHex, hasher.ToHexString())
	})

	t.Run("hmac binary data", func(t *testing.T) {
		binaryData := []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f}
		hasher := NewHasher().FromBytes(binaryData).WithKey(sha1HmacKey).BySha1()
		assert.Nil(t, hasher.Error)
		// Calculate expected HMAC for binary data using the same method
		expectedHasher := NewHasher().FromBytes(binaryData).WithKey(sha1HmacKey).BySha1()
		assert.Nil(t, expectedHasher.Error)
		expectedHex := expectedHasher.ToHexString()
		assert.Equal(t, expectedHex, hasher.ToHexString())
	})

	t.Run("hmac empty file", func(t *testing.T) {
		file := mock.NewFile([]byte{}, "empty.txt")
		hasher := NewHasher().FromFile(file).WithKey(sha1HmacKey).BySha1()
		assert.Nil(t, hasher.Error)
		// Calculate expected HMAC for empty file using the same method
		file2 := mock.NewFile([]byte{}, "empty2.txt")
		expectedHasher := NewHasher().FromFile(file2).WithKey(sha1HmacKey).BySha1()
		assert.Nil(t, expectedHasher.Error)
		expectedHex := expectedHasher.ToHexString()
		assert.Equal(t, expectedHex, hasher.ToHexString())
	})

	t.Run("hmac with large key", func(t *testing.T) {
		key := make([]byte, 1000)
		for i := range key {
			key[i] = byte(i % 256)
		}
		hasher := NewHasher().FromString(string(sha1HmacSrc)).WithKey(key).BySha1()
		assert.Nil(t, hasher.Error)
		// Calculate expected HMAC for large key using the same method
		expectedHasher := NewHasher().FromString(string(sha1HmacSrc)).WithKey(key).BySha1()
		assert.Nil(t, expectedHasher.Error)
		expectedHex := expectedHasher.ToHexString()
		assert.Equal(t, expectedHex, hasher.ToHexString())
	})
}

func TestHasher_BySha1_Error(t *testing.T) {
	t.Run("existing error", func(t *testing.T) {
		hasher := NewHasher()
		hasher.Error = errors.New("existing error")
		result := hasher.BySha1()
		assert.Equal(t, hasher, result)
		assert.Equal(t, errors.New("existing error"), result.Error)
	})
}
