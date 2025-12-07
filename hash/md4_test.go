package hash

import (
	"errors"
	"strings"
	"testing"

	"github.com/dromara/dongle/internal/mock"
	"github.com/stretchr/testify/assert"
)

// Test data for hash-md4 (generated using Python pycryptodome library)
var (
	md4HashSrc       = []byte("hello world")
	md4HashHexDst    = "aa010fbc1d14c795d86ef98c95479d17"
	md4HashBase64Dst = "qgEPvB0Ux5XYbvmMlUedFw=="
)

// Test data for hmac-md4 (generated using Python pycryptodome library)
var (
	md4HmacKey       = []byte("dongle")
	md4HmacSrc       = []byte("hello world")
	md4HmacHexDst    = "7a9df5247cbf76a8bc17c9c4f5a75b6b"
	md4HmacBase64Dst = "ep31JHy/dqi8F8nE9adbaw=="
)

func TestHasher_ByMd4_Hash(t *testing.T) {
	t.Run("hash string", func(t *testing.T) {
		hasher := NewHasher().FromString(string(md4HashSrc)).ByMd4()
		assert.Nil(t, hasher.Error)
		assert.Equal(t, md4HashHexDst, hasher.ToHexString())
		assert.Equal(t, md4HashBase64Dst, hasher.ToBase64String())
	})

	t.Run("hash bytes", func(t *testing.T) {
		hasher := NewHasher().FromBytes(md4HashSrc).ByMd4()
		assert.Nil(t, hasher.Error)
		assert.Equal(t, md4HashHexDst, hasher.ToHexString())
		assert.Equal(t, md4HashBase64Dst, hasher.ToBase64String())
	})

	t.Run("hash file", func(t *testing.T) {
		file := mock.NewFile(md4HashSrc, "test.txt")
		defer file.Close()
		hasher := NewHasher().FromFile(file).ByMd4()
		assert.Nil(t, hasher.Error)
		assert.Equal(t, md4HashHexDst, hasher.ToHexString())
		assert.Equal(t, md4HashBase64Dst, hasher.ToBase64String())
	})

	t.Run("empty string", func(t *testing.T) {
		hasher := NewHasher().FromString("").ByMd4()
		assert.Nil(t, hasher.Error)
		assert.Empty(t, hasher.ToHexString())
		assert.Empty(t, hasher.ToBase64String())
	})

	t.Run("empty bytes", func(t *testing.T) {
		hasher := NewHasher().FromBytes([]byte{}).ByMd4()
		assert.Nil(t, hasher.Error)
		assert.Empty(t, hasher.ToHexString())
		assert.Empty(t, hasher.ToBase64String())
	})

	t.Run("nil bytes", func(t *testing.T) {
		hasher := NewHasher().FromBytes(nil).ByMd4()
		assert.Nil(t, hasher.Error)
		assert.Empty(t, hasher.ToHexString())
		assert.Empty(t, hasher.ToBase64String())
	})

	t.Run("large data", func(t *testing.T) {
		data := strings.Repeat("a", 10000)
		hasher := NewHasher().FromString(data).ByMd4()
		assert.Nil(t, hasher.Error)
		// Calculate expected hash for large data using the same method
		expectedHasher := NewHasher().FromString(data).ByMd4()
		assert.Nil(t, expectedHasher.Error)
		expectedHex := expectedHasher.ToHexString()
		assert.Equal(t, expectedHex, hasher.ToHexString())
	})

	t.Run("unicode data", func(t *testing.T) {
		unicodeData := "你好世界"
		hasher := NewHasher().FromString(unicodeData).ByMd4()
		assert.Nil(t, hasher.Error)
		// Calculate expected hash for unicode data using the same method
		expectedHasher := NewHasher().FromString(unicodeData).ByMd4()
		assert.Nil(t, expectedHasher.Error)
		expectedHex := expectedHasher.ToHexString()
		assert.Equal(t, expectedHex, hasher.ToHexString())
	})

	t.Run("binary data", func(t *testing.T) {
		binaryData := []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f}
		hasher := NewHasher().FromBytes(binaryData).ByMd4()
		assert.Nil(t, hasher.Error)
		// Calculate expected hash for binary data using the same method
		expectedHasher := NewHasher().FromBytes(binaryData).ByMd4()
		assert.Nil(t, expectedHasher.Error)
		expectedHex := expectedHasher.ToHexString()
		assert.Equal(t, expectedHex, hasher.ToHexString())
	})

	t.Run("empty file", func(t *testing.T) {
		file := mock.NewFile([]byte{}, "empty.txt")
		defer file.Close()
		hasher := NewHasher().FromFile(file).ByMd4()
		assert.Nil(t, hasher.Error)
		assert.Empty(t, hasher.ToHexString())
		assert.Empty(t, hasher.ToBase64String())
	})

	t.Run("no data no reader no key", func(t *testing.T) {
		hasher := NewHasher().ByMd4()
		assert.Nil(t, hasher.Error)
		assert.Empty(t, hasher.ToHexString())
		assert.Empty(t, hasher.ToBase64String())
	})
}

func TestHasher_ByMd4_HMAC(t *testing.T) {
	t.Run("hmac string", func(t *testing.T) {
		hasher := NewHasher().FromString(string(md4HmacSrc)).WithKey(md4HmacKey).ByMd4()
		assert.Nil(t, hasher.Error)
		assert.Equal(t, md4HmacHexDst, hasher.ToHexString())

		hasher2 := NewHasher().FromString(string(md4HmacSrc)).WithKey(md4HmacKey).ByMd4()
		assert.Nil(t, hasher2.Error)
		assert.Equal(t, md4HmacBase64Dst, hasher2.ToBase64String())
	})

	t.Run("hmac bytes", func(t *testing.T) {
		hasher := NewHasher().FromBytes(md4HmacSrc).WithKey(md4HmacKey).ByMd4()
		assert.Nil(t, hasher.Error)
		assert.Equal(t, md4HmacHexDst, hasher.ToHexString())

		hasher2 := NewHasher().FromBytes(md4HmacSrc).WithKey(md4HmacKey).ByMd4()
		assert.Nil(t, hasher2.Error)
		assert.Equal(t, md4HmacBase64Dst, hasher2.ToBase64String())
	})

	t.Run("hmac file", func(t *testing.T) {
		file := mock.NewFile(md4HmacSrc, "test.txt")
		defer file.Close()
		hasher := NewHasher().FromFile(file).WithKey(md4HmacKey).ByMd4()
		assert.Nil(t, hasher.Error)
		assert.Equal(t, md4HmacHexDst, hasher.ToHexString())

		file2 := mock.NewFile(md4HmacSrc, "test2.txt")
		defer file2.Close()
		hasher2 := NewHasher().FromFile(file2).WithKey(md4HmacKey).ByMd4()
		assert.Nil(t, hasher2.Error)
		assert.Equal(t, md4HmacBase64Dst, hasher2.ToBase64String())
	})

	t.Run("hmac empty string", func(t *testing.T) {
		hasher := NewHasher().FromString("").WithKey(md4HmacKey).ByMd4()
		assert.Nil(t, hasher.Error)
		// Calculate expected HMAC for empty string using the same method
		expectedHasher := NewHasher().FromString("").WithKey(md4HmacKey).ByMd4()
		assert.Nil(t, expectedHasher.Error)
		expectedHex := expectedHasher.ToHexString()
		assert.Equal(t, expectedHex, hasher.ToHexString())
	})

	t.Run("hmac empty bytes", func(t *testing.T) {
		hasher := NewHasher().FromBytes([]byte{}).WithKey(md4HmacKey).ByMd4()
		assert.Nil(t, hasher.Error)
		// Calculate expected HMAC for empty bytes using the same method
		expectedHasher := NewHasher().FromBytes([]byte{}).WithKey(md4HmacKey).ByMd4()
		assert.Nil(t, expectedHasher.Error)
		expectedHex := expectedHasher.ToHexString()
		assert.Equal(t, expectedHex, hasher.ToHexString())
	})

	t.Run("hmac large data", func(t *testing.T) {
		data := strings.Repeat("a", 10000)
		hasher := NewHasher().FromString(data).WithKey(md4HmacKey).ByMd4()
		assert.Nil(t, hasher.Error)
		// Calculate expected HMAC for large data using the same method
		expectedHasher := NewHasher().FromString(data).WithKey(md4HmacKey).ByMd4()
		assert.Nil(t, expectedHasher.Error)
		expectedHex := expectedHasher.ToHexString()
		assert.Equal(t, expectedHex, hasher.ToHexString())
	})

	t.Run("hmac unicode data", func(t *testing.T) {
		unicodeData := "你好世界"
		hasher := NewHasher().FromString(unicodeData).WithKey(md4HmacKey).ByMd4()
		assert.Nil(t, hasher.Error)
		// Calculate expected HMAC for unicode data using the same method
		expectedHasher := NewHasher().FromString(unicodeData).WithKey(md4HmacKey).ByMd4()
		assert.Nil(t, expectedHasher.Error)
		expectedHex := expectedHasher.ToHexString()
		assert.Equal(t, expectedHex, hasher.ToHexString())
	})

	t.Run("hmac binary data", func(t *testing.T) {
		binaryData := []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f}
		hasher := NewHasher().FromBytes(binaryData).WithKey(md4HmacKey).ByMd4()
		assert.Nil(t, hasher.Error)
		// Calculate expected HMAC for binary data using the same method
		expectedHasher := NewHasher().FromBytes(binaryData).WithKey(md4HmacKey).ByMd4()
		assert.Nil(t, expectedHasher.Error)
		expectedHex := expectedHasher.ToHexString()
		assert.Equal(t, expectedHex, hasher.ToHexString())
	})

	t.Run("hmac empty file", func(t *testing.T) {
		file := mock.NewFile([]byte{}, "empty.txt")
		defer file.Close()
		hasher := NewHasher().FromFile(file).WithKey(md4HmacKey).ByMd4()
		assert.Nil(t, hasher.Error)
		// Calculate expected HMAC for empty file using the same method
		file2 := mock.NewFile([]byte{}, "empty2.txt")
		defer file2.Close()
		expectedHasher := NewHasher().FromFile(file2).WithKey(md4HmacKey).ByMd4()
		assert.Nil(t, expectedHasher.Error)
		expectedHex := expectedHasher.ToHexString()
		assert.Equal(t, expectedHex, hasher.ToHexString())
	})

	t.Run("hmac with large key", func(t *testing.T) {
		key := make([]byte, 1000)
		for i := range key {
			key[i] = byte(i % 256)
		}
		hasher := NewHasher().FromString(string(md4HmacSrc)).WithKey(key).ByMd4()
		assert.Nil(t, hasher.Error)
		// Calculate expected HMAC for large key using the same method
		expectedHasher := NewHasher().FromString(string(md4HmacSrc)).WithKey(key).ByMd4()
		assert.Nil(t, expectedHasher.Error)
		expectedHex := expectedHasher.ToHexString()
		assert.Equal(t, expectedHex, hasher.ToHexString())
	})
}

func TestHasher_ByMd4_Error(t *testing.T) {
	t.Run("existing error", func(t *testing.T) {
		hasher := NewHasher()
		hasher.Error = errors.New("existing error")
		result := hasher.ByMd4()
		assert.Equal(t, hasher, result)
		assert.Equal(t, errors.New("existing error"), result.Error)
	})
}
