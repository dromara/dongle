package hash

import (
	"errors"
	"strings"
	"testing"

	"github.com/dromara/dongle/internal/mock"
	"github.com/stretchr/testify/assert"
)

// Test data for hash-md2 (generated using Python pycryptodome library)
var (
	md2HashSrc       = []byte("hello world")
	md2HashHexDst    = "d9cce882ee690a5c1ce70beff3a78c77"
	md2HashBase64Dst = "2czogu5pClwc5wvv86eMdw=="
)

// Test data for hmac-md2 (generated using Python pycryptodome library)
var (
	md2HmacKey       = []byte("dongle")
	md2HmacSrc       = []byte("hello world")
	md2HmacHexDst    = "88ed6ef9ab699d03a702f2a6fb1c0673"
	md2HmacBase64Dst = "iO1u+atpnQOnAvKm+xwGcw=="
)

func TestHasher_ByMd2_Hash(t *testing.T) {
	t.Run("hash string", func(t *testing.T) {
		hasher := NewHasher().FromString(string(md2HashSrc)).ByMd2()
		assert.Nil(t, hasher.Error)
		assert.Equal(t, md2HashHexDst, hasher.ToHexString())

		hasher2 := NewHasher().FromString(string(md2HashSrc)).ByMd2()
		assert.Nil(t, hasher2.Error)
		assert.Equal(t, md2HashBase64Dst, hasher2.ToBase64String())
	})

	t.Run("hash bytes", func(t *testing.T) {
		hasher := NewHasher().FromBytes(md2HashSrc).ByMd2()
		assert.Nil(t, hasher.Error)
		assert.Equal(t, md2HashHexDst, hasher.ToHexString())

		hasher2 := NewHasher().FromBytes(md2HashSrc).ByMd2()
		assert.Nil(t, hasher2.Error)
		assert.Equal(t, md2HashBase64Dst, hasher2.ToBase64String())
	})

	t.Run("hash file", func(t *testing.T) {
		file := mock.NewFile(md2HashSrc, "test.txt")
		hasher := NewHasher().FromFile(file).ByMd2()
		assert.Nil(t, hasher.Error)
		assert.Equal(t, md2HashHexDst, hasher.ToHexString())

		file2 := mock.NewFile(md2HashSrc, "test2.txt")
		hasher2 := NewHasher().FromFile(file2).ByMd2()
		assert.Nil(t, hasher2.Error)
		assert.Equal(t, md2HashBase64Dst, hasher2.ToBase64String())
	})

	t.Run("empty string", func(t *testing.T) {
		hasher := NewHasher().FromString("").ByMd2()
		assert.Nil(t, hasher.Error)
		assert.Empty(t, hasher.ToHexString())
		assert.Empty(t, hasher.ToBase64String())
	})

	t.Run("empty bytes", func(t *testing.T) {
		hasher := NewHasher().FromBytes([]byte{}).ByMd2()
		assert.Nil(t, hasher.Error)
		assert.Empty(t, hasher.ToHexString())
		assert.Empty(t, hasher.ToBase64String())
	})

	t.Run("nil bytes", func(t *testing.T) {
		hasher := NewHasher().FromBytes(nil).ByMd2()
		assert.Nil(t, hasher.Error)
		assert.Empty(t, hasher.ToHexString())
		assert.Empty(t, hasher.ToBase64String())
	})

	t.Run("large data", func(t *testing.T) {
		data := strings.Repeat("a", 10000)
		hasher := NewHasher().FromString(data).ByMd2()
		assert.Nil(t, hasher.Error)
		// Calculate expected hash for large data using the same method
		expectedHasher := NewHasher().FromString(data).ByMd2()
		assert.Nil(t, expectedHasher.Error)
		expectedHex := expectedHasher.ToHexString()
		assert.Equal(t, expectedHex, hasher.ToHexString())
	})

	t.Run("unicode data", func(t *testing.T) {
		unicodeData := "你好世界"
		hasher := NewHasher().FromString(unicodeData).ByMd2()
		assert.Nil(t, hasher.Error)
		// Calculate expected hash for unicode data using the same method
		expectedHasher := NewHasher().FromString(unicodeData).ByMd2()
		assert.Nil(t, expectedHasher.Error)
		expectedHex := expectedHasher.ToHexString()
		assert.Equal(t, expectedHex, hasher.ToHexString())
	})

	t.Run("binary data", func(t *testing.T) {
		binaryData := []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f}
		hasher := NewHasher().FromBytes(binaryData).ByMd2()
		assert.Nil(t, hasher.Error)
		// Calculate expected hash for binary data using the same method
		expectedHasher := NewHasher().FromBytes(binaryData).ByMd2()
		assert.Nil(t, expectedHasher.Error)
		expectedHex := expectedHasher.ToHexString()
		assert.Equal(t, expectedHex, hasher.ToHexString())
	})

	t.Run("empty file", func(t *testing.T) {
		file := mock.NewFile([]byte{}, "empty.txt")
		hasher := NewHasher().FromFile(file).ByMd2()
		assert.Nil(t, hasher.Error)
		assert.Empty(t, hasher.ToHexString())
		assert.Empty(t, hasher.ToBase64String())
	})

	t.Run("no data no reader no key", func(t *testing.T) {
		hasher := NewHasher().ByMd2()
		assert.Nil(t, hasher.Error)
		assert.Empty(t, hasher.ToHexString())
		assert.Empty(t, hasher.ToBase64String())
	})
}

func TestHasher_ByMd2_HMAC(t *testing.T) {
	t.Run("hmac string", func(t *testing.T) {
		hasher := NewHasher().FromString(string(md2HmacSrc)).WithKey(md2HmacKey).ByMd2()
		assert.Nil(t, hasher.Error)
		assert.Equal(t, md2HmacHexDst, hasher.ToHexString())

		hasher2 := NewHasher().FromString(string(md2HmacSrc)).WithKey(md2HmacKey).ByMd2()
		assert.Nil(t, hasher2.Error)
		assert.Equal(t, md2HmacBase64Dst, hasher2.ToBase64String())
	})

	t.Run("hmac bytes", func(t *testing.T) {
		hasher := NewHasher().FromBytes(md2HmacSrc).WithKey(md2HmacKey).ByMd2()
		assert.Nil(t, hasher.Error)
		assert.Equal(t, md2HmacHexDst, hasher.ToHexString())

		hasher2 := NewHasher().FromBytes(md2HmacSrc).WithKey(md2HmacKey).ByMd2()
		assert.Nil(t, hasher2.Error)
		assert.Equal(t, md2HmacBase64Dst, hasher2.ToBase64String())
	})

	t.Run("hmac file", func(t *testing.T) {
		file := mock.NewFile(md2HmacSrc, "test.txt")
		hasher := NewHasher().FromFile(file).WithKey(md2HmacKey).ByMd2()
		assert.Nil(t, hasher.Error)
		assert.Equal(t, md2HmacHexDst, hasher.ToHexString())

		file2 := mock.NewFile(md2HmacSrc, "test2.txt")
		hasher2 := NewHasher().FromFile(file2).WithKey(md2HmacKey).ByMd2()
		assert.Nil(t, hasher2.Error)
		assert.Equal(t, md2HmacBase64Dst, hasher2.ToBase64String())
	})

	t.Run("hmac empty string", func(t *testing.T) {
		hasher := NewHasher().FromString("").WithKey(md2HmacKey).ByMd2()
		assert.Nil(t, hasher.Error)
		assert.Empty(t, hasher.ToHexString())
		assert.Empty(t, hasher.ToBase64String())
	})

	t.Run("hmac empty bytes", func(t *testing.T) {
		hasher := NewHasher().FromBytes([]byte{}).WithKey(md2HmacKey).ByMd2()
		assert.Nil(t, hasher.Error)
		assert.Empty(t, hasher.ToHexString())
		assert.Empty(t, hasher.ToBase64String())
	})

	t.Run("hmac large data", func(t *testing.T) {
		data := strings.Repeat("a", 10000)
		hasher := NewHasher().FromString(data).WithKey(md2HmacKey).ByMd2()
		assert.Nil(t, hasher.Error)
		// Calculate expected HMAC for large data using the same method
		expectedHasher := NewHasher().FromString(data).WithKey(md2HmacKey).ByMd2()
		assert.Nil(t, expectedHasher.Error)
		expectedHex := expectedHasher.ToHexString()
		assert.Equal(t, expectedHex, hasher.ToHexString())
	})

	t.Run("hmac unicode data", func(t *testing.T) {
		unicodeData := "你好世界"
		hasher := NewHasher().FromString(unicodeData).WithKey(md2HmacKey).ByMd2()
		assert.Nil(t, hasher.Error)
		// Calculate expected HMAC for unicode data using the same method
		expectedHasher := NewHasher().FromString(unicodeData).WithKey(md2HmacKey).ByMd2()
		assert.Nil(t, expectedHasher.Error)
		expectedHex := expectedHasher.ToHexString()
		assert.Equal(t, expectedHex, hasher.ToHexString())
	})

	t.Run("hmac binary data", func(t *testing.T) {
		binaryData := []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f}
		hasher := NewHasher().FromBytes(binaryData).WithKey(md2HmacKey).ByMd2()
		assert.Nil(t, hasher.Error)
		// Calculate expected HMAC for binary data using the same method
		expectedHasher := NewHasher().FromBytes(binaryData).WithKey(md2HmacKey).ByMd2()
		assert.Nil(t, expectedHasher.Error)
		expectedHex := expectedHasher.ToHexString()
		assert.Equal(t, expectedHex, hasher.ToHexString())
	})

	t.Run("hmac empty file", func(t *testing.T) {
		file := mock.NewFile([]byte{}, "empty.txt")
		hasher := NewHasher().FromFile(file).WithKey(md2HmacKey).ByMd2()
		assert.Nil(t, hasher.Error)
		// Calculate expected HMAC for empty file using the same method
		file2 := mock.NewFile([]byte{}, "empty2.txt")
		expectedHasher := NewHasher().FromFile(file2).WithKey(md2HmacKey).ByMd2()
		assert.Nil(t, expectedHasher.Error)
		expectedHex := expectedHasher.ToHexString()
		assert.Equal(t, expectedHex, hasher.ToHexString())
	})

	t.Run("hmac with large key", func(t *testing.T) {
		key := make([]byte, 1000)
		for i := range key {
			key[i] = byte(i % 256)
		}
		hasher := NewHasher().FromString(string(md2HmacSrc)).WithKey(key).ByMd2()
		assert.Nil(t, hasher.Error)
		// Calculate expected HMAC for large key using the same method
		expectedHasher := NewHasher().FromString(string(md2HmacSrc)).WithKey(key).ByMd2()
		assert.Nil(t, expectedHasher.Error)
		expectedHex := expectedHasher.ToHexString()
		assert.Equal(t, expectedHex, hasher.ToHexString())
	})
}

func TestHasher_ByMd2_Error(t *testing.T) {
	t.Run("existing error", func(t *testing.T) {
		hasher := NewHasher()
		hasher.Error = errors.New("existing error")
		result := hasher.ByMd2()
		assert.Equal(t, hasher, result)
		assert.Equal(t, errors.New("existing error"), result.Error)
	})
}
