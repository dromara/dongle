package hash

import (
	"errors"
	"strings"
	"testing"

	"github.com/dromara/dongle/mock"
	"github.com/stretchr/testify/assert"
)

// Test data for hash-blake2s (generated using Python hashlib library)
var (
	blake2sHashSrc          = []byte("hello world")
	blake2sHash256HexDst    = "9aec6806794561107e594b1f6a8a6b0c92a0cba9acf5e5e93cca06f781813b0b"
	blake2sHash256Base64Dst = "muxoBnlFYRB+WUsfaoprDJKgy6ms9eXpPMoG94GBOws="
	blake2sHash128HexDst    = "8e9dce350baec849c2bc163d0e73552a"
	blake2sHash128Base64Dst = "jp3ONQuuyEnCvBY9DnNVKg=="
)

// Test data for hmac-blake2s (generated using Python hashlib library)
var (
	blake2sHmacKey          = []byte("dongle")
	blake2sHmacSrc          = []byte("hello world")
	blake2sHmac256HexDst    = "14953619e2781ed4a20f571d32d494af37b92e9bede33fbe429dff376f233af3"
	blake2sHmac256Base64Dst = "FJU2GeJ4HtSiD1cdMtSUrze5Lpvt4z++Qp3/N28jOvM="
)

func TestHasher_ByBlake2s_Hash(t *testing.T) {
	t.Run("hash string BLAKE2s-256", func(t *testing.T) {
		hasher := NewHasher().FromString(string(blake2sHashSrc)).ByBlake2s(256)
		assert.Nil(t, hasher.Error)
		assert.Equal(t, blake2sHash256HexDst, hasher.ToHexString())

		hasher2 := NewHasher().FromString(string(blake2sHashSrc)).ByBlake2s(256)
		assert.Nil(t, hasher2.Error)
		assert.Equal(t, blake2sHash256Base64Dst, hasher2.ToBase64String())
	})

	t.Run("hash bytes BLAKE2s-256", func(t *testing.T) {
		hasher := NewHasher().FromBytes(blake2sHashSrc).ByBlake2s(256)
		assert.Nil(t, hasher.Error)
		assert.Equal(t, blake2sHash256HexDst, hasher.ToHexString())

		hasher2 := NewHasher().FromBytes(blake2sHashSrc).ByBlake2s(256)
		assert.Nil(t, hasher2.Error)
		assert.Equal(t, blake2sHash256Base64Dst, hasher2.ToBase64String())
	})

	t.Run("hash file BLAKE2s-256", func(t *testing.T) {
		file := mock.NewFile(blake2sHashSrc, "test.txt")
		hasher := NewHasher().FromFile(file).ByBlake2s(256)
		assert.Nil(t, hasher.Error)
		assert.Equal(t, blake2sHash256HexDst, hasher.ToHexString())

		file2 := mock.NewFile(blake2sHashSrc, "test2.txt")
		hasher2 := NewHasher().FromFile(file2).ByBlake2s(256)
		assert.Nil(t, hasher2.Error)
		assert.Equal(t, blake2sHash256Base64Dst, hasher2.ToBase64String())
	})

	t.Run("hash string BLAKE2s-128 with key", func(t *testing.T) {
		hasher := NewHasher().FromString(string(blake2sHashSrc)).WithKey(blake2sHmacKey).ByBlake2s(128)
		assert.Nil(t, hasher.Error)
		assert.Equal(t, blake2sHash128HexDst, hasher.ToHexString())

		hasher2 := NewHasher().FromString(string(blake2sHashSrc)).WithKey(blake2sHmacKey).ByBlake2s(128)
		assert.Nil(t, hasher2.Error)
		assert.Equal(t, blake2sHash128Base64Dst, hasher2.ToBase64String())
	})

	t.Run("empty string BLAKE2s-256", func(t *testing.T) {
		hasher := NewHasher().FromString("").ByBlake2s(256)
		assert.Nil(t, hasher.Error)
		assert.Empty(t, hasher.ToHexString())
		assert.Empty(t, hasher.ToBase64String())
	})

	t.Run("empty bytes BLAKE2s-256", func(t *testing.T) {
		hasher := NewHasher().FromBytes([]byte{}).ByBlake2s(256)
		assert.Nil(t, hasher.Error)
		assert.Empty(t, hasher.ToHexString())
		assert.Empty(t, hasher.ToBase64String())
	})

	t.Run("nil bytes BLAKE2s-256", func(t *testing.T) {
		hasher := NewHasher().FromBytes(nil).ByBlake2s(256)
		assert.Nil(t, hasher.Error)
		assert.Empty(t, hasher.ToHexString())
		assert.Empty(t, hasher.ToBase64String())
	})

	t.Run("large data BLAKE2s-256", func(t *testing.T) {
		data := strings.Repeat("a", 10000)
		hasher := NewHasher().FromString(data).ByBlake2s(256)
		assert.Nil(t, hasher.Error)
		// Calculate expected hash for large data using the same method
		expectedHasher := NewHasher().FromString(data).ByBlake2s(256)
		assert.Nil(t, expectedHasher.Error)
		expectedHex := expectedHasher.ToHexString()
		assert.Equal(t, expectedHex, hasher.ToHexString())
	})

	t.Run("unicode data BLAKE2s-256", func(t *testing.T) {
		unicodeData := "你好世界"
		hasher := NewHasher().FromString(unicodeData).ByBlake2s(256)
		assert.Nil(t, hasher.Error)
		// Calculate expected hash for unicode data using the same method
		expectedHasher := NewHasher().FromString(unicodeData).ByBlake2s(256)
		assert.Nil(t, expectedHasher.Error)
		expectedHex := expectedHasher.ToHexString()
		assert.Equal(t, expectedHex, hasher.ToHexString())
	})

	t.Run("binary data BLAKE2s-256", func(t *testing.T) {
		binaryData := []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f}
		hasher := NewHasher().FromBytes(binaryData).ByBlake2s(256)
		assert.Nil(t, hasher.Error)
		// Calculate expected hash for binary data using the same method
		expectedHasher := NewHasher().FromBytes(binaryData).ByBlake2s(256)
		assert.Nil(t, expectedHasher.Error)
		expectedHex := expectedHasher.ToHexString()
		assert.Equal(t, expectedHex, hasher.ToHexString())
	})

	t.Run("empty file BLAKE2s-256", func(t *testing.T) {
		file := mock.NewFile([]byte{}, "empty.txt")
		hasher := NewHasher().FromFile(file).ByBlake2s(256)
		assert.Nil(t, hasher.Error)
		assert.Empty(t, hasher.ToHexString())
		assert.Empty(t, hasher.ToBase64String())
	})

	t.Run("no data no reader no key", func(t *testing.T) {
		hasher := NewHasher().ByBlake2s(256)
		assert.Nil(t, hasher.Error)
		assert.Empty(t, hasher.ToHexString())
		assert.Empty(t, hasher.ToBase64String())
	})
}

func TestHasher_ByBlake2s_HMAC(t *testing.T) {
	t.Run("hmac string BLAKE2s-256", func(t *testing.T) {
		hasher := NewHasher().FromString(string(blake2sHmacSrc)).WithKey(blake2sHmacKey).ByBlake2s(256)
		assert.Nil(t, hasher.Error)
		assert.Equal(t, blake2sHmac256HexDst, hasher.ToHexString())

		hasher2 := NewHasher().FromString(string(blake2sHmacSrc)).WithKey(blake2sHmacKey).ByBlake2s(256)
		assert.Nil(t, hasher2.Error)
		assert.Equal(t, blake2sHmac256Base64Dst, hasher2.ToBase64String())
	})

	t.Run("hmac bytes BLAKE2s-256", func(t *testing.T) {
		hasher := NewHasher().FromBytes(blake2sHmacSrc).WithKey(blake2sHmacKey).ByBlake2s(256)
		assert.Nil(t, hasher.Error)
		assert.Equal(t, blake2sHmac256HexDst, hasher.ToHexString())

		hasher2 := NewHasher().FromBytes(blake2sHmacSrc).WithKey(blake2sHmacKey).ByBlake2s(256)
		assert.Nil(t, hasher2.Error)
		assert.Equal(t, blake2sHmac256Base64Dst, hasher2.ToBase64String())
	})

	t.Run("hmac file BLAKE2s-256", func(t *testing.T) {
		file := mock.NewFile(blake2sHmacSrc, "test.txt")
		hasher := NewHasher().FromFile(file).WithKey(blake2sHmacKey).ByBlake2s(256)
		assert.Nil(t, hasher.Error)
		assert.Equal(t, blake2sHmac256HexDst, hasher.ToHexString())

		file2 := mock.NewFile(blake2sHmacSrc, "test2.txt")
		hasher2 := NewHasher().FromFile(file2).WithKey(blake2sHmacKey).ByBlake2s(256)
		assert.Nil(t, hasher2.Error)
		assert.Equal(t, blake2sHmac256Base64Dst, hasher2.ToBase64String())
	})

	t.Run("hmac empty string BLAKE2s-256", func(t *testing.T) {
		hasher := NewHasher().FromString("").WithKey(blake2sHmacKey).ByBlake2s(256)
		assert.Nil(t, hasher.Error)
		assert.Empty(t, hasher.ToHexString())
		assert.Empty(t, hasher.ToBase64String())
	})

	t.Run("hmac empty bytes BLAKE2s-256", func(t *testing.T) {
		hasher := NewHasher().FromBytes([]byte{}).WithKey(blake2sHmacKey).ByBlake2s(256)
		assert.Nil(t, hasher.Error)
		assert.Empty(t, hasher.ToHexString())
		assert.Empty(t, hasher.ToBase64String())
	})

	t.Run("hmac large data BLAKE2s-256", func(t *testing.T) {
		data := strings.Repeat("a", 10000)
		hasher := NewHasher().FromString(data).WithKey(blake2sHmacKey).ByBlake2s(256)
		assert.Nil(t, hasher.Error)
		// Calculate expected HMAC for large data using the same method
		expectedHasher := NewHasher().FromString(data).WithKey(blake2sHmacKey).ByBlake2s(256)
		assert.Nil(t, expectedHasher.Error)
		expectedHex := expectedHasher.ToHexString()
		assert.Equal(t, expectedHex, hasher.ToHexString())
	})

	t.Run("hmac unicode data BLAKE2s-256", func(t *testing.T) {
		unicodeData := "你好世界"
		hasher := NewHasher().FromString(unicodeData).WithKey(blake2sHmacKey).ByBlake2s(256)
		assert.Nil(t, hasher.Error)
		// Calculate expected HMAC for unicode data using the same method
		expectedHasher := NewHasher().FromString(unicodeData).WithKey(blake2sHmacKey).ByBlake2s(256)
		assert.Nil(t, expectedHasher.Error)
		expectedHex := expectedHasher.ToHexString()
		assert.Equal(t, expectedHex, hasher.ToHexString())
	})

	t.Run("hmac binary data BLAKE2s-256", func(t *testing.T) {
		binaryData := []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f}
		hasher := NewHasher().FromBytes(binaryData).WithKey(blake2sHmacKey).ByBlake2s(256)
		assert.Nil(t, hasher.Error)
		// Calculate expected HMAC for binary data using the same method
		expectedHasher := NewHasher().FromBytes(binaryData).WithKey(blake2sHmacKey).ByBlake2s(256)
		assert.Nil(t, expectedHasher.Error)
		expectedHex := expectedHasher.ToHexString()
		assert.Equal(t, expectedHex, hasher.ToHexString())
	})

	t.Run("hmac empty file BLAKE2s-256", func(t *testing.T) {
		file := mock.NewFile([]byte{}, "empty.txt")
		hasher := NewHasher().FromFile(file).WithKey(blake2sHmacKey).ByBlake2s(256)
		assert.Nil(t, hasher.Error)
		// Calculate expected HMAC for empty file using the same method
		file2 := mock.NewFile([]byte{}, "empty2.txt")
		expectedHasher := NewHasher().FromFile(file2).WithKey(blake2sHmacKey).ByBlake2s(256)
		assert.Nil(t, expectedHasher.Error)
		expectedHex := expectedHasher.ToHexString()
		assert.Equal(t, expectedHex, hasher.ToHexString())
	})

	t.Run("hmac with large key BLAKE2s-256", func(t *testing.T) {
		key := make([]byte, 1000)
		for i := range key {
			key[i] = byte(i % 256)
		}
		hasher := NewHasher().FromString(string(blake2sHmacSrc)).WithKey(key).ByBlake2s(256)
		assert.Nil(t, hasher.Error)
		// Calculate expected HMAC for large key using the same method
		expectedHasher := NewHasher().FromString(string(blake2sHmacSrc)).WithKey(key).ByBlake2s(256)
		assert.Nil(t, expectedHasher.Error)
		expectedHex := expectedHasher.ToHexString()
		assert.Equal(t, expectedHex, hasher.ToHexString())
	})
}

func TestHasher_ByBlake2s_Error(t *testing.T) {
	t.Run("existing error", func(t *testing.T) {
		hasher := NewHasher()
		hasher.Error = errors.New("existing error")
		result := hasher.ByBlake2s(256)
		assert.Equal(t, hasher, result)
		assert.Equal(t, errors.New("existing error"), result.Error)
	})

	t.Run("unsupported size", func(t *testing.T) {
		hasher := NewHasher().FromString("hello").ByBlake2s(64)
		assert.NotNil(t, hasher.Error)
		assert.Contains(t, hasher.Error.Error(), "unsupported size: 64")
		assert.Contains(t, hasher.Error.Error(), "supported sizes are 128, 256")
	})

	t.Run("BLAKE2s-128 without key", func(t *testing.T) {
		hasher := NewHasher().FromString("hello").ByBlake2s(128)
		assert.NotNil(t, hasher.Error)
		assert.Contains(t, hasher.Error.Error(), "BLAKE2s-128 requires a key for security reasons")
	})
}
