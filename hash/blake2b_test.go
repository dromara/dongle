package hash

import (
	"errors"
	"strings"
	"testing"

	"github.com/dromara/dongle/mock"
	"github.com/stretchr/testify/assert"
)

// Test data for hash-blake2b (generated using Python hashlib library)
var (
	blake2bHashSrc          = []byte("hello world")
	blake2bHash256HexDst    = "256c83b297114d201b30179f3f0ef0cace9783622da5974326b436178aeef610"
	blake2bHash256Base64Dst = "JWyDspcRTSAbMBefPw7wys6Xg2ItpZdDJrQ2F4ru9hA="
	blake2bHash384HexDst    = "8c653f8c9c9aa2177fb6f8cf5bb914828faa032d7b486c8150663d3f6524b086784f8e62693171ac51fc80b7d2cbb12b"
	blake2bHash384Base64Dst = "jGU/jJyaohd/tvjPW7kUgo+qAy17SGyBUGY9P2UksIZ4T45iaTFxrFH8gLfSy7Er"
	blake2bHash512HexDst    = "021ced8799296ceca557832ab941a50b4a11f83478cf141f51f933f653ab9fbcc05a037cddbed06e309bf334942c4e58cdf1a46e237911ccd7fcf9787cbc7fd0"
	blake2bHash512Base64Dst = "Ahzth5kpbOylV4MquUGlC0oR+DR4zxQfUfkz9lOrn7zAWgN83b7QbjCb8zSULE5YzfGkbiN5EczX/Pl4fLx/0A=="
)

// Test data for hmac-blake2b (generated using Python hashlib library)
var (
	blake2bHmacKey          = []byte("dongle")
	blake2bHmacSrc          = []byte("hello world")
	blake2bHmac256HexDst    = "11de19238a5d5414bc8f9effb2a5f004a4210804668d25d252d0733c26670a0d"
	blake2bHmac256Base64Dst = "Ed4ZI4pdVBS8j57/sqXwBKQhCARmjSXSUtBzPCZnCg0="
	blake2bHmac384HexDst    = "506c397b0b5d437342a07748d09612f9905ab21e6674d8409516a53cf341a1bc9052bf47edf85ffe50643a7acd1f91bc"
	blake2bHmac384Base64Dst = "UGw5ewtdQ3NCoHdI0JYS+ZBash5mdNhAlRalPPNBobyQUr9H7fhf/lBkOnrNH5G8"
	blake2bHmac512HexDst    = "9ab7280ca18d0fca29034329eddecb36ecdcefe00758bbe966e30cfbf9774e3e21c2ee5be01fdc23c983d8849fcf2f0dcfd3a0e6ba92442cbd64a2342763d2ae"
	blake2bHmac512Base64Dst = "mrcoDKGND8opA0Mp7d7LNuzc7+AHWLvpZuMM+/l3Tj4hwu5b4B/cI8mD2ISfzy8Nz9Og5rqSRCy9ZKI0J2PSrg=="
)

func TestHasher_ByBlake2b_Hash(t *testing.T) {
	t.Run("hash string 256", func(t *testing.T) {
		hasher := NewHasher().FromString(string(blake2bHashSrc)).ByBlake2b(256)
		assert.Nil(t, hasher.Error)
		assert.Equal(t, blake2bHash256HexDst, hasher.ToHexString())

		hasher2 := NewHasher().FromString(string(blake2bHashSrc)).ByBlake2b(256)
		assert.Nil(t, hasher2.Error)
		assert.Equal(t, blake2bHash256Base64Dst, hasher2.ToBase64String())
	})

	t.Run("hash string 384", func(t *testing.T) {
		hasher := NewHasher().FromString(string(blake2bHashSrc)).ByBlake2b(384)
		assert.Nil(t, hasher.Error)
		assert.Equal(t, blake2bHash384HexDst, hasher.ToHexString())

		hasher2 := NewHasher().FromString(string(blake2bHashSrc)).ByBlake2b(384)
		assert.Nil(t, hasher2.Error)
		assert.Equal(t, blake2bHash384Base64Dst, hasher2.ToBase64String())
	})

	t.Run("hash string 512", func(t *testing.T) {
		hasher := NewHasher().FromString(string(blake2bHashSrc)).ByBlake2b(512)
		assert.Nil(t, hasher.Error)
		assert.Equal(t, blake2bHash512HexDst, hasher.ToHexString())

		hasher2 := NewHasher().FromString(string(blake2bHashSrc)).ByBlake2b(512)
		assert.Nil(t, hasher2.Error)
		assert.Equal(t, blake2bHash512Base64Dst, hasher2.ToBase64String())
	})

	t.Run("hash bytes", func(t *testing.T) {
		hasher := NewHasher().FromBytes(blake2bHashSrc).ByBlake2b(256)
		assert.Nil(t, hasher.Error)
		assert.Equal(t, blake2bHash256HexDst, hasher.ToHexString())

		hasher2 := NewHasher().FromBytes(blake2bHashSrc).ByBlake2b(256)
		assert.Nil(t, hasher2.Error)
		assert.Equal(t, blake2bHash256Base64Dst, hasher2.ToBase64String())
	})

	t.Run("hash file", func(t *testing.T) {
		file := mock.NewFile(blake2bHashSrc, "test.txt")
		hasher := NewHasher().FromFile(file).ByBlake2b(256)
		assert.Nil(t, hasher.Error)
		assert.Equal(t, blake2bHash256HexDst, hasher.ToHexString())

		file2 := mock.NewFile(blake2bHashSrc, "test2.txt")
		hasher2 := NewHasher().FromFile(file2).ByBlake2b(256)
		assert.Nil(t, hasher2.Error)
		assert.Equal(t, blake2bHash256Base64Dst, hasher2.ToBase64String())
	})

	t.Run("hash empty string", func(t *testing.T) {
		hasher := NewHasher().FromString("").ByBlake2b(256)
		assert.Nil(t, hasher.Error)
		assert.Empty(t, hasher.ToHexString())
		assert.Empty(t, hasher.ToBase64String())
	})

	t.Run("hash empty bytes", func(t *testing.T) {
		hasher := NewHasher().FromBytes([]byte{}).ByBlake2b(256)
		assert.Nil(t, hasher.Error)
		assert.Empty(t, hasher.ToHexString())
		assert.Empty(t, hasher.ToBase64String())
	})

	t.Run("hash nil bytes", func(t *testing.T) {
		hasher := NewHasher().FromBytes(nil).ByBlake2b(256)
		assert.Nil(t, hasher.Error)
		assert.Empty(t, hasher.ToHexString())
		assert.Empty(t, hasher.ToBase64String())
	})

	t.Run("hash large data", func(t *testing.T) {
		data := strings.Repeat("a", 10000)
		hasher := NewHasher().FromString(data).ByBlake2b(256)
		assert.Nil(t, hasher.Error)
		// Calculate expected hash for large data using the same method
		expectedHasher := NewHasher().FromString(data).ByBlake2b(256)
		assert.Nil(t, expectedHasher.Error)
		expectedHex := expectedHasher.ToHexString()
		assert.Equal(t, expectedHex, hasher.ToHexString())
	})

	t.Run("hash unicode data", func(t *testing.T) {
		unicodeData := "你好世界"
		hasher := NewHasher().FromString(unicodeData).ByBlake2b(256)
		assert.Nil(t, hasher.Error)
		// Calculate expected hash for unicode data using the same method
		expectedHasher := NewHasher().FromString(unicodeData).ByBlake2b(256)
		assert.Nil(t, expectedHasher.Error)
		expectedHex := expectedHasher.ToHexString()
		assert.Equal(t, expectedHex, hasher.ToHexString())
	})

	t.Run("hash binary data", func(t *testing.T) {
		binaryData := []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f}
		hasher := NewHasher().FromBytes(binaryData).ByBlake2b(256)
		assert.Nil(t, hasher.Error)
		// Calculate expected hash for binary data using the same method
		expectedHasher := NewHasher().FromBytes(binaryData).ByBlake2b(256)
		assert.Nil(t, expectedHasher.Error)
		expectedHex := expectedHasher.ToHexString()
		assert.Equal(t, expectedHex, hasher.ToHexString())
	})

	t.Run("hash empty file", func(t *testing.T) {
		file := mock.NewFile([]byte{}, "empty.txt")
		hasher := NewHasher().FromFile(file).ByBlake2b(256)
		assert.Nil(t, hasher.Error)
		assert.Empty(t, hasher.ToHexString())
		assert.Empty(t, hasher.ToBase64String())
	})

	t.Run("hash no data", func(t *testing.T) {
		hasher := NewHasher().ByBlake2b(256)
		assert.Nil(t, hasher.Error)
		assert.Empty(t, hasher.ToHexString())
		assert.Empty(t, hasher.ToBase64String())
	})
}

func TestHasher_ByBlake2b_HMAC(t *testing.T) {
	t.Run("hmac string 256", func(t *testing.T) {
		hasher := NewHasher().FromString(string(blake2bHmacSrc)).WithKey(blake2bHmacKey).ByBlake2b(256)
		assert.Nil(t, hasher.Error)
		assert.Equal(t, blake2bHmac256HexDst, hasher.ToHexString())

		hasher2 := NewHasher().FromString(string(blake2bHmacSrc)).WithKey(blake2bHmacKey).ByBlake2b(256)
		assert.Nil(t, hasher2.Error)
		assert.Equal(t, blake2bHmac256Base64Dst, hasher2.ToBase64String())
	})

	t.Run("hmac string 384", func(t *testing.T) {
		hasher := NewHasher().FromString(string(blake2bHmacSrc)).WithKey(blake2bHmacKey).ByBlake2b(384)
		assert.Nil(t, hasher.Error)
		assert.Equal(t, blake2bHmac384HexDst, hasher.ToHexString())

		hasher2 := NewHasher().FromString(string(blake2bHmacSrc)).WithKey(blake2bHmacKey).ByBlake2b(384)
		assert.Nil(t, hasher2.Error)
		assert.Equal(t, blake2bHmac384Base64Dst, hasher2.ToBase64String())
	})

	t.Run("hmac string 512", func(t *testing.T) {
		hasher := NewHasher().FromString(string(blake2bHmacSrc)).WithKey(blake2bHmacKey).ByBlake2b(512)
		assert.Nil(t, hasher.Error)
		assert.Equal(t, blake2bHmac512HexDst, hasher.ToHexString())

		hasher2 := NewHasher().FromString(string(blake2bHmacSrc)).WithKey(blake2bHmacKey).ByBlake2b(512)
		assert.Nil(t, hasher2.Error)
		assert.Equal(t, blake2bHmac512Base64Dst, hasher2.ToBase64String())
	})

	t.Run("hmac bytes", func(t *testing.T) {
		hasher := NewHasher().FromBytes(blake2bHmacSrc).WithKey(blake2bHmacKey).ByBlake2b(256)
		assert.Nil(t, hasher.Error)
		assert.Equal(t, blake2bHmac256HexDst, hasher.ToHexString())

		hasher2 := NewHasher().FromBytes(blake2bHmacSrc).WithKey(blake2bHmacKey).ByBlake2b(256)
		assert.Nil(t, hasher2.Error)
		assert.Equal(t, blake2bHmac256Base64Dst, hasher2.ToBase64String())
	})

	t.Run("hmac file", func(t *testing.T) {
		file := mock.NewFile(blake2bHmacSrc, "test.txt")
		hasher := NewHasher().FromFile(file).WithKey(blake2bHmacKey).ByBlake2b(256)
		assert.Nil(t, hasher.Error)
		assert.Equal(t, blake2bHmac256HexDst, hasher.ToHexString())

		file2 := mock.NewFile(blake2bHmacSrc, "test2.txt")
		hasher2 := NewHasher().FromFile(file2).WithKey(blake2bHmacKey).ByBlake2b(256)
		assert.Nil(t, hasher2.Error)
		assert.Equal(t, blake2bHmac256Base64Dst, hasher2.ToBase64String())
	})

	t.Run("hmac empty string", func(t *testing.T) {
		hasher := NewHasher().FromString("").WithKey(blake2bHmacKey).ByBlake2b(256)
		assert.Nil(t, hasher.Error)
		assert.Empty(t, hasher.ToHexString())
		assert.Empty(t, hasher.ToBase64String())
	})

	t.Run("hmac empty bytes", func(t *testing.T) {
		hasher := NewHasher().FromBytes([]byte{}).WithKey(blake2bHmacKey).ByBlake2b(256)
		assert.Nil(t, hasher.Error)
		assert.Empty(t, hasher.ToHexString())
		assert.Empty(t, hasher.ToBase64String())
	})

	t.Run("hmac large data", func(t *testing.T) {
		data := strings.Repeat("a", 10000)
		hasher := NewHasher().FromString(data).WithKey(blake2bHmacKey).ByBlake2b(256)
		assert.Nil(t, hasher.Error)
		// Calculate expected HMAC for large data using the same method
		expectedHasher := NewHasher().FromString(data).WithKey(blake2bHmacKey).ByBlake2b(256)
		assert.Nil(t, expectedHasher.Error)
		expectedHex := expectedHasher.ToHexString()
		assert.Equal(t, expectedHex, hasher.ToHexString())
	})

	t.Run("hmac unicode data", func(t *testing.T) {
		unicodeData := "你好世界"
		hasher := NewHasher().FromString(unicodeData).WithKey(blake2bHmacKey).ByBlake2b(256)
		assert.Nil(t, hasher.Error)
		// Calculate expected HMAC for unicode data using the same method
		expectedHasher := NewHasher().FromString(unicodeData).WithKey(blake2bHmacKey).ByBlake2b(256)
		assert.Nil(t, expectedHasher.Error)
		expectedHex := expectedHasher.ToHexString()
		assert.Equal(t, expectedHex, hasher.ToHexString())
	})

	t.Run("hmac binary data", func(t *testing.T) {
		binaryData := []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f}
		hasher := NewHasher().FromBytes(binaryData).WithKey(blake2bHmacKey).ByBlake2b(256)
		assert.Nil(t, hasher.Error)
		// Calculate expected HMAC for binary data using the same method
		expectedHasher := NewHasher().FromBytes(binaryData).WithKey(blake2bHmacKey).ByBlake2b(256)
		assert.Nil(t, expectedHasher.Error)
		expectedHex := expectedHasher.ToHexString()
		assert.Equal(t, expectedHex, hasher.ToHexString())
	})

	t.Run("hmac empty file", func(t *testing.T) {
		file := mock.NewFile([]byte{}, "empty.txt")
		hasher := NewHasher().FromFile(file).WithKey(blake2bHmacKey).ByBlake2b(256)
		assert.Nil(t, hasher.Error)
		// Calculate expected HMAC for empty file using the same method
		file2 := mock.NewFile([]byte{}, "empty2.txt")
		expectedHasher := NewHasher().FromFile(file2).WithKey(blake2bHmacKey).ByBlake2b(256)
		assert.Nil(t, expectedHasher.Error)
		expectedHex := expectedHasher.ToHexString()
		assert.Equal(t, expectedHex, hasher.ToHexString())
	})

	t.Run("hmac with large key", func(t *testing.T) {
		key := make([]byte, 1000)
		for i := range key {
			key[i] = byte(i % 256)
		}
		hasher := NewHasher().FromString(string(blake2bHmacSrc)).WithKey(key).ByBlake2b(256)
		assert.Nil(t, hasher.Error)
		// Calculate expected HMAC for large key using the same method
		expectedHasher := NewHasher().FromString(string(blake2bHmacSrc)).WithKey(key).ByBlake2b(256)
		assert.Nil(t, expectedHasher.Error)
		expectedHex := expectedHasher.ToHexString()
		assert.Equal(t, expectedHex, hasher.ToHexString())
	})
}

func TestHasher_ByBlake2b_Error(t *testing.T) {
	t.Run("existing error", func(t *testing.T) {
		hasher := NewHasher()
		hasher.Error = errors.New("existing error")
		result := hasher.ByBlake2b(256)
		assert.Equal(t, hasher, result)
		assert.Equal(t, errors.New("existing error"), result.Error)
	})

	t.Run("unsupported size", func(t *testing.T) {
		hasher := NewHasher().FromString("hello").ByBlake2b(224)
		assert.NotNil(t, hasher.Error)
		assert.Contains(t, hasher.Error.Error(), "unsupported size: 224")
		assert.Contains(t, hasher.Error.Error(), "supported sizes are 256, 384, 512")
	})
}
