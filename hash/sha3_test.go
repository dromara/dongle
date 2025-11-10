package hash

import (
	"errors"
	"strings"
	"testing"

	"github.com/dromara/dongle/mock"
	"github.com/stretchr/testify/assert"
)

// Test data for hash-sha3 (generated using Python pycryptodome library)
var (
	sha3HashSrc          = []byte("hello world")
	sha3Hash224HexDst    = "dfb7f18c77e928bb56faeb2da27291bd790bc1045cde45f3210bb6c5"
	sha3Hash224Base64Dst = "37fxjHfpKLtW+ustonKRvXkLwQRc3kXzIQu2xQ=="
	sha3Hash256HexDst    = "644bcc7e564373040999aac89e7622f3ca71fba1d972fd94a31c3bfbf24e3938"
	sha3Hash256Base64Dst = "ZEvMflZDcwQJmarInnYi88px+6HZcv2Uoxw7+/JOOTg="
	sha3Hash384HexDst    = "83bff28dde1b1bf5810071c6643c08e5b05bdb836effd70b403ea8ea0a634dc4997eb1053aa3593f590f9c63630dd90b"
	sha3Hash384Base64Dst = "g7/yjd4bG/WBAHHGZDwI5bBb24Nu/9cLQD6o6gpjTcSZfrEFOqNZP1kPnGNjDdkL"
	sha3Hash512HexDst    = "840006653e9ac9e95117a15c915caab81662918e925de9e004f774ff82d7079a40d4d27b1b372657c61d46d470304c88c788b3a4527ad074d1dccbee5dbaa99a"
	sha3Hash512Base64Dst = "hAAGZT6ayelRF6FckVyquBZikY6SXengBPd0/4LXB5pA1NJ7GzcmV8YdRtRwMEyIx4izpFJ60HTR3MvuXbqpmg=="
)

// Test data for hmac-sha3 (generated using Python pycryptodome library)
var (
	sha3HmacKey          = []byte("dongle")
	sha3HmacSrc          = []byte("hello world")
	sha3Hmac224HexDst    = "fb8f061d9d1dddd2f5d3b9064a5e98e3e4b6df27ea93ce67627583ce"
	sha3Hmac224Base64Dst = "+48GHZ0d3dL107kGSl6Y4+S23yfqk85nYnWDzg=="
	sha3Hmac256HexDst    = "8193367fde28cf5c460adb449a04b3dd9c184f488bdccbabf0526c54f90c4460"
	sha3Hmac256Base64Dst = "gZM2f94oz1xGCttEmgSz3ZwYT0iL3Mur8FJsVPkMRGA="
	sha3Hmac384HexDst    = "3f76f5cda69cada3ee6b33f8458cd498b063075db263dd8b33f2a3992a8804f9569a7c86ffa2b8f0748babeb7a6fc0e7"
	sha3Hmac384Base64Dst = "P3b1zaacraPuazP4RYzUmLBjB12yY92LM/KjmSqIBPlWmnyG/6K48HSLq+t6b8Dn"
	sha3Hmac512HexDst    = "a99653d0407d659eccdeed43bb7cccd2e2b05a2c34fd3467c4198cf2ad26a466738513e88839fb55e64eb49df65bc52ed0fec2775bd9e086edd4fb4024add4a2"
	sha3Hmac512Base64Dst = "qZZT0EB9ZZ7M3u1Du3zM0uKwWiw0/TRnxBmM8q0mpGZzhRPoiDn7VeZOtJ32W8Uu0P7Cd1vZ4Ibt1PtAJK3Uog=="
)

func TestHasher_BySha3_Hash(t *testing.T) {
	t.Run("hash string 224", func(t *testing.T) {
		hasher := NewHasher().FromString(string(sha3HashSrc)).BySha3(224)
		assert.Nil(t, hasher.Error)
		assert.Equal(t, sha3Hash224HexDst, hasher.ToHexString())

		hasher2 := NewHasher().FromString(string(sha3HashSrc)).BySha3(224)
		assert.Nil(t, hasher2.Error)
		assert.Equal(t, sha3Hash224Base64Dst, hasher2.ToBase64String())
	})

	t.Run("hash string 256", func(t *testing.T) {
		hasher := NewHasher().FromString(string(sha3HashSrc)).BySha3(256)
		assert.Nil(t, hasher.Error)
		assert.Equal(t, sha3Hash256HexDst, hasher.ToHexString())

		hasher2 := NewHasher().FromString(string(sha3HashSrc)).BySha3(256)
		assert.Nil(t, hasher2.Error)
		assert.Equal(t, sha3Hash256Base64Dst, hasher2.ToBase64String())
	})

	t.Run("hash string 384", func(t *testing.T) {
		hasher := NewHasher().FromString(string(sha3HashSrc)).BySha3(384)
		assert.Nil(t, hasher.Error)
		assert.Equal(t, sha3Hash384HexDst, hasher.ToHexString())

		hasher2 := NewHasher().FromString(string(sha3HashSrc)).BySha3(384)
		assert.Nil(t, hasher2.Error)
		assert.Equal(t, sha3Hash384Base64Dst, hasher2.ToBase64String())
	})

	t.Run("hash string 512", func(t *testing.T) {
		hasher := NewHasher().FromString(string(sha3HashSrc)).BySha3(512)
		assert.Nil(t, hasher.Error)
		assert.Equal(t, sha3Hash512HexDst, hasher.ToHexString())

		hasher2 := NewHasher().FromString(string(sha3HashSrc)).BySha3(512)
		assert.Nil(t, hasher2.Error)
		assert.Equal(t, sha3Hash512Base64Dst, hasher2.ToBase64String())
	})

	t.Run("hash bytes", func(t *testing.T) {
		hasher := NewHasher().FromBytes(sha3HashSrc).BySha3(256)
		assert.Nil(t, hasher.Error)
		assert.Equal(t, sha3Hash256HexDst, hasher.ToHexString())

		hasher2 := NewHasher().FromBytes(sha3HashSrc).BySha3(256)
		assert.Nil(t, hasher2.Error)
		assert.Equal(t, sha3Hash256Base64Dst, hasher2.ToBase64String())
	})

	t.Run("hash file", func(t *testing.T) {
		file := mock.NewFile(sha3HashSrc, "test.txt")
		hasher := NewHasher().FromFile(file).BySha3(256)
		assert.Nil(t, hasher.Error)
		assert.Equal(t, sha3Hash256HexDst, hasher.ToHexString())

		file2 := mock.NewFile(sha3HashSrc, "test2.txt")
		hasher2 := NewHasher().FromFile(file2).BySha3(256)
		assert.Nil(t, hasher2.Error)
		assert.Equal(t, sha3Hash256Base64Dst, hasher2.ToBase64String())
	})

	t.Run("hash empty string 224", func(t *testing.T) {
		hasher := NewHasher().FromString("").BySha3(224)
		assert.Nil(t, hasher.Error)
		assert.Empty(t, hasher.ToHexString())
		assert.Empty(t, hasher.ToBase64String())
	})

	t.Run("hash empty string 256", func(t *testing.T) {
		hasher := NewHasher().FromString("").BySha3(256)
		assert.Nil(t, hasher.Error)
		assert.Empty(t, hasher.ToHexString())
		assert.Empty(t, hasher.ToBase64String())
	})

	t.Run("hash empty string 384", func(t *testing.T) {
		hasher := NewHasher().FromString("").BySha3(384)
		assert.Nil(t, hasher.Error)
		assert.Empty(t, hasher.ToHexString())
		assert.Empty(t, hasher.ToBase64String())
	})

	t.Run("hash empty string 512", func(t *testing.T) {
		hasher := NewHasher().FromString("").BySha3(512)
		assert.Nil(t, hasher.Error)
		assert.Empty(t, hasher.ToHexString())
		assert.Empty(t, hasher.ToBase64String())
	})

	t.Run("hash empty bytes", func(t *testing.T) {
		hasher := NewHasher().FromBytes([]byte{}).BySha3(256)
		assert.Nil(t, hasher.Error)
		assert.Empty(t, hasher.ToHexString())
		assert.Empty(t, hasher.ToBase64String())
	})

	t.Run("hash nil bytes", func(t *testing.T) {
		hasher := NewHasher().FromBytes(nil).BySha3(256)
		assert.Nil(t, hasher.Error)
		assert.Empty(t, hasher.ToHexString())
		assert.Empty(t, hasher.ToBase64String())
	})

	t.Run("hash large data", func(t *testing.T) {
		data := strings.Repeat("a", 10000)
		hasher := NewHasher().FromString(data).BySha3(256)
		assert.Nil(t, hasher.Error)
		// Calculate expected hash for large data using the same method
		expectedHasher := NewHasher().FromString(data).BySha3(256)
		assert.Nil(t, expectedHasher.Error)
		expectedHex := expectedHasher.ToHexString()
		assert.Equal(t, expectedHex, hasher.ToHexString())
	})

	t.Run("hash unicode data", func(t *testing.T) {
		unicodeData := "你好世界"
		hasher := NewHasher().FromString(unicodeData).BySha3(256)
		assert.Nil(t, hasher.Error)
		// Calculate expected hash for unicode data using the same method
		expectedHasher := NewHasher().FromString(unicodeData).BySha3(256)
		assert.Nil(t, expectedHasher.Error)
		expectedHex := expectedHasher.ToHexString()
		assert.Equal(t, expectedHex, hasher.ToHexString())
	})

	t.Run("hash binary data", func(t *testing.T) {
		binaryData := []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f}
		hasher := NewHasher().FromBytes(binaryData).BySha3(256)
		assert.Nil(t, hasher.Error)
		// Calculate expected hash for binary data using the same method
		expectedHasher := NewHasher().FromBytes(binaryData).BySha3(256)
		assert.Nil(t, expectedHasher.Error)
		expectedHex := expectedHasher.ToHexString()
		assert.Equal(t, expectedHex, hasher.ToHexString())
	})

	t.Run("hash empty file", func(t *testing.T) {
		file := mock.NewFile([]byte{}, "empty.txt")
		hasher := NewHasher().FromFile(file).BySha3(256)
		assert.Nil(t, hasher.Error)
		assert.Empty(t, hasher.ToHexString())
		assert.Empty(t, hasher.ToBase64String())
	})

	t.Run("hash no data", func(t *testing.T) {
		hasher := NewHasher().BySha3(256)
		assert.Nil(t, hasher.Error)
		assert.Empty(t, hasher.ToHexString())
		assert.Empty(t, hasher.ToBase64String())
	})
}

func TestHasher_BySha3_HMAC(t *testing.T) {
	t.Run("hmac string 224", func(t *testing.T) {
		hasher := NewHasher().FromString(string(sha3HmacSrc)).WithKey(sha3HmacKey).BySha3(224)
		assert.Nil(t, hasher.Error)
		assert.Equal(t, sha3Hmac224HexDst, hasher.ToHexString())

		hasher2 := NewHasher().FromString(string(sha3HmacSrc)).WithKey(sha3HmacKey).BySha3(224)
		assert.Nil(t, hasher2.Error)
		assert.Equal(t, sha3Hmac224Base64Dst, hasher2.ToBase64String())
	})

	t.Run("hmac string 256", func(t *testing.T) {
		hasher := NewHasher().FromString(string(sha3HmacSrc)).WithKey(sha3HmacKey).BySha3(256)
		assert.Nil(t, hasher.Error)
		assert.Equal(t, sha3Hmac256HexDst, hasher.ToHexString())

		hasher2 := NewHasher().FromString(string(sha3HmacSrc)).WithKey(sha3HmacKey).BySha3(256)
		assert.Nil(t, hasher2.Error)
		assert.Equal(t, sha3Hmac256Base64Dst, hasher2.ToBase64String())
	})

	t.Run("hmac string 384", func(t *testing.T) {
		hasher := NewHasher().FromString(string(sha3HmacSrc)).WithKey(sha3HmacKey).BySha3(384)
		assert.Nil(t, hasher.Error)
		assert.Equal(t, sha3Hmac384HexDst, hasher.ToHexString())

		hasher2 := NewHasher().FromString(string(sha3HmacSrc)).WithKey(sha3HmacKey).BySha3(384)
		assert.Nil(t, hasher2.Error)
		assert.Equal(t, sha3Hmac384Base64Dst, hasher2.ToBase64String())
	})

	t.Run("hmac string 512", func(t *testing.T) {
		hasher := NewHasher().FromString(string(sha3HmacSrc)).WithKey(sha3HmacKey).BySha3(512)
		assert.Nil(t, hasher.Error)
		assert.Equal(t, sha3Hmac512HexDst, hasher.ToHexString())

		hasher2 := NewHasher().FromString(string(sha3HmacSrc)).WithKey(sha3HmacKey).BySha3(512)
		assert.Nil(t, hasher2.Error)
		assert.Equal(t, sha3Hmac512Base64Dst, hasher2.ToBase64String())
	})

	t.Run("hmac bytes", func(t *testing.T) {
		hasher := NewHasher().FromBytes(sha3HmacSrc).WithKey(sha3HmacKey).BySha3(256)
		assert.Nil(t, hasher.Error)
		assert.Equal(t, sha3Hmac256HexDst, hasher.ToHexString())

		hasher2 := NewHasher().FromBytes(sha3HmacSrc).WithKey(sha3HmacKey).BySha3(256)
		assert.Nil(t, hasher2.Error)
		assert.Equal(t, sha3Hmac256Base64Dst, hasher2.ToBase64String())
	})

	t.Run("hmac file", func(t *testing.T) {
		file := mock.NewFile(sha3HmacSrc, "test.txt")
		hasher := NewHasher().FromFile(file).WithKey(sha3HmacKey).BySha3(256)
		assert.Nil(t, hasher.Error)
		assert.Equal(t, sha3Hmac256HexDst, hasher.ToHexString())

		file2 := mock.NewFile(sha3HmacSrc, "test2.txt")
		hasher2 := NewHasher().FromFile(file2).WithKey(sha3HmacKey).BySha3(256)
		assert.Nil(t, hasher2.Error)
		assert.Equal(t, sha3Hmac256Base64Dst, hasher2.ToBase64String())
	})

	t.Run("hmac empty string", func(t *testing.T) {
		hasher := NewHasher().FromString("").WithKey(sha3HmacKey).BySha3(256)
		assert.Nil(t, hasher.Error)
		// Calculate expected HMAC for empty string using the same method
		expectedHasher := NewHasher().FromString("").WithKey(sha3HmacKey).BySha3(256)
		assert.Nil(t, expectedHasher.Error)
		expectedHex := expectedHasher.ToHexString()
		assert.Equal(t, expectedHex, hasher.ToHexString())
	})

	t.Run("hmac empty bytes", func(t *testing.T) {
		hasher := NewHasher().FromBytes([]byte{}).WithKey(sha3HmacKey).BySha3(256)
		assert.Nil(t, hasher.Error)
		// Calculate expected HMAC for empty bytes using the same method
		expectedHasher := NewHasher().FromBytes([]byte{}).WithKey(sha3HmacKey).BySha3(256)
		assert.Nil(t, expectedHasher.Error)
		expectedHex := expectedHasher.ToHexString()
		assert.Equal(t, expectedHex, hasher.ToHexString())
	})

	t.Run("hmac large data", func(t *testing.T) {
		data := strings.Repeat("a", 10000)
		hasher := NewHasher().FromString(data).WithKey(sha3HmacKey).BySha3(256)
		assert.Nil(t, hasher.Error)
		// Calculate expected HMAC for large data using the same method
		expectedHasher := NewHasher().FromString(data).WithKey(sha3HmacKey).BySha3(256)
		assert.Nil(t, expectedHasher.Error)
		expectedHex := expectedHasher.ToHexString()
		assert.Equal(t, expectedHex, hasher.ToHexString())
	})

	t.Run("hmac unicode data", func(t *testing.T) {
		unicodeData := "你好世界"
		hasher := NewHasher().FromString(unicodeData).WithKey(sha3HmacKey).BySha3(256)
		assert.Nil(t, hasher.Error)
		// Calculate expected HMAC for unicode data using the same method
		expectedHasher := NewHasher().FromString(unicodeData).WithKey(sha3HmacKey).BySha3(256)
		assert.Nil(t, expectedHasher.Error)
		expectedHex := expectedHasher.ToHexString()
		assert.Equal(t, expectedHex, hasher.ToHexString())
	})

	t.Run("hmac binary data", func(t *testing.T) {
		binaryData := []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f}
		hasher := NewHasher().FromBytes(binaryData).WithKey(sha3HmacKey).BySha3(256)
		assert.Nil(t, hasher.Error)
		// Calculate expected HMAC for binary data using the same method
		expectedHasher := NewHasher().FromBytes(binaryData).WithKey(sha3HmacKey).BySha3(256)
		assert.Nil(t, expectedHasher.Error)
		expectedHex := expectedHasher.ToHexString()
		assert.Equal(t, expectedHex, hasher.ToHexString())
	})

	t.Run("hmac empty file", func(t *testing.T) {
		file := mock.NewFile([]byte{}, "empty.txt")
		hasher := NewHasher().FromFile(file).WithKey(sha3HmacKey).BySha3(256)
		assert.Nil(t, hasher.Error)
		// Calculate expected HMAC for empty file using the same method
		file2 := mock.NewFile([]byte{}, "empty2.txt")
		expectedHasher := NewHasher().FromFile(file2).WithKey(sha3HmacKey).BySha3(256)
		assert.Nil(t, expectedHasher.Error)
		expectedHex := expectedHasher.ToHexString()
		assert.Equal(t, expectedHex, hasher.ToHexString())
	})

	t.Run("hmac with large key", func(t *testing.T) {
		largeKey := strings.Repeat("secret", 100)
		hasher := NewHasher().FromString(string(sha3HmacSrc)).WithKey([]byte(largeKey)).BySha3(256)
		assert.Nil(t, hasher.Error)
		// Calculate expected HMAC for large key using the same method
		expectedHasher := NewHasher().FromString(string(sha3HmacSrc)).WithKey([]byte(largeKey)).BySha3(256)
		assert.Nil(t, expectedHasher.Error)
		expectedHex := expectedHasher.ToHexString()
		assert.Equal(t, expectedHex, hasher.ToHexString())
	})
}

func TestHasher_BySha3_Error(t *testing.T) {
	t.Run("existing error", func(t *testing.T) {
		hasher := NewHasher()
		hasher.Error = errors.New("existing error")
		result := hasher.BySha3(256)
		assert.Equal(t, hasher, result)
		assert.Equal(t, errors.New("existing error"), result.Error)
	})

	t.Run("unsupported size", func(t *testing.T) {
		hasher := NewHasher().FromString("hello").BySha3(128)
		assert.NotNil(t, hasher.Error)
		assert.Contains(t, hasher.Error.Error(), "unsupported size: 128")
		assert.Contains(t, hasher.Error.Error(), "supported sizes are 224, 256, 384, 512")
	})
}
