package hash

import (
	"errors"
	"strings"
	"testing"

	"github.com/dromara/dongle/internal/mock"
	"github.com/stretchr/testify/assert"
)

// Test data for hash-sha2 (generated using Python pycryptodome library)
var (
	sha2HashSrc          = []byte("hello world")
	sha2Hash224HexDst    = "2f05477fc24bb4faefd86517156dafdecec45b8ad3cf2522a563582b"
	sha2Hash224Base64Dst = "LwVHf8JLtPrv2GUXFW2v3s7EW4rTzyUipWNYKw=="
	sha2Hash256HexDst    = "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
	sha2Hash256Base64Dst = "uU0nuZNNPgilLlLX2n2r+sSE7+N6U4DukIj3rOLvzek="
	sha2Hash384HexDst    = "fdbd8e75a67f29f701a4e040385e2e23986303ea10239211af907fcbb83578b3e417cb71ce646efd0819dd8c088de1bd"
	sha2Hash384Base64Dst = "/b2OdaZ/KfcBpOBAOF4uI5hjA+oQI5IRr5B/y7g1eLPkF8txzmRu/QgZ3YwIjeG9"
	sha2Hash512HexDst    = "309ecc489c12d6eb4cc40f50c902f2b4d0ed77ee511a7c7a9bcd3ca86d4cd86f989dd35bc5ff499670da34255b45b0cfd830e81f605dcf7dc5542e93ae9cd76f"
	sha2Hash512Base64Dst = "MJ7MSJwS1utMxA9QyQLytNDtd+5RGnx6m808qG1M2G+YndNbxf9JlnDaNCVbRbDP2DDoH2Bdz33FVC6TrpzXbw=="
)

// Test data for hmac-sha2 (generated using Python pycryptodome library)
var (
	sha2HmacKey          = []byte("dongle")
	sha2HmacSrc          = []byte("hello world")
	sha2Hmac224HexDst    = "e15b9e5a7eccb1f17dc81dc07c909a891936dc3429dc0d940accbcec"
	sha2Hmac224Base64Dst = "4VueWn7MsfF9yB3AfJCaiRk23DQp3A2UCsy87A=="
	sha2Hmac256HexDst    = "77f5c8ce4147600543e70b12701e7b78b5b95172332ebbb06de65fcea7112179"
	sha2Hmac256Base64Dst = "d/XIzkFHYAVD5wsScB57eLW5UXIzLruwbeZfzqcRIXk="
	sha2Hmac384HexDst    = "421fcaa740216a31bbcd1f86f2212e0c68aa4b156a8ebc2ae55b3e75c4ee0509ea0325a0570ae739006b61d91d817fe8"
	sha2Hmac384Base64Dst = "Qh/Kp0AhajG7zR+G8iEuDGiqSxVqjrwq5Vs+dcTuBQnqAyWgVwrnOQBrYdkdgX/o"
	sha2Hmac512HexDst    = "d971b790bbc2a4ac81062bbffac693c9c234bae176c8faf5e304dbdb153032a826f12353964b4a4fb87abecd2dc237638a630cbad54a6b94b1f6ef5d5e2835d1"
	sha2Hmac512Base64Dst = "2XG3kLvCpKyBBiu/+saTycI0uuF2yPr14wTb2xUwMqgm8SNTlktKT7h6vs0twjdjimMMutVKa5Sx9u9dXig10Q=="
)

func TestHasher_BySha2_Hash(t *testing.T) {
	t.Run("hash string 224", func(t *testing.T) {
		hasher := NewHasher().FromString(string(sha2HashSrc)).BySha2(224)
		assert.Nil(t, hasher.Error)
		assert.Equal(t, sha2Hash224HexDst, hasher.ToHexString())
		assert.Equal(t, sha2Hash224Base64Dst, hasher.ToBase64String())
	})

	t.Run("hash string 256", func(t *testing.T) {
		hasher := NewHasher().FromString(string(sha2HashSrc)).BySha2(256)
		assert.Nil(t, hasher.Error)
		assert.Equal(t, sha2Hash256HexDst, hasher.ToHexString())
		assert.Equal(t, sha2Hash256Base64Dst, hasher.ToBase64String())
	})

	t.Run("hash string 384", func(t *testing.T) {
		hasher := NewHasher().FromString(string(sha2HashSrc)).BySha2(384)
		assert.Nil(t, hasher.Error)
		assert.Equal(t, sha2Hash384HexDst, hasher.ToHexString())
		assert.Equal(t, sha2Hash384Base64Dst, hasher.ToBase64String())
	})

	t.Run("hash string 512", func(t *testing.T) {
		hasher := NewHasher().FromString(string(sha2HashSrc)).BySha2(512)
		assert.Nil(t, hasher.Error)
		assert.Equal(t, sha2Hash512HexDst, hasher.ToHexString())
		assert.Equal(t, sha2Hash512Base64Dst, hasher.ToBase64String())
	})

	t.Run("hash bytes", func(t *testing.T) {
		hasher := NewHasher().FromBytes(sha2HashSrc).BySha2(256)
		assert.Nil(t, hasher.Error)
		assert.Equal(t, sha2Hash256HexDst, hasher.ToHexString())
		assert.Equal(t, sha2Hash256Base64Dst, hasher.ToBase64String())
	})

	t.Run("hash file", func(t *testing.T) {
		file := mock.NewFile(sha2HashSrc, "test.txt")
		hasher := NewHasher().FromFile(file).BySha2(256)
		assert.Nil(t, hasher.Error)
		assert.Equal(t, sha2Hash256HexDst, hasher.ToHexString())
		assert.Equal(t, sha2Hash256Base64Dst, hasher.ToBase64String())
	})

	t.Run("hash empty string 224", func(t *testing.T) {
		hasher := NewHasher().FromString("").BySha2(224)
		assert.Nil(t, hasher.Error)
		assert.Empty(t, hasher.ToHexString())
		assert.Empty(t, hasher.ToBase64String())
	})

	t.Run("hash empty string 256", func(t *testing.T) {
		hasher := NewHasher().FromString("").BySha2(256)
		assert.Nil(t, hasher.Error)
		assert.Empty(t, hasher.ToHexString())
		assert.Empty(t, hasher.ToBase64String())
	})

	t.Run("hash empty string 384", func(t *testing.T) {
		hasher := NewHasher().FromString("").BySha2(384)
		assert.Nil(t, hasher.Error)
		assert.Empty(t, hasher.ToHexString())
		assert.Empty(t, hasher.ToBase64String())
	})

	t.Run("hash empty string 512", func(t *testing.T) {
		hasher := NewHasher().FromString("").BySha2(512)
		assert.Nil(t, hasher.Error)
		assert.Empty(t, hasher.ToHexString())
		assert.Empty(t, hasher.ToBase64String())
	})

	t.Run("hash empty bytes", func(t *testing.T) {
		hasher := NewHasher().FromBytes([]byte{}).BySha2(256)
		assert.Nil(t, hasher.Error)
		assert.Empty(t, hasher.ToHexString())
		assert.Empty(t, hasher.ToBase64String())
	})

	t.Run("hash nil bytes", func(t *testing.T) {
		hasher := NewHasher().FromBytes(nil).BySha2(256)
		assert.Nil(t, hasher.Error)
		assert.Empty(t, hasher.ToHexString())
		assert.Empty(t, hasher.ToBase64String())
	})

	t.Run("hash large data", func(t *testing.T) {
		data := strings.Repeat("a", 10000)
		hasher := NewHasher().FromString(data).BySha2(256)
		assert.Nil(t, hasher.Error)
		assert.NotEmpty(t, hasher.ToHexString())
	})

	t.Run("hash unicode data", func(t *testing.T) {
		unicodeData := "你好世界"
		hasher := NewHasher().FromString(unicodeData).BySha2(256)
		assert.Nil(t, hasher.Error)
		assert.NotEmpty(t, hasher.ToHexString())
	})

	t.Run("hash binary data", func(t *testing.T) {
		binaryData := []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f}
		hasher := NewHasher().FromBytes(binaryData).BySha2(256)
		assert.Nil(t, hasher.Error)
		assert.NotEmpty(t, hasher.ToHexString())
	})

	t.Run("hash empty file", func(t *testing.T) {
		file := mock.NewFile([]byte{}, "empty.txt")
		hasher := NewHasher().FromFile(file).BySha2(256)
		assert.Nil(t, hasher.Error)
		assert.Empty(t, hasher.ToHexString())
		assert.Empty(t, hasher.ToBase64String())
	})

	t.Run("hash no data", func(t *testing.T) {
		hasher := NewHasher().BySha2(256)
		assert.Nil(t, hasher.Error)
		assert.Empty(t, hasher.ToHexString())
		assert.Empty(t, hasher.ToBase64String())
	})
}

func TestHasher_BySha2_HMAC(t *testing.T) {
	t.Run("hmac string 224", func(t *testing.T) {
		hasher := NewHasher().FromString(string(sha2HmacSrc)).WithKey(sha2HmacKey).BySha2(224)
		assert.Nil(t, hasher.Error)
		assert.Equal(t, sha2Hmac224HexDst, hasher.ToHexString())
		assert.Equal(t, sha2Hmac224Base64Dst, hasher.ToBase64String())
	})

	t.Run("hmac string 256", func(t *testing.T) {
		hasher := NewHasher().FromString(string(sha2HmacSrc)).WithKey(sha2HmacKey).BySha2(256)
		assert.Nil(t, hasher.Error)
		assert.Equal(t, sha2Hmac256HexDst, hasher.ToHexString())
		assert.Equal(t, sha2Hmac256Base64Dst, hasher.ToBase64String())
	})

	t.Run("hmac string 384", func(t *testing.T) {
		hasher := NewHasher().FromString(string(sha2HmacSrc)).WithKey(sha2HmacKey).BySha2(384)
		assert.Nil(t, hasher.Error)
		assert.Equal(t, sha2Hmac384HexDst, hasher.ToHexString())
		assert.Equal(t, sha2Hmac384Base64Dst, hasher.ToBase64String())
	})

	t.Run("hmac string 512", func(t *testing.T) {
		hasher := NewHasher().FromString(string(sha2HmacSrc)).WithKey(sha2HmacKey).BySha2(512)
		assert.Nil(t, hasher.Error)
		assert.Equal(t, sha2Hmac512HexDst, hasher.ToHexString())
		assert.Equal(t, sha2Hmac512Base64Dst, hasher.ToBase64String())
	})

	t.Run("hmac bytes", func(t *testing.T) {
		hasher := NewHasher().FromBytes(sha2HmacSrc).WithKey(sha2HmacKey).BySha2(256)
		assert.Nil(t, hasher.Error)
		assert.Equal(t, sha2Hmac256HexDst, hasher.ToHexString())
		assert.Equal(t, sha2Hmac256Base64Dst, hasher.ToBase64String())
	})

	t.Run("hmac file", func(t *testing.T) {
		file := mock.NewFile(sha2HmacSrc, "test.txt")
		hasher := NewHasher().FromFile(file).WithKey(sha2HmacKey).BySha2(256)
		assert.Nil(t, hasher.Error)
		assert.Equal(t, sha2Hmac256HexDst, hasher.ToHexString())
		assert.Equal(t, sha2Hmac256Base64Dst, hasher.ToBase64String())
	})

	t.Run("hmac empty string", func(t *testing.T) {
		hasher := NewHasher().FromString("").WithKey(sha2HmacKey).BySha2(256)
		assert.Nil(t, hasher.Error)
		assert.Empty(t, hasher.ToHexString())
	})

	t.Run("hmac empty bytes", func(t *testing.T) {
		hasher := NewHasher().FromBytes([]byte{}).WithKey(sha2HmacKey).BySha2(256)
		assert.Nil(t, hasher.Error)
		assert.Empty(t, hasher.ToHexString())
	})

	t.Run("hmac large data", func(t *testing.T) {
		data := strings.Repeat("a", 10000)
		hasher := NewHasher().FromString(data).WithKey(sha2HmacKey).BySha2(256)
		assert.Nil(t, hasher.Error)
		assert.NotEmpty(t, hasher.ToHexString())
	})

	t.Run("hmac unicode data", func(t *testing.T) {
		unicodeData := "你好世界"
		hasher := NewHasher().FromString(unicodeData).WithKey(sha2HmacKey).BySha2(256)
		assert.Nil(t, hasher.Error)
		assert.NotEmpty(t, hasher.ToHexString())
	})

	t.Run("hmac binary data", func(t *testing.T) {
		binaryData := []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f}
		hasher := NewHasher().FromBytes(binaryData).WithKey(sha2HmacKey).BySha2(256)
		assert.Nil(t, hasher.Error)
		assert.NotEmpty(t, hasher.ToHexString())
	})

	t.Run("hmac empty file", func(t *testing.T) {
		file := mock.NewFile([]byte{}, "empty.txt")
		hasher := NewHasher().FromFile(file).WithKey(sha2HmacKey).BySha2(256)
		assert.Nil(t, hasher.Error)
		assert.Empty(t, hasher.ToHexString())
	})

	t.Run("hmac with large key", func(t *testing.T) {
		largeKey := strings.Repeat("secret", 100)
		hasher := NewHasher().FromString(string(sha2HmacSrc)).WithKey([]byte(largeKey)).BySha2(256)
		assert.Nil(t, hasher.Error)
		assert.NotEmpty(t, hasher.ToHexString())
	})
}

func TestHasher_BySha2_Error(t *testing.T) {
	t.Run("existing error", func(t *testing.T) {
		hasher := NewHasher()
		hasher.Error = errors.New("existing error")
		result := hasher.BySha2(256)
		assert.Equal(t, hasher, result)
		assert.Equal(t, errors.New("existing error"), result.Error)
	})

	t.Run("unsupported size", func(t *testing.T) {
		hasher := NewHasher().FromString("hello").BySha2(128)
		assert.NotNil(t, hasher.Error)
		assert.Contains(t, hasher.Error.Error(), "unsupported size: 128")
		assert.Contains(t, hasher.Error.Error(), "supported sizes are 224, 256, 384, 512")
	})
}
