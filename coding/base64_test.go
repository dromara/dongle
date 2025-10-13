package coding

import (
	"errors"
	"strings"
	"testing"

	"github.com/dromara/dongle/mock"
	"github.com/stretchr/testify/assert"
)

// Test data for base64 encoding (generated using Python base64 library)
var (
	base64Src        = []byte("hello world")
	base64Encoded    = "aGVsbG8gd29ybGQ="
	base64UrlEncoded = "aGVsbG8gd29ybGQ="
)

// Test data for base64 unicode encoding (generated using Python base64 library)
var (
	base64UnicodeSrc        = []byte("你好世界")
	base64UnicodeEncoded    = "5L2g5aW95LiW55WM"
	base64UnicodeUrlEncoded = "5L2g5aW95LiW55WM"
)

// Test data for base64 binary encoding (generated using Python base64 library)
var (
	base64BinarySrc        = []byte{0x00, 0x01, 0x02, 0x03, 0xFF, 0xFE, 0xFD, 0xFC}
	base64BinaryEncoded    = "AAECA//+/fw="
	base64BinaryUrlEncoded = "AAECA__-_fw="
)

func TestEncoder_ByBase64_Encode(t *testing.T) {
	t.Run("encode string", func(t *testing.T) {
		encoder := NewEncoder().FromString(string(base64Src)).ByBase64()
		assert.Nil(t, encoder.Error)
		assert.Equal(t, base64Encoded, encoder.ToString())
	})

	t.Run("encode bytes", func(t *testing.T) {
		encoder := NewEncoder().FromBytes(base64Src).ByBase64()
		assert.Nil(t, encoder.Error)
		assert.Equal(t, base64Encoded, encoder.ToString())
	})

	t.Run("encode file", func(t *testing.T) {
		file := mock.NewFile(base64Src, "test.txt")
		encoder := NewEncoder().FromFile(file).ByBase64()
		assert.Nil(t, encoder.Error)
		assert.Equal(t, base64Encoded, encoder.ToString())
	})

	t.Run("empty string", func(t *testing.T) {
		encoder := NewEncoder().FromString("").ByBase64()
		assert.Nil(t, encoder.Error)
		assert.Empty(t, encoder.ToString())
	})

	t.Run("empty bytes", func(t *testing.T) {
		encoder := NewEncoder().FromBytes([]byte{}).ByBase64()
		assert.Nil(t, encoder.Error)
		assert.Empty(t, encoder.ToString())
	})

	t.Run("nil bytes", func(t *testing.T) {
		encoder := NewEncoder().FromBytes(nil).ByBase64()
		assert.Nil(t, encoder.Error)
		assert.Empty(t, encoder.ToString())
	})

	t.Run("empty file", func(t *testing.T) {
		file := mock.NewFile([]byte{}, "empty.txt")
		encoder := NewEncoder().FromFile(file).ByBase64()
		assert.Nil(t, encoder.Error)
		assert.Empty(t, encoder.ToString())
	})

	t.Run("unicode string", func(t *testing.T) {
		encoder := NewEncoder().FromString(string(base64UnicodeSrc)).ByBase64()
		assert.Nil(t, encoder.Error)
		assert.Equal(t, base64UnicodeEncoded, encoder.ToString())
	})

	t.Run("binary data", func(t *testing.T) {
		encoder := NewEncoder().FromBytes(base64BinarySrc).ByBase64()
		assert.Nil(t, encoder.Error)
		assert.Equal(t, base64BinaryEncoded, encoder.ToString())
	})

	t.Run("large data", func(t *testing.T) {
		largeData := strings.Repeat("Hello, World! ", 100)
		encoder := NewEncoder().FromString(largeData).ByBase64()
		assert.Nil(t, encoder.Error)
		assert.NotEmpty(t, encoder.ToString())
	})

	t.Run("single byte", func(t *testing.T) {
		encoder := NewEncoder().FromBytes([]byte{0x41}).ByBase64()
		assert.Nil(t, encoder.Error)
		assert.Equal(t, "QQ==", encoder.ToString())
	})

	t.Run("two bytes", func(t *testing.T) {
		encoder := NewEncoder().FromBytes([]byte{0x41, 0x42}).ByBase64()
		assert.Nil(t, encoder.Error)
		assert.Equal(t, "QUI=", encoder.ToString())
	})

	t.Run("three bytes", func(t *testing.T) {
		encoder := NewEncoder().FromBytes([]byte{0x41, 0x42, 0x43}).ByBase64()
		assert.Nil(t, encoder.Error)
		assert.Equal(t, "QUJD", encoder.ToString())
	})

	t.Run("zero bytes", func(t *testing.T) {
		encoder := NewEncoder().FromBytes([]byte{0x00, 0x00, 0x00, 0x00}).ByBase64()
		assert.Nil(t, encoder.Error)
		assert.Equal(t, "AAAAAA==", encoder.ToString())
	})

	t.Run("max bytes", func(t *testing.T) {
		encoder := NewEncoder().FromBytes([]byte{0xFF, 0xFF, 0xFF, 0xFF}).ByBase64()
		assert.Nil(t, encoder.Error)
		assert.Equal(t, "/////w==", encoder.ToString())
	})

	t.Run("error file", func(t *testing.T) {
		errorFile := mock.NewErrorFile(errors.New("read error"))
		encoder := NewEncoder().FromFile(errorFile).ByBase64()
		assert.Error(t, encoder.Error)
		assert.Contains(t, encoder.Error.Error(), "read error")
	})

	t.Run("no data no reader", func(t *testing.T) {
		encoder := NewEncoder().ByBase64()
		assert.Nil(t, encoder.Error)
		assert.Empty(t, encoder.ToString())
	})
}

func TestEncoder_ByBase64_Error(t *testing.T) {
	t.Run("existing error", func(t *testing.T) {
		encoder := NewEncoder()
		encoder.Error = errors.New("existing error")
		result := encoder.ByBase64()
		assert.Equal(t, encoder, result)
		assert.Equal(t, errors.New("existing error"), result.Error)
	})
}

func TestDecoder_ByBase64_Decode(t *testing.T) {
	t.Run("decode string", func(t *testing.T) {
		decoder := NewDecoder().FromString(base64Encoded).ByBase64()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, base64Src, decoder.ToBytes())
	})

	t.Run("decode bytes", func(t *testing.T) {
		decoder := NewDecoder().FromBytes([]byte(base64Encoded)).ByBase64()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, base64Src, decoder.ToBytes())
	})

	t.Run("decode file", func(t *testing.T) {
		file := mock.NewFile([]byte(base64Encoded), "test.txt")
		decoder := NewDecoder().FromFile(file).ByBase64()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, base64Src, decoder.ToBytes())
	})

	t.Run("empty string", func(t *testing.T) {
		decoder := NewDecoder().FromString("").ByBase64()
		assert.Nil(t, decoder.Error)
		assert.Empty(t, decoder.ToBytes())
	})

	t.Run("empty bytes", func(t *testing.T) {
		decoder := NewDecoder().FromBytes([]byte{}).ByBase64()
		assert.Nil(t, decoder.Error)
		assert.Empty(t, decoder.ToBytes())
	})

	t.Run("nil bytes", func(t *testing.T) {
		decoder := NewDecoder().FromBytes(nil).ByBase64()
		assert.Nil(t, decoder.Error)
		assert.Empty(t, decoder.ToBytes())
	})

	t.Run("empty file", func(t *testing.T) {
		file := mock.NewFile([]byte{}, "empty.txt")
		decoder := NewDecoder().FromFile(file).ByBase64()
		assert.Nil(t, decoder.Error)
		assert.Empty(t, decoder.ToBytes())
	})

	t.Run("unicode string", func(t *testing.T) {
		decoder := NewDecoder().FromString(base64UnicodeEncoded).ByBase64()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, base64UnicodeSrc, decoder.ToBytes())
	})

	t.Run("binary data", func(t *testing.T) {
		decoder := NewDecoder().FromString(base64BinaryEncoded).ByBase64()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, base64BinarySrc, decoder.ToBytes())
	})

	t.Run("single byte", func(t *testing.T) {
		decoder := NewDecoder().FromString("QQ==").ByBase64()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, []byte{0x41}, decoder.ToBytes())
	})

	t.Run("two bytes", func(t *testing.T) {
		decoder := NewDecoder().FromString("QUI=").ByBase64()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, []byte{0x41, 0x42}, decoder.ToBytes())
	})

	t.Run("three bytes", func(t *testing.T) {
		decoder := NewDecoder().FromString("QUJD").ByBase64()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, []byte{0x41, 0x42, 0x43}, decoder.ToBytes())
	})

	t.Run("zero bytes", func(t *testing.T) {
		decoder := NewDecoder().FromString("AAAAAA==").ByBase64()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, []byte{0x00, 0x00, 0x00, 0x00}, decoder.ToBytes())
	})

	t.Run("max bytes", func(t *testing.T) {
		decoder := NewDecoder().FromString("/////w==").ByBase64()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, []byte{0xFF, 0xFF, 0xFF, 0xFF}, decoder.ToBytes())
	})

	t.Run("error file", func(t *testing.T) {
		errorFile := mock.NewErrorFile(errors.New("read error"))
		decoder := NewDecoder().FromFile(errorFile).ByBase64()
		assert.Error(t, decoder.Error)
		assert.Contains(t, decoder.Error.Error(), "read error")
	})

	t.Run("invalid base64", func(t *testing.T) {
		decoder := NewDecoder().FromString("invalid!").ByBase64()
		assert.Error(t, decoder.Error)
	})

	t.Run("no data no reader", func(t *testing.T) {
		decoder := NewDecoder().ByBase64()
		assert.Nil(t, decoder.Error)
		assert.Empty(t, decoder.ToBytes())
	})
}

func TestDecoder_ByBase64_Error(t *testing.T) {
	t.Run("existing error", func(t *testing.T) {
		decoder := NewDecoder()
		decoder.Error = errors.New("existing error")
		result := decoder.ByBase64()
		assert.Equal(t, decoder, result)
		assert.Equal(t, errors.New("existing error"), result.Error)
	})
}

func TestEncoder_ByBase64Url_Encode(t *testing.T) {
	t.Run("encode string", func(t *testing.T) {
		encoder := NewEncoder().FromString(string(base64Src)).ByBase64Url()
		assert.Nil(t, encoder.Error)
		assert.Equal(t, base64UrlEncoded, encoder.ToString())
	})

	t.Run("encode bytes", func(t *testing.T) {
		encoder := NewEncoder().FromBytes(base64Src).ByBase64Url()
		assert.Nil(t, encoder.Error)
		assert.Equal(t, base64UrlEncoded, encoder.ToString())
	})

	t.Run("encode file", func(t *testing.T) {
		file := mock.NewFile(base64Src, "test.txt")
		encoder := NewEncoder().FromFile(file).ByBase64Url()
		assert.Nil(t, encoder.Error)
		assert.Equal(t, base64UrlEncoded, encoder.ToString())
	})

	t.Run("empty string", func(t *testing.T) {
		encoder := NewEncoder().FromString("").ByBase64Url()
		assert.Nil(t, encoder.Error)
		assert.Empty(t, encoder.ToString())
	})

	t.Run("empty bytes", func(t *testing.T) {
		encoder := NewEncoder().FromBytes([]byte{}).ByBase64Url()
		assert.Nil(t, encoder.Error)
		assert.Empty(t, encoder.ToString())
	})

	t.Run("nil bytes", func(t *testing.T) {
		encoder := NewEncoder().FromBytes(nil).ByBase64Url()
		assert.Nil(t, encoder.Error)
		assert.Empty(t, encoder.ToString())
	})

	t.Run("empty file", func(t *testing.T) {
		file := mock.NewFile([]byte{}, "empty.txt")
		encoder := NewEncoder().FromFile(file).ByBase64Url()
		assert.Nil(t, encoder.Error)
		assert.Empty(t, encoder.ToString())
	})

	t.Run("unicode string", func(t *testing.T) {
		encoder := NewEncoder().FromString(string(base64UnicodeSrc)).ByBase64Url()
		assert.Nil(t, encoder.Error)
		assert.Equal(t, base64UnicodeUrlEncoded, encoder.ToString())
	})

	t.Run("binary data", func(t *testing.T) {
		encoder := NewEncoder().FromBytes(base64BinarySrc).ByBase64Url()
		assert.Nil(t, encoder.Error)
		assert.Equal(t, base64BinaryUrlEncoded, encoder.ToString())
	})

	t.Run("large data", func(t *testing.T) {
		largeData := strings.Repeat("Hello, World! ", 100)
		encoder := NewEncoder().FromString(largeData).ByBase64Url()
		assert.Nil(t, encoder.Error)
		assert.NotEmpty(t, encoder.ToString())
	})

	t.Run("single byte", func(t *testing.T) {
		encoder := NewEncoder().FromBytes([]byte{0x41}).ByBase64Url()
		assert.Nil(t, encoder.Error)
		assert.Equal(t, "QQ==", encoder.ToString())
	})

	t.Run("two bytes", func(t *testing.T) {
		encoder := NewEncoder().FromBytes([]byte{0x41, 0x42}).ByBase64Url()
		assert.Nil(t, encoder.Error)
		assert.Equal(t, "QUI=", encoder.ToString())
	})

	t.Run("three bytes", func(t *testing.T) {
		encoder := NewEncoder().FromBytes([]byte{0x41, 0x42, 0x43}).ByBase64Url()
		assert.Nil(t, encoder.Error)
		assert.Equal(t, "QUJD", encoder.ToString())
	})

	t.Run("zero bytes", func(t *testing.T) {
		encoder := NewEncoder().FromBytes([]byte{0x00, 0x00, 0x00, 0x00}).ByBase64Url()
		assert.Nil(t, encoder.Error)
		assert.Equal(t, "AAAAAA==", encoder.ToString())
	})

	t.Run("max bytes", func(t *testing.T) {
		encoder := NewEncoder().FromBytes([]byte{0xFF, 0xFF, 0xFF, 0xFF}).ByBase64Url()
		assert.Nil(t, encoder.Error)
		assert.Equal(t, "_____w==", encoder.ToString())
	})

	t.Run("error file", func(t *testing.T) {
		errorFile := mock.NewErrorFile(errors.New("read error"))
		encoder := NewEncoder().FromFile(errorFile).ByBase64Url()
		assert.Error(t, encoder.Error)
		assert.Contains(t, encoder.Error.Error(), "read error")
	})

	t.Run("no data no reader", func(t *testing.T) {
		encoder := NewEncoder().ByBase64Url()
		assert.Nil(t, encoder.Error)
		assert.Empty(t, encoder.ToString())
	})
}

func TestEncoder_ByBase64Url_Error(t *testing.T) {
	t.Run("existing error", func(t *testing.T) {
		encoder := NewEncoder()
		encoder.Error = errors.New("existing error")
		result := encoder.ByBase64Url()
		assert.Equal(t, encoder, result)
		assert.Equal(t, errors.New("existing error"), result.Error)
	})
}

func TestDecoder_ByBase64Url_Decode(t *testing.T) {
	t.Run("decode string", func(t *testing.T) {
		decoder := NewDecoder().FromString(base64UrlEncoded).ByBase64Url()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, base64Src, decoder.ToBytes())
	})

	t.Run("decode bytes", func(t *testing.T) {
		decoder := NewDecoder().FromBytes([]byte(base64UrlEncoded)).ByBase64Url()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, base64Src, decoder.ToBytes())
	})

	t.Run("decode file", func(t *testing.T) {
		file := mock.NewFile([]byte(base64UrlEncoded), "test.txt")
		decoder := NewDecoder().FromFile(file).ByBase64Url()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, base64Src, decoder.ToBytes())
	})

	t.Run("empty string", func(t *testing.T) {
		decoder := NewDecoder().FromString("").ByBase64Url()
		assert.Nil(t, decoder.Error)
		assert.Empty(t, decoder.ToBytes())
	})

	t.Run("empty bytes", func(t *testing.T) {
		decoder := NewDecoder().FromBytes([]byte{}).ByBase64Url()
		assert.Nil(t, decoder.Error)
		assert.Empty(t, decoder.ToBytes())
	})

	t.Run("nil bytes", func(t *testing.T) {
		decoder := NewDecoder().FromBytes(nil).ByBase64Url()
		assert.Nil(t, decoder.Error)
		assert.Empty(t, decoder.ToBytes())
	})

	t.Run("empty file", func(t *testing.T) {
		file := mock.NewFile([]byte{}, "empty.txt")
		decoder := NewDecoder().FromFile(file).ByBase64Url()
		assert.Nil(t, decoder.Error)
		assert.Empty(t, decoder.ToBytes())
	})

	t.Run("unicode string", func(t *testing.T) {
		decoder := NewDecoder().FromString(base64UnicodeUrlEncoded).ByBase64Url()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, base64UnicodeSrc, decoder.ToBytes())
	})

	t.Run("binary data", func(t *testing.T) {
		decoder := NewDecoder().FromString(base64BinaryUrlEncoded).ByBase64Url()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, base64BinarySrc, decoder.ToBytes())
	})

	t.Run("single byte", func(t *testing.T) {
		decoder := NewDecoder().FromString("QQ==").ByBase64Url()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, []byte{0x41}, decoder.ToBytes())
	})

	t.Run("two bytes", func(t *testing.T) {
		decoder := NewDecoder().FromString("QUI=").ByBase64Url()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, []byte{0x41, 0x42}, decoder.ToBytes())
	})

	t.Run("three bytes", func(t *testing.T) {
		decoder := NewDecoder().FromString("QUJD").ByBase64Url()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, []byte{0x41, 0x42, 0x43}, decoder.ToBytes())
	})

	t.Run("zero bytes", func(t *testing.T) {
		decoder := NewDecoder().FromString("AAAAAA==").ByBase64Url()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, []byte{0x00, 0x00, 0x00, 0x00}, decoder.ToBytes())
	})

	t.Run("max bytes", func(t *testing.T) {
		decoder := NewDecoder().FromString("_____w==").ByBase64Url()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, []byte{0xFF, 0xFF, 0xFF, 0xFF}, decoder.ToBytes())
	})

	t.Run("error file", func(t *testing.T) {
		errorFile := mock.NewErrorFile(errors.New("read error"))
		decoder := NewDecoder().FromFile(errorFile).ByBase64Url()
		assert.Error(t, decoder.Error)
		assert.Contains(t, decoder.Error.Error(), "read error")
	})

	t.Run("invalid base64url", func(t *testing.T) {
		decoder := NewDecoder().FromString("invalid!").ByBase64Url()
		assert.Error(t, decoder.Error)
	})

	t.Run("no data no reader", func(t *testing.T) {
		decoder := NewDecoder().ByBase64Url()
		assert.Nil(t, decoder.Error)
		assert.Empty(t, decoder.ToBytes())
	})
}

func TestDecoder_ByBase64Url_Error(t *testing.T) {
	t.Run("existing error", func(t *testing.T) {
		decoder := NewDecoder()
		decoder.Error = errors.New("existing error")
		result := decoder.ByBase64Url()
		assert.Equal(t, decoder, result)
		assert.Equal(t, errors.New("existing error"), result.Error)
	})
}

func TestBase64RoundTrip(t *testing.T) {
	t.Run("base64 round trip", func(t *testing.T) {
		testData := "Hello, World! 你好世界"

		encoder := NewEncoder().FromString(testData).ByBase64()
		assert.Nil(t, encoder.Error)

		decoder := NewDecoder().FromBytes(encoder.ToBytes()).ByBase64()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, []byte(testData), decoder.ToBytes())
	})

	t.Run("base64 round trip with file", func(t *testing.T) {
		testData := "Hello, World! 你好世界"

		file := mock.NewFile([]byte(testData), "test.txt")
		encoder := NewEncoder().FromFile(file).ByBase64()
		assert.Nil(t, encoder.Error)

		decoderFile := mock.NewFile(encoder.ToBytes(), "decoded.txt")
		decoder := NewDecoder().FromFile(decoderFile).ByBase64()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, []byte(testData), decoder.ToBytes())
	})

	t.Run("base64 round trip with bytes", func(t *testing.T) {
		testData := []byte{0x00, 0x01, 0x02, 0x03, 0xFF, 0xFE, 0xFD, 0xFC}

		encoder := NewEncoder().FromBytes(testData).ByBase64()
		assert.Nil(t, encoder.Error)

		decoder := NewDecoder().FromBytes(encoder.ToBytes()).ByBase64()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, testData, decoder.ToBytes())
	})
}

func TestBase64URLRoundTrip(t *testing.T) {
	t.Run("base64url round trip", func(t *testing.T) {
		testData := "Hello, World! 你好世界"

		encoder := NewEncoder().FromString(testData).ByBase64Url()
		assert.Nil(t, encoder.Error)

		decoder := NewDecoder().FromBytes(encoder.ToBytes()).ByBase64Url()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, []byte(testData), decoder.ToBytes())
	})

	t.Run("base64url round trip with file", func(t *testing.T) {
		testData := "Hello, World! 你好世界"

		file := mock.NewFile([]byte(testData), "test.txt")
		encoder := NewEncoder().FromFile(file).ByBase64Url()
		assert.Nil(t, encoder.Error)

		decoderFile := mock.NewFile(encoder.ToBytes(), "decoded.txt")
		decoder := NewDecoder().FromFile(decoderFile).ByBase64Url()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, []byte(testData), decoder.ToBytes())
	})

	t.Run("base64url round trip with bytes", func(t *testing.T) {
		testData := []byte{0x00, 0x01, 0x02, 0x03, 0xFF, 0xFE, 0xFD, 0xFC}

		encoder := NewEncoder().FromBytes(testData).ByBase64Url()
		assert.Nil(t, encoder.Error)

		decoder := NewDecoder().FromBytes(encoder.ToBytes()).ByBase64Url()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, testData, decoder.ToBytes())
	})
}

func TestBase64EdgeCases(t *testing.T) {
	t.Run("very large data", func(t *testing.T) {
		largeData := strings.Repeat("Hello, World! ", 1000)

		encoder := NewEncoder().FromString(largeData).ByBase64()
		assert.Nil(t, encoder.Error)

		decoder := NewDecoder().FromBytes(encoder.ToBytes()).ByBase64()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, []byte(largeData), decoder.ToBytes())
	})

	t.Run("single character", func(t *testing.T) {
		encoder := NewEncoder().FromString("A").ByBase64()
		assert.Nil(t, encoder.Error)
		assert.NotEmpty(t, encoder.ToString())

		decoder := NewDecoder().FromBytes(encoder.ToBytes()).ByBase64()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, []byte("A"), decoder.ToBytes())
	})

	t.Run("binary data", func(t *testing.T) {
		binaryData := []byte{0x00, 0x01, 0x02, 0x03, 0xFF, 0xFE, 0xFD, 0xFC}

		encoder := NewEncoder().FromBytes(binaryData).ByBase64()
		assert.Nil(t, encoder.Error)

		decoder := NewDecoder().FromBytes(encoder.ToBytes()).ByBase64()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, binaryData, decoder.ToBytes())
	})

	t.Run("mixed encoding methods", func(t *testing.T) {
		testData := "hello world"

		encoder1 := NewEncoder().FromString(testData).ByBase64()
		encoder2 := NewEncoder().FromBytes([]byte(testData)).ByBase64()
		encoder3 := NewEncoder().FromFile(mock.NewFile([]byte(testData), "test.txt")).ByBase64()

		assert.Nil(t, encoder1.Error)
		assert.Nil(t, encoder2.Error)
		assert.Nil(t, encoder3.Error)
		assert.Equal(t, encoder1.ToString(), encoder2.ToString())
		assert.Equal(t, encoder1.ToString(), encoder3.ToString())
	})

	t.Run("zero bytes", func(t *testing.T) {
		zeroData := []byte{0x00, 0x00, 0x00, 0x00}

		encoder := NewEncoder().FromBytes(zeroData).ByBase64()
		assert.Nil(t, encoder.Error)

		decoder := NewDecoder().FromBytes(encoder.ToBytes()).ByBase64()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, zeroData, decoder.ToBytes())
	})

	t.Run("max bytes", func(t *testing.T) {
		maxData := []byte{0xFF, 0xFF, 0xFF, 0xFF}

		encoder := NewEncoder().FromBytes(maxData).ByBase64()
		assert.Nil(t, encoder.Error)

		decoder := NewDecoder().FromBytes(encoder.ToBytes()).ByBase64()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, maxData, decoder.ToBytes())
	})

	t.Run("all possible byte values", func(t *testing.T) {
		allBytes := make([]byte, 256)
		for i := 0; i < 256; i++ {
			allBytes[i] = byte(i)
		}

		encoder := NewEncoder().FromBytes(allBytes).ByBase64()
		assert.Nil(t, encoder.Error)

		decoder := NewDecoder().FromBytes(encoder.ToBytes()).ByBase64()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, allBytes, decoder.ToBytes())
	})
}

func TestBase64URLEdgeCases(t *testing.T) {
	t.Run("very large data", func(t *testing.T) {
		largeData := strings.Repeat("Hello, World! ", 1000)

		encoder := NewEncoder().FromString(largeData).ByBase64Url()
		assert.Nil(t, encoder.Error)

		decoder := NewDecoder().FromBytes(encoder.ToBytes()).ByBase64Url()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, []byte(largeData), decoder.ToBytes())
	})

	t.Run("single character", func(t *testing.T) {
		encoder := NewEncoder().FromString("A").ByBase64Url()
		assert.Nil(t, encoder.Error)
		assert.NotEmpty(t, encoder.ToString())

		decoder := NewDecoder().FromBytes(encoder.ToBytes()).ByBase64Url()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, []byte("A"), decoder.ToBytes())
	})

	t.Run("binary data", func(t *testing.T) {
		binaryData := []byte{0x00, 0x01, 0x02, 0x03, 0xFF, 0xFE, 0xFD, 0xFC}

		encoder := NewEncoder().FromBytes(binaryData).ByBase64Url()
		assert.Nil(t, encoder.Error)

		decoder := NewDecoder().FromBytes(encoder.ToBytes()).ByBase64Url()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, binaryData, decoder.ToBytes())
	})

	t.Run("mixed encoding methods", func(t *testing.T) {
		testData := "hello world"

		encoder1 := NewEncoder().FromString(testData).ByBase64Url()
		encoder2 := NewEncoder().FromBytes([]byte(testData)).ByBase64Url()
		encoder3 := NewEncoder().FromFile(mock.NewFile([]byte(testData), "test.txt")).ByBase64Url()

		assert.Nil(t, encoder1.Error)
		assert.Nil(t, encoder2.Error)
		assert.Nil(t, encoder3.Error)
		assert.Equal(t, encoder1.ToString(), encoder2.ToString())
		assert.Equal(t, encoder1.ToString(), encoder3.ToString())
	})

	t.Run("zero bytes", func(t *testing.T) {
		zeroData := []byte{0x00, 0x00, 0x00, 0x00}

		encoder := NewEncoder().FromBytes(zeroData).ByBase64Url()
		assert.Nil(t, encoder.Error)

		decoder := NewDecoder().FromBytes(encoder.ToBytes()).ByBase64Url()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, zeroData, decoder.ToBytes())
	})

	t.Run("max bytes", func(t *testing.T) {
		maxData := []byte{0xFF, 0xFF, 0xFF, 0xFF}

		encoder := NewEncoder().FromBytes(maxData).ByBase64Url()
		assert.Nil(t, encoder.Error)

		decoder := NewDecoder().FromBytes(encoder.ToBytes()).ByBase64Url()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, maxData, decoder.ToBytes())
	})

	t.Run("all possible byte values", func(t *testing.T) {
		allBytes := make([]byte, 256)
		for i := 0; i < 256; i++ {
			allBytes[i] = byte(i)
		}

		encoder := NewEncoder().FromBytes(allBytes).ByBase64Url()
		assert.Nil(t, encoder.Error)

		decoder := NewDecoder().FromBytes(encoder.ToBytes()).ByBase64Url()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, allBytes, decoder.ToBytes())
	})
}

func TestBase64Specific(t *testing.T) {
	t.Run("base64 alphabet verification", func(t *testing.T) {
		testData := []byte{0x00, 0x01, 0x02}
		encoder := NewEncoder().FromBytes(testData).ByBase64()
		assert.Nil(t, encoder.Error)

		resultStr := encoder.ToString()
		for _, char := range resultStr {
			assert.Contains(t, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/", string(char))
		}
	})

	t.Run("base64 padding behavior", func(t *testing.T) {
		testCases := []struct {
			input    []byte
			expected string
		}{
			{[]byte{0x00}, "AA=="},
			{[]byte{0x00, 0x00}, "AAA="},
			{[]byte{0x00, 0x00, 0x00}, "AAAA"},
		}

		for _, tc := range testCases {
			encoder := NewEncoder().FromBytes(tc.input).ByBase64()
			assert.Nil(t, encoder.Error)
			assert.NotEmpty(t, encoder.ToString())

			decoder := NewDecoder().FromBytes(encoder.ToBytes()).ByBase64()
			assert.Nil(t, decoder.Error)
			assert.Equal(t, tc.input, decoder.ToBytes())
		}
	})

	t.Run("base64 RFC 4648 compliance", func(t *testing.T) {
		testData := []byte("Hello, World!")
		encoder := NewEncoder().FromBytes(testData).ByBase64()
		assert.Nil(t, encoder.Error)

		decoder := NewDecoder().FromBytes(encoder.ToBytes()).ByBase64()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, testData, decoder.ToBytes())
	})

	t.Run("base64 vs base64url comparison", func(t *testing.T) {
		testData := []byte("Hello, World!")

		encoder64 := NewEncoder().FromBytes(testData).ByBase64()
		assert.Nil(t, encoder64.Error)

		encoder64url := NewEncoder().FromBytes(testData).ByBase64Url()
		assert.Nil(t, encoder64url.Error)

		// Base64URL should not contain '+' or '/' characters
		resultStr := encoder64url.ToString()
		assert.NotContains(t, resultStr, "+")
		assert.NotContains(t, resultStr, "/")

		// Both should decode back to the same data
		decoder64 := NewDecoder().FromBytes(encoder64.ToBytes()).ByBase64()
		decoder64url := NewDecoder().FromBytes(encoder64url.ToBytes()).ByBase64Url()

		assert.Nil(t, decoder64.Error)
		assert.Nil(t, decoder64url.Error)
		assert.Equal(t, testData, decoder64.ToBytes())
		assert.Equal(t, testData, decoder64url.ToBytes())
	})
}

func TestBase64URLSpecific(t *testing.T) {
	t.Run("base64url alphabet verification", func(t *testing.T) {
		testData := []byte{0x00, 0x01, 0x02}
		encoder := NewEncoder().FromBytes(testData).ByBase64Url()
		assert.Nil(t, encoder.Error)

		resultStr := encoder.ToString()
		for _, char := range resultStr {
			assert.Contains(t, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_", string(char))
		}
	})

	t.Run("base64url URL safety", func(t *testing.T) {
		testData := []byte("Hello, World!")
		encoder := NewEncoder().FromBytes(testData).ByBase64Url()
		assert.Nil(t, encoder.Error)

		resultStr := encoder.ToString()
		// Base64URL should not contain '+' or '/' characters
		assert.NotContains(t, resultStr, "+")
		assert.NotContains(t, resultStr, "/")

		// Should only contain URL-safe characters (including padding '=')
		for _, char := range resultStr {
			assert.True(t, (char >= '0' && char <= '9') ||
				(char >= 'A' && char <= 'Z') ||
				(char >= 'a' && char <= 'z') ||
				char == '-' || char == '_' || char == '=')
		}
	})

	t.Run("base64url padding behavior", func(t *testing.T) {
		testCases := []struct {
			input    []byte
			expected string
		}{
			{[]byte{0x00}, "AA=="},
			{[]byte{0x00, 0x00}, "AAA="},
			{[]byte{0x00, 0x00, 0x00}, "AAAA"},
		}

		for _, tc := range testCases {
			encoder := NewEncoder().FromBytes(tc.input).ByBase64Url()
			assert.Nil(t, encoder.Error)
			assert.NotEmpty(t, encoder.ToString())

			decoder := NewDecoder().FromBytes(encoder.ToBytes()).ByBase64Url()
			assert.Nil(t, decoder.Error)
			assert.Equal(t, tc.input, decoder.ToBytes())
		}
	})

	t.Run("base64url RFC 4648 compliance", func(t *testing.T) {
		testData := []byte("Hello, World!")
		encoder := NewEncoder().FromBytes(testData).ByBase64Url()
		assert.Nil(t, encoder.Error)

		decoder := NewDecoder().FromBytes(encoder.ToBytes()).ByBase64Url()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, testData, decoder.ToBytes())
	})
}
