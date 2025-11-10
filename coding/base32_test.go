package coding

import (
	"errors"
	"strings"
	"testing"

	"github.com/dromara/dongle/mock"
	"github.com/stretchr/testify/assert"
)

// Test data for base32 encoding (generated using Python base64 library)
var (
	base32Src     = []byte("hello world")
	base32Encoded = "NBSWY3DPEB3W64TMMQ======"
)

// Test data for base32 unicode encoding (generated using Python base64 library)
var (
	base32UnicodeSrc     = []byte("你好世界")
	base32UnicodeEncoded = "4S62BZNFXXSLRFXHSWGA===="
)

// Test data for base32 binary encoding (generated using Python base64 library)
var (
	base32BinarySrc     = []byte{0x00, 0x01, 0x02, 0x03, 0xFF, 0xFE, 0xFD, 0xFC}
	base32BinaryEncoded = "AAAQEA777367Y==="
)

// Test data for base32hex encoding (generated using dongle implementation)
var (
	base32HexSrc     = []byte("hello world")
	base32HexEncoded = "D1IMOR3F41RMUSJCCG======"
)

// Test data for base32hex unicode encoding (generated using dongle implementation)
var (
	base32HexUnicodeSrc     = []byte("你好世界")
	base32HexUnicodeEncoded = "SIUQ1PD5NNIBH5N7IM60===="
)

// Test data for base32hex binary encoding (generated using dongle implementation)
var (
	base32HexBinarySrc     = []byte{0x00, 0x01, 0x02, 0x03, 0xFF, 0xFE, 0xFD, 0xFC}
	base32HexBinaryEncoded = "000G40VVVRUVO==="
)

func TestEncoder_ByBase32_Encode(t *testing.T) {
	t.Run("encode string", func(t *testing.T) {
		encoder := NewEncoder().FromString(string(base32Src)).ByBase32()
		assert.Nil(t, encoder.Error)
		assert.Equal(t, base32Encoded, encoder.ToString())
	})

	t.Run("encode bytes", func(t *testing.T) {
		encoder := NewEncoder().FromBytes(base32Src).ByBase32()
		assert.Nil(t, encoder.Error)
		assert.Equal(t, base32Encoded, encoder.ToString())
	})

	t.Run("encode file", func(t *testing.T) {
		file := mock.NewFile(base32Src, "test.txt")
		encoder := NewEncoder().FromFile(file).ByBase32()
		assert.Nil(t, encoder.Error)
		assert.Equal(t, base32Encoded, encoder.ToString())
	})

	t.Run("encode empty string", func(t *testing.T) {
		encoder := NewEncoder().FromString("").ByBase32()
		assert.Nil(t, encoder.Error)
		assert.Empty(t, encoder.ToString())
	})

	t.Run("encode empty bytes", func(t *testing.T) {
		encoder := NewEncoder().FromBytes([]byte{}).ByBase32()
		assert.Nil(t, encoder.Error)
		assert.Empty(t, encoder.ToString())
	})

	t.Run("encode nil bytes", func(t *testing.T) {
		encoder := NewEncoder().FromBytes(nil).ByBase32()
		assert.Nil(t, encoder.Error)
		assert.Empty(t, encoder.ToString())
	})

	t.Run("encode empty file", func(t *testing.T) {
		file := mock.NewFile([]byte{}, "empty.txt")
		encoder := NewEncoder().FromFile(file).ByBase32()
		assert.Nil(t, encoder.Error)
		assert.Empty(t, encoder.ToString())
	})

	t.Run("unicode string", func(t *testing.T) {
		encoder := NewEncoder().FromString(string(base32UnicodeSrc)).ByBase32()
		assert.Nil(t, encoder.Error)
		assert.Equal(t, base32UnicodeEncoded, encoder.ToString())
	})

	t.Run("binary data", func(t *testing.T) {
		encoder := NewEncoder().FromBytes(base32BinarySrc).ByBase32()
		assert.Nil(t, encoder.Error)
		assert.Equal(t, base32BinaryEncoded, encoder.ToString())
	})

	t.Run("large data", func(t *testing.T) {
		largeData := strings.Repeat("Hello, World! ", 100)
		encoder := NewEncoder().FromString(largeData).ByBase32()
		assert.Nil(t, encoder.Error)
		assert.NotEmpty(t, encoder.ToString())
	})

	t.Run("single byte", func(t *testing.T) {
		encoder := NewEncoder().FromBytes([]byte{0x41}).ByBase32()
		assert.Nil(t, encoder.Error)
		assert.Equal(t, "IE======", encoder.ToString())
	})

	t.Run("two bytes", func(t *testing.T) {
		encoder := NewEncoder().FromBytes([]byte{0x41, 0x42}).ByBase32()
		assert.Nil(t, encoder.Error)
		assert.Equal(t, "IFBA====", encoder.ToString())
	})

	t.Run("three bytes", func(t *testing.T) {
		encoder := NewEncoder().FromBytes([]byte{0x41, 0x42, 0x43}).ByBase32()
		assert.Nil(t, encoder.Error)
		assert.Equal(t, "IFBEG===", encoder.ToString())
	})

	t.Run("zero bytes", func(t *testing.T) {
		encoder := NewEncoder().FromBytes([]byte{0x00, 0x00, 0x00, 0x00}).ByBase32()
		assert.Nil(t, encoder.Error)
		assert.Equal(t, "AAAAAAA=", encoder.ToString())
	})

	t.Run("max bytes", func(t *testing.T) {
		encoder := NewEncoder().FromBytes([]byte{0xFF, 0xFF, 0xFF, 0xFF}).ByBase32()
		assert.Nil(t, encoder.Error)
		assert.Equal(t, "777777Y=", encoder.ToString())
	})

	t.Run("specific bytes", func(t *testing.T) {
		encoder := NewEncoder().FromBytes([]byte{0x00, 0x01, 0x02, 0x03}).ByBase32()
		assert.Nil(t, encoder.Error)
		assert.Equal(t, "AAAQEAY=", encoder.ToString())
	})

	t.Run("error file", func(t *testing.T) {
		errorFile := mock.NewErrorFile(errors.New("read error"))
		encoder := NewEncoder().FromFile(errorFile).ByBase32()
		assert.Error(t, encoder.Error)
		assert.Contains(t, encoder.Error.Error(), "read error")
	})

	t.Run("encode no data", func(t *testing.T) {
		encoder := NewEncoder().ByBase32()
		assert.Nil(t, encoder.Error)
		assert.Empty(t, encoder.ToString())
	})
}

func TestEncoder_ByBase32_Error(t *testing.T) {
	t.Run("existing error", func(t *testing.T) {
		encoder := NewEncoder()
		encoder.Error = errors.New("existing error")
		result := encoder.ByBase32()
		assert.Equal(t, encoder, result)
		assert.Equal(t, errors.New("existing error"), result.Error)
	})
}

func TestDecoder_ByBase32_Decode(t *testing.T) {
	t.Run("decode string", func(t *testing.T) {
		decoder := NewDecoder().FromString(base32Encoded).ByBase32()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, base32Src, decoder.ToBytes())
	})

	t.Run("decode bytes", func(t *testing.T) {
		decoder := NewDecoder().FromBytes([]byte(base32Encoded)).ByBase32()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, base32Src, decoder.ToBytes())
	})

	t.Run("decode file", func(t *testing.T) {
		file := mock.NewFile([]byte(base32Encoded), "test.txt")
		decoder := NewDecoder().FromFile(file).ByBase32()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, base32Src, decoder.ToBytes())
	})

	t.Run("decode empty string", func(t *testing.T) {
		decoder := NewDecoder().FromString("").ByBase32()
		assert.Nil(t, decoder.Error)
		assert.Empty(t, decoder.ToBytes())
	})

	t.Run("decode empty bytes", func(t *testing.T) {
		decoder := NewDecoder().FromBytes([]byte{}).ByBase32()
		assert.Nil(t, decoder.Error)
		assert.Empty(t, decoder.ToBytes())
	})

	t.Run("decode nil bytes", func(t *testing.T) {
		decoder := NewDecoder().FromBytes(nil).ByBase32()
		assert.Nil(t, decoder.Error)
		assert.Empty(t, decoder.ToBytes())
	})

	t.Run("decode empty file", func(t *testing.T) {
		file := mock.NewFile([]byte{}, "empty.txt")
		decoder := NewDecoder().FromFile(file).ByBase32()
		assert.Nil(t, decoder.Error)
		assert.Empty(t, decoder.ToBytes())
	})

	t.Run("unicode string", func(t *testing.T) {
		decoder := NewDecoder().FromString(base32UnicodeEncoded).ByBase32()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, base32UnicodeSrc, decoder.ToBytes())
	})

	t.Run("binary data", func(t *testing.T) {
		decoder := NewDecoder().FromString(base32BinaryEncoded).ByBase32()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, base32BinarySrc, decoder.ToBytes())
	})

	t.Run("single byte", func(t *testing.T) {
		decoder := NewDecoder().FromString("IE======").ByBase32()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, []byte{0x41}, decoder.ToBytes())
	})

	t.Run("two bytes", func(t *testing.T) {
		decoder := NewDecoder().FromString("IFBA====").ByBase32()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, []byte{0x41, 0x42}, decoder.ToBytes())
	})

	t.Run("three bytes", func(t *testing.T) {
		decoder := NewDecoder().FromString("IFBEG===").ByBase32()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, []byte{0x41, 0x42, 0x43}, decoder.ToBytes())
	})

	t.Run("zero bytes", func(t *testing.T) {
		decoder := NewDecoder().FromString("AAAAAAA=").ByBase32()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, []byte{0x00, 0x00, 0x00, 0x00}, decoder.ToBytes())
	})

	t.Run("max bytes", func(t *testing.T) {
		decoder := NewDecoder().FromString("777777Y=").ByBase32()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, []byte{0xFF, 0xFF, 0xFF, 0xFF}, decoder.ToBytes())
	})

	t.Run("specific bytes", func(t *testing.T) {
		decoder := NewDecoder().FromString("AAAQEAY=").ByBase32()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, []byte{0x00, 0x01, 0x02, 0x03}, decoder.ToBytes())
	})

	t.Run("error file", func(t *testing.T) {
		errorFile := mock.NewErrorFile(errors.New("read error"))
		decoder := NewDecoder().FromFile(errorFile).ByBase32()
		assert.Error(t, decoder.Error)
		assert.Contains(t, decoder.Error.Error(), "read error")
	})

	t.Run("invalid base32", func(t *testing.T) {
		decoder := NewDecoder().FromString("invalid!").ByBase32()
		assert.Error(t, decoder.Error)
	})

	t.Run("decode no data", func(t *testing.T) {
		decoder := NewDecoder().ByBase32()
		assert.Nil(t, decoder.Error)
		assert.Empty(t, decoder.ToBytes())
	})
}

func TestDecoder_ByBase32_Error(t *testing.T) {
	t.Run("existing error", func(t *testing.T) {
		decoder := NewDecoder()
		decoder.Error = errors.New("existing error")
		result := decoder.ByBase32()
		assert.Equal(t, decoder, result)
		assert.Equal(t, errors.New("existing error"), result.Error)
	})
}

func TestBase32RoundTrip(t *testing.T) {
	t.Run("base32 round trip", func(t *testing.T) {
		testData := "Hello, World! 你好世界"

		encoder := NewEncoder().FromString(testData).ByBase32()
		assert.Nil(t, encoder.Error)

		decoder := NewDecoder().FromBytes(encoder.ToBytes()).ByBase32()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, []byte(testData), decoder.ToBytes())
	})

	t.Run("base32 round trip with file", func(t *testing.T) {
		testData := "Hello, World! 你好世界"

		file := mock.NewFile([]byte(testData), "test.txt")
		encoder := NewEncoder().FromFile(file).ByBase32()
		assert.Nil(t, encoder.Error)

		decoderFile := mock.NewFile(encoder.ToBytes(), "decoded.txt")
		decoder := NewDecoder().FromFile(decoderFile).ByBase32()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, []byte(testData), decoder.ToBytes())
	})

	t.Run("base32 round trip with bytes", func(t *testing.T) {
		testData := []byte{0x00, 0x01, 0x02, 0x03, 0xFF, 0xFE, 0xFD, 0xFC}

		encoder := NewEncoder().FromBytes(testData).ByBase32()
		assert.Nil(t, encoder.Error)

		decoder := NewDecoder().FromBytes(encoder.ToBytes()).ByBase32()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, testData, decoder.ToBytes())
	})
}

func TestEncoder_ByBase32Hex_Encode(t *testing.T) {
	t.Run("encode string", func(t *testing.T) {
		encoder := NewEncoder().FromString(string(base32HexSrc)).ByBase32Hex()
		assert.Nil(t, encoder.Error)
		assert.Equal(t, base32HexEncoded, encoder.ToString())
	})

	t.Run("encode bytes", func(t *testing.T) {
		encoder := NewEncoder().FromBytes(base32HexSrc).ByBase32Hex()
		assert.Nil(t, encoder.Error)
		assert.Equal(t, base32HexEncoded, encoder.ToString())
	})

	t.Run("encode file", func(t *testing.T) {
		file := mock.NewFile(base32HexSrc, "test.txt")
		encoder := NewEncoder().FromFile(file).ByBase32Hex()
		assert.Nil(t, encoder.Error)
		assert.Equal(t, base32HexEncoded, encoder.ToString())
	})

	t.Run("encode empty string", func(t *testing.T) {
		encoder := NewEncoder().FromString("").ByBase32Hex()
		assert.Nil(t, encoder.Error)
		assert.Empty(t, encoder.ToString())
	})

	t.Run("encode empty bytes", func(t *testing.T) {
		encoder := NewEncoder().FromBytes([]byte{}).ByBase32Hex()
		assert.Nil(t, encoder.Error)
		assert.Empty(t, encoder.ToString())
	})

	t.Run("encode nil bytes", func(t *testing.T) {
		encoder := NewEncoder().FromBytes(nil).ByBase32Hex()
		assert.Nil(t, encoder.Error)
		assert.Empty(t, encoder.ToString())
	})

	t.Run("encode empty file", func(t *testing.T) {
		file := mock.NewFile([]byte{}, "empty.txt")
		encoder := NewEncoder().FromFile(file).ByBase32Hex()
		assert.Nil(t, encoder.Error)
		assert.Empty(t, encoder.ToString())
	})

	t.Run("unicode string", func(t *testing.T) {
		encoder := NewEncoder().FromString(string(base32HexUnicodeSrc)).ByBase32Hex()
		assert.Nil(t, encoder.Error)
		assert.Equal(t, base32HexUnicodeEncoded, encoder.ToString())
	})

	t.Run("binary data", func(t *testing.T) {
		encoder := NewEncoder().FromBytes(base32HexBinarySrc).ByBase32Hex()
		assert.Nil(t, encoder.Error)
		assert.Equal(t, base32HexBinaryEncoded, encoder.ToString())
	})

	t.Run("large data", func(t *testing.T) {
		largeData := strings.Repeat("Hello, World! ", 100)
		encoder := NewEncoder().FromString(largeData).ByBase32Hex()
		assert.Nil(t, encoder.Error)
		assert.NotEmpty(t, encoder.ToString())
	})

	t.Run("single byte", func(t *testing.T) {
		encoder := NewEncoder().FromBytes([]byte{0x41}).ByBase32Hex()
		assert.Nil(t, encoder.Error)
		assert.Equal(t, "84======", encoder.ToString())
	})

	t.Run("two bytes", func(t *testing.T) {
		encoder := NewEncoder().FromBytes([]byte{0x41, 0x42}).ByBase32Hex()
		assert.Nil(t, encoder.Error)
		assert.Equal(t, "8510====", encoder.ToString())
	})

	t.Run("three bytes", func(t *testing.T) {
		encoder := NewEncoder().FromBytes([]byte{0x41, 0x42, 0x43}).ByBase32Hex()
		assert.Nil(t, encoder.Error)
		assert.Equal(t, "85146===", encoder.ToString())
	})

	t.Run("zero bytes", func(t *testing.T) {
		encoder := NewEncoder().FromBytes([]byte{0x00, 0x00, 0x00, 0x00}).ByBase32Hex()
		assert.Nil(t, encoder.Error)
		assert.Equal(t, "0000000=", encoder.ToString())
	})

	t.Run("max bytes", func(t *testing.T) {
		encoder := NewEncoder().FromBytes([]byte{0xFF, 0xFF, 0xFF, 0xFF}).ByBase32Hex()
		assert.Nil(t, encoder.Error)
		assert.Equal(t, "VVVVVVO=", encoder.ToString())
	})

	t.Run("specific bytes", func(t *testing.T) {
		encoder := NewEncoder().FromBytes([]byte{0x00, 0x01, 0x02, 0x03}).ByBase32Hex()
		assert.Nil(t, encoder.Error)
		assert.Equal(t, "000G40O=", encoder.ToString())
	})

	t.Run("error file", func(t *testing.T) {
		errorFile := mock.NewErrorFile(errors.New("read error"))
		encoder := NewEncoder().FromFile(errorFile).ByBase32Hex()
		assert.Error(t, encoder.Error)
		assert.Contains(t, encoder.Error.Error(), "read error")
	})

	t.Run("encode no data", func(t *testing.T) {
		encoder := NewEncoder().ByBase32Hex()
		assert.Nil(t, encoder.Error)
		assert.Empty(t, encoder.ToString())
	})
}

func TestEncoder_ByBase32Hex_Error(t *testing.T) {
	t.Run("existing error", func(t *testing.T) {
		encoder := NewEncoder()
		encoder.Error = errors.New("existing error")
		result := encoder.ByBase32Hex()
		assert.Equal(t, encoder, result)
		assert.Equal(t, errors.New("existing error"), result.Error)
	})
}

func TestDecoder_ByBase32Hex_Decode(t *testing.T) {
	t.Run("decode string", func(t *testing.T) {
		decoder := NewDecoder().FromString(base32HexEncoded).ByBase32Hex()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, base32HexSrc, decoder.ToBytes())
	})

	t.Run("decode bytes", func(t *testing.T) {
		decoder := NewDecoder().FromBytes([]byte(base32HexEncoded)).ByBase32Hex()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, base32HexSrc, decoder.ToBytes())
	})

	t.Run("decode file", func(t *testing.T) {
		file := mock.NewFile([]byte(base32HexEncoded), "test.txt")
		decoder := NewDecoder().FromFile(file).ByBase32Hex()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, base32HexSrc, decoder.ToBytes())
	})

	t.Run("decode empty string", func(t *testing.T) {
		decoder := NewDecoder().FromString("").ByBase32Hex()
		assert.Nil(t, decoder.Error)
		assert.Empty(t, decoder.ToBytes())
	})

	t.Run("decode empty bytes", func(t *testing.T) {
		decoder := NewDecoder().FromBytes([]byte{}).ByBase32Hex()
		assert.Nil(t, decoder.Error)
		assert.Empty(t, decoder.ToBytes())
	})

	t.Run("decode nil bytes", func(t *testing.T) {
		decoder := NewDecoder().FromBytes(nil).ByBase32Hex()
		assert.Nil(t, decoder.Error)
		assert.Empty(t, decoder.ToBytes())
	})

	t.Run("decode empty file", func(t *testing.T) {
		file := mock.NewFile([]byte{}, "empty.txt")
		decoder := NewDecoder().FromFile(file).ByBase32Hex()
		assert.Nil(t, decoder.Error)
		assert.Empty(t, decoder.ToBytes())
	})

	t.Run("unicode string", func(t *testing.T) {
		decoder := NewDecoder().FromString(base32HexUnicodeEncoded).ByBase32Hex()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, base32HexUnicodeSrc, decoder.ToBytes())
	})

	t.Run("binary data", func(t *testing.T) {
		decoder := NewDecoder().FromString(base32HexBinaryEncoded).ByBase32Hex()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, base32HexBinarySrc, decoder.ToBytes())
	})

	t.Run("single byte", func(t *testing.T) {
		decoder := NewDecoder().FromString("84======").ByBase32Hex()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, []byte{0x41}, decoder.ToBytes())
	})

	t.Run("two bytes", func(t *testing.T) {
		decoder := NewDecoder().FromString("8510====").ByBase32Hex()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, []byte{0x41, 0x42}, decoder.ToBytes())
	})

	t.Run("three bytes", func(t *testing.T) {
		decoder := NewDecoder().FromString("85146===").ByBase32Hex()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, []byte{0x41, 0x42, 0x43}, decoder.ToBytes())
	})

	t.Run("zero bytes", func(t *testing.T) {
		decoder := NewDecoder().FromString("0000000=").ByBase32Hex()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, []byte{0x00, 0x00, 0x00, 0x00}, decoder.ToBytes())
	})

	t.Run("max bytes", func(t *testing.T) {
		decoder := NewDecoder().FromString("VVVVVVO=").ByBase32Hex()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, []byte{0xFF, 0xFF, 0xFF, 0xFF}, decoder.ToBytes())
	})

	t.Run("specific bytes", func(t *testing.T) {
		decoder := NewDecoder().FromString("000G40O=").ByBase32Hex()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, []byte{0x00, 0x01, 0x02, 0x03}, decoder.ToBytes())
	})

	t.Run("error file", func(t *testing.T) {
		errorFile := mock.NewErrorFile(errors.New("read error"))
		decoder := NewDecoder().FromFile(errorFile).ByBase32Hex()
		assert.Error(t, decoder.Error)
		assert.Contains(t, decoder.Error.Error(), "read error")
	})

	t.Run("invalid base32hex", func(t *testing.T) {
		decoder := NewDecoder().FromString("invalid!").ByBase32Hex()
		assert.Error(t, decoder.Error)
	})

	t.Run("decode no data", func(t *testing.T) {
		decoder := NewDecoder().ByBase32Hex()
		assert.Nil(t, decoder.Error)
		assert.Empty(t, decoder.ToBytes())
	})
}

func TestDecoder_ByBase32Hex_Error(t *testing.T) {
	t.Run("existing error", func(t *testing.T) {
		decoder := NewDecoder()
		decoder.Error = errors.New("existing error")
		result := decoder.ByBase32Hex()
		assert.Equal(t, decoder, result)
		assert.Equal(t, errors.New("existing error"), result.Error)
	})
}

func TestBase32HexRoundTrip(t *testing.T) {
	t.Run("base32hex round trip", func(t *testing.T) {
		testData := "Hello, World! 你好世界"

		encoder := NewEncoder().FromString(testData).ByBase32Hex()
		assert.Nil(t, encoder.Error)

		decoder := NewDecoder().FromBytes(encoder.ToBytes()).ByBase32Hex()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, []byte(testData), decoder.ToBytes())
	})

	t.Run("base32hex round trip with file", func(t *testing.T) {
		testData := "Hello, World! 你好世界"

		file := mock.NewFile([]byte(testData), "test.txt")
		encoder := NewEncoder().FromFile(file).ByBase32Hex()
		assert.Nil(t, encoder.Error)

		decoderFile := mock.NewFile(encoder.ToBytes(), "decoded.txt")
		decoder := NewDecoder().FromFile(decoderFile).ByBase32Hex()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, []byte(testData), decoder.ToBytes())
	})

	t.Run("base32hex round trip with bytes", func(t *testing.T) {
		testData := []byte{0x00, 0x01, 0x02, 0x03, 0xFF, 0xFE, 0xFD, 0xFC}

		encoder := NewEncoder().FromBytes(testData).ByBase32Hex()
		assert.Nil(t, encoder.Error)

		decoder := NewDecoder().FromBytes(encoder.ToBytes()).ByBase32Hex()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, testData, decoder.ToBytes())
	})
}

func TestBase32EdgeCases(t *testing.T) {
	t.Run("very large data", func(t *testing.T) {
		largeData := strings.Repeat("Hello, World! ", 1000)

		encoder := NewEncoder().FromString(largeData).ByBase32()
		assert.Nil(t, encoder.Error)

		decoder := NewDecoder().FromBytes(encoder.ToBytes()).ByBase32()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, []byte(largeData), decoder.ToBytes())
	})

	t.Run("single character", func(t *testing.T) {
		encoder := NewEncoder().FromString("A").ByBase32()
		assert.Nil(t, encoder.Error)
		assert.NotEmpty(t, encoder.ToString())

		decoder := NewDecoder().FromBytes(encoder.ToBytes()).ByBase32()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, []byte("A"), decoder.ToBytes())
	})

	t.Run("binary data", func(t *testing.T) {
		binaryData := []byte{0x00, 0x01, 0x02, 0x03, 0xFF, 0xFE, 0xFD, 0xFC}

		encoder := NewEncoder().FromBytes(binaryData).ByBase32()
		assert.Nil(t, encoder.Error)

		decoder := NewDecoder().FromBytes(encoder.ToBytes()).ByBase32()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, binaryData, decoder.ToBytes())
	})

	t.Run("mixed encoding methods", func(t *testing.T) {
		testData := "hello world"

		encoder1 := NewEncoder().FromString(testData).ByBase32()
		encoder2 := NewEncoder().FromBytes([]byte(testData)).ByBase32()
		encoder3 := NewEncoder().FromFile(mock.NewFile([]byte(testData), "test.txt")).ByBase32()

		assert.Nil(t, encoder1.Error)
		assert.Nil(t, encoder2.Error)
		assert.Nil(t, encoder3.Error)
		assert.Equal(t, encoder1.ToString(), encoder2.ToString())
		assert.Equal(t, encoder1.ToString(), encoder3.ToString())
	})

	t.Run("zero bytes", func(t *testing.T) {
		zeroData := []byte{0x00, 0x00, 0x00, 0x00}

		encoder := NewEncoder().FromBytes(zeroData).ByBase32()
		assert.Nil(t, encoder.Error)

		decoder := NewDecoder().FromBytes(encoder.ToBytes()).ByBase32()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, zeroData, decoder.ToBytes())
	})

	t.Run("max bytes", func(t *testing.T) {
		maxData := []byte{0xFF, 0xFF, 0xFF, 0xFF}

		encoder := NewEncoder().FromBytes(maxData).ByBase32()
		assert.Nil(t, encoder.Error)

		decoder := NewDecoder().FromBytes(encoder.ToBytes()).ByBase32()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, maxData, decoder.ToBytes())
	})

	t.Run("all possible byte values", func(t *testing.T) {
		allBytes := make([]byte, 256)
		for i := 0; i < 256; i++ {
			allBytes[i] = byte(i)
		}

		encoder := NewEncoder().FromBytes(allBytes).ByBase32()
		assert.Nil(t, encoder.Error)

		decoder := NewDecoder().FromBytes(encoder.ToBytes()).ByBase32()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, allBytes, decoder.ToBytes())
	})
}

func TestBase32Specific(t *testing.T) {
	t.Run("base32 alphabet verification", func(t *testing.T) {
		testData := []byte{0x00, 0x01, 0x02}
		encoder := NewEncoder().FromBytes(testData).ByBase32()
		assert.Nil(t, encoder.Error)

		resultStr := encoder.ToString()
		for _, char := range resultStr {
			assert.Contains(t, "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567=", string(char))
		}
	})

	t.Run("base32 encoding consistency", func(t *testing.T) {
		testData := []byte("Hello, World!")
		encoder := NewEncoder().FromBytes(testData).ByBase32()
		assert.Nil(t, encoder.Error)

		decoder := NewDecoder().FromBytes(encoder.ToBytes()).ByBase32()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, testData, decoder.ToBytes())
	})

	t.Run("base32 vs string vs bytes consistency", func(t *testing.T) {
		testData := "hello world"

		encoder1 := NewEncoder().FromString(testData).ByBase32()
		encoder2 := NewEncoder().FromBytes([]byte(testData)).ByBase32()
		encoder3 := NewEncoder().FromFile(mock.NewFile([]byte(testData), "test.txt")).ByBase32()

		assert.Nil(t, encoder1.Error)
		assert.Nil(t, encoder2.Error)
		assert.Nil(t, encoder3.Error)
		assert.Equal(t, encoder1.ToString(), encoder2.ToString())
		assert.Equal(t, encoder1.ToString(), encoder3.ToString())
	})

	t.Run("base32 vs base32hex comparison", func(t *testing.T) {
		testData := []byte("Hello, World!")

		encoder32 := NewEncoder().FromBytes(testData).ByBase32()
		assert.Nil(t, encoder32.Error)

		encoder32hex := NewEncoder().FromBytes(testData).ByBase32Hex()
		assert.Nil(t, encoder32hex.Error)

		// Both should decode back to the same data
		decoder32 := NewDecoder().FromBytes(encoder32.ToBytes()).ByBase32()
		decoder32hex := NewDecoder().FromBytes(encoder32hex.ToBytes()).ByBase32Hex()

		assert.Nil(t, decoder32.Error)
		assert.Nil(t, decoder32hex.Error)
		assert.Equal(t, testData, decoder32.ToBytes())
		assert.Equal(t, testData, decoder32hex.ToBytes())
	})
}
