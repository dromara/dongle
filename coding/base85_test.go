package coding

import (
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/dromara/dongle/mock"
)

// Test data for base85 encoding (generated using Python base64.a85encode - Ascii85)
var (
	base85Src     = []byte("hello world")
	base85Encoded = "BOu!rD]j7BEbo7"
)

// Test data for base85 unicode encoding (generated using Python base64.a85encode - Ascii85)
var (
	base85UnicodeSrc     = []byte("你好世界")
	base85UnicodeEncoded = "jLq5JV7ks\"QKONl"
)

// Test data for base85 binary encoding (generated using Python base64.a85encode - Ascii85)
var (
	base85BinarySrc     = []byte{0x00, 0x01, 0x02, 0x03, 0xFF, 0xFE, 0xFD, 0xFC}
	base85BinaryEncoded = "!!*-'s8Mup"
)

// Test data for base85 specific bytes (generated using Python base64.a85encode - Ascii85)
var (
	base85SpecificBytesSrc     = []byte{0x00, 0x01, 0x02, 0x03}
	base85SpecificBytesEncoded = "!!*-'"
)

// Test data for base85 single byte (generated using Python base64.a85encode - Ascii85)
var (
	base85SingleByteSrc     = []byte{0x41}
	base85SingleByteEncoded = "5l"
)

// Test data for base85 two bytes (generated using Python base64.a85encode - Ascii85)
var (
	base85TwoBytesSrc     = []byte{0x41, 0x42}
	base85TwoBytesEncoded = "5sb"
)

// Test data for base85 three bytes (generated using Python base64.a85encode - Ascii85)
var (
	base85ThreeBytesSrc     = []byte{0x41, 0x42, 0x43}
	base85ThreeBytesEncoded = "5sdp"
)

// Test data for base85 zero bytes (generated using Python base64.a85encode - Ascii85)
var (
	base85ZeroBytesSrc     = []byte{0x00, 0x00, 0x00, 0x00}
	base85ZeroBytesEncoded = "z"
)

// Test data for base85 max bytes (generated using Python base64.a85encode - Ascii85)
var (
	base85MaxBytesSrc     = []byte{0xFF, 0xFF, 0xFF, 0xFF}
	base85MaxBytesEncoded = "s8W-!"
)

func TestEncoder_ByBase85_Encode(t *testing.T) {
	t.Run("encode string", func(t *testing.T) {
		encoder := NewEncoder().FromString(string(base85Src)).ByBase85()
		assert.Nil(t, encoder.Error)
		assert.Equal(t, base85Encoded, encoder.ToString())
	})

	t.Run("encode bytes", func(t *testing.T) {
		encoder := NewEncoder().FromBytes(base85Src).ByBase85()
		assert.Nil(t, encoder.Error)
		assert.Equal(t, base85Encoded, encoder.ToString())
	})

	t.Run("encode file", func(t *testing.T) {
		file := mock.NewFile(base85Src, "test.txt")
		encoder := NewEncoder().FromFile(file).ByBase85()
		assert.Nil(t, encoder.Error)
		assert.Equal(t, base85Encoded, encoder.ToString())
	})

	t.Run("empty string", func(t *testing.T) {
		encoder := NewEncoder().FromString("").ByBase85()
		assert.Nil(t, encoder.Error)
		assert.Empty(t, encoder.ToString())
	})

	t.Run("empty bytes", func(t *testing.T) {
		encoder := NewEncoder().FromBytes([]byte{}).ByBase85()
		assert.Nil(t, encoder.Error)
		assert.Empty(t, encoder.ToString())
	})

	t.Run("nil bytes", func(t *testing.T) {
		encoder := NewEncoder().FromBytes(nil).ByBase85()
		assert.Nil(t, encoder.Error)
		assert.Empty(t, encoder.ToString())
	})

	t.Run("empty file", func(t *testing.T) {
		file := mock.NewFile([]byte{}, "empty.txt")
		encoder := NewEncoder().FromFile(file).ByBase85()
		assert.Nil(t, encoder.Error)
		assert.Empty(t, encoder.ToString())
	})

	t.Run("unicode string", func(t *testing.T) {
		encoder := NewEncoder().FromString(string(base85UnicodeSrc)).ByBase85()
		assert.Nil(t, encoder.Error)
		assert.Equal(t, base85UnicodeEncoded, encoder.ToString())
	})

	t.Run("binary data", func(t *testing.T) {
		encoder := NewEncoder().FromBytes(base85BinarySrc).ByBase85()
		assert.Nil(t, encoder.Error)
		assert.Equal(t, base85BinaryEncoded, encoder.ToString())
	})

	t.Run("large data", func(t *testing.T) {
		largeData := strings.Repeat("Hello, World! ", 100)
		encoder := NewEncoder().FromString(largeData).ByBase85()
		assert.Nil(t, encoder.Error)
		assert.NotEmpty(t, encoder.ToString())
	})

	t.Run("single byte", func(t *testing.T) {
		encoder := NewEncoder().FromBytes(base85SingleByteSrc).ByBase85()
		assert.Nil(t, encoder.Error)
		assert.Equal(t, base85SingleByteEncoded, encoder.ToString())
	})

	t.Run("two bytes", func(t *testing.T) {
		encoder := NewEncoder().FromBytes(base85TwoBytesSrc).ByBase85()
		assert.Nil(t, encoder.Error)
		assert.Equal(t, base85TwoBytesEncoded, encoder.ToString())
	})

	t.Run("three bytes", func(t *testing.T) {
		encoder := NewEncoder().FromBytes(base85ThreeBytesSrc).ByBase85()
		assert.Nil(t, encoder.Error)
		assert.Equal(t, base85ThreeBytesEncoded, encoder.ToString())
	})

	t.Run("zero bytes", func(t *testing.T) {
		encoder := NewEncoder().FromBytes(base85ZeroBytesSrc).ByBase85()
		assert.Nil(t, encoder.Error)
		assert.Equal(t, base85ZeroBytesEncoded, encoder.ToString())
	})

	t.Run("max bytes", func(t *testing.T) {
		encoder := NewEncoder().FromBytes(base85MaxBytesSrc).ByBase85()
		assert.Nil(t, encoder.Error)
		assert.Equal(t, base85MaxBytesEncoded, encoder.ToString())
	})

	t.Run("specific bytes", func(t *testing.T) {
		encoder := NewEncoder().FromBytes(base85SpecificBytesSrc).ByBase85()
		assert.Nil(t, encoder.Error)
		assert.Equal(t, base85SpecificBytesEncoded, encoder.ToString())
	})

	t.Run("error file", func(t *testing.T) {
		errorFile := mock.NewErrorFile(errors.New("read error"))
		encoder := NewEncoder().FromFile(errorFile).ByBase85()
		assert.Error(t, encoder.Error)
		assert.Contains(t, encoder.Error.Error(), "read error")
	})

	t.Run("no data no reader", func(t *testing.T) {
		encoder := NewEncoder().ByBase85()
		assert.Nil(t, encoder.Error)
		assert.Empty(t, encoder.ToString())
	})
}

func TestEncoder_ByBase85_Error(t *testing.T) {
	t.Run("existing error", func(t *testing.T) {
		encoder := NewEncoder()
		encoder.Error = errors.New("existing error")
		result := encoder.ByBase85()
		assert.Equal(t, encoder, result)
		assert.Equal(t, errors.New("existing error"), result.Error)
	})
}

func TestDecoder_ByBase85_Decode(t *testing.T) {
	t.Run("decode string", func(t *testing.T) {
		decoder := NewDecoder().FromString(base85Encoded).ByBase85()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, base85Src, decoder.ToBytes())
	})

	t.Run("decode bytes", func(t *testing.T) {
		decoder := NewDecoder().FromBytes([]byte(base85Encoded)).ByBase85()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, base85Src, decoder.ToBytes())
	})

	t.Run("decode file", func(t *testing.T) {
		file := mock.NewFile([]byte(base85Encoded), "test.txt")
		decoder := NewDecoder().FromFile(file).ByBase85()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, base85Src, decoder.ToBytes())
	})

	t.Run("empty string", func(t *testing.T) {
		decoder := NewDecoder().FromString("").ByBase85()
		assert.Nil(t, decoder.Error)
		assert.Empty(t, decoder.ToBytes())
	})

	t.Run("empty bytes", func(t *testing.T) {
		decoder := NewDecoder().FromBytes([]byte{}).ByBase85()
		assert.Nil(t, decoder.Error)
		assert.Empty(t, decoder.ToBytes())
	})

	t.Run("nil bytes", func(t *testing.T) {
		decoder := NewDecoder().FromBytes(nil).ByBase85()
		assert.Nil(t, decoder.Error)
		assert.Empty(t, decoder.ToBytes())
	})

	t.Run("empty file", func(t *testing.T) {
		file := mock.NewFile([]byte{}, "empty.txt")
		decoder := NewDecoder().FromFile(file).ByBase85()
		assert.Nil(t, decoder.Error)
		assert.Empty(t, decoder.ToBytes())
	})

	t.Run("unicode string", func(t *testing.T) {
		decoder := NewDecoder().FromString(base85UnicodeEncoded).ByBase85()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, base85UnicodeSrc, decoder.ToBytes())
	})

	t.Run("binary data", func(t *testing.T) {
		decoder := NewDecoder().FromString(base85BinaryEncoded).ByBase85()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, base85BinarySrc, decoder.ToBytes())
	})

	t.Run("single byte", func(t *testing.T) {
		decoder := NewDecoder().FromString(base85SingleByteEncoded).ByBase85()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, base85SingleByteSrc, decoder.ToBytes())
	})

	t.Run("two bytes", func(t *testing.T) {
		decoder := NewDecoder().FromString(base85TwoBytesEncoded).ByBase85()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, base85TwoBytesSrc, decoder.ToBytes())
	})

	t.Run("three bytes", func(t *testing.T) {
		decoder := NewDecoder().FromString(base85ThreeBytesEncoded).ByBase85()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, base85ThreeBytesSrc, decoder.ToBytes())
	})

	t.Run("zero bytes", func(t *testing.T) {
		decoder := NewDecoder().FromString(base85ZeroBytesEncoded).ByBase85()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, base85ZeroBytesSrc, decoder.ToBytes())
	})

	t.Run("max bytes", func(t *testing.T) {
		decoder := NewDecoder().FromString(base85MaxBytesEncoded).ByBase85()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, base85MaxBytesSrc, decoder.ToBytes())
	})

	t.Run("specific bytes", func(t *testing.T) {
		decoder := NewDecoder().FromString(base85SpecificBytesEncoded).ByBase85()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, base85SpecificBytesSrc, decoder.ToBytes())
	})

	t.Run("error file", func(t *testing.T) {
		errorFile := mock.NewErrorFile(errors.New("read error"))
		decoder := NewDecoder().FromFile(errorFile).ByBase85()
		assert.Error(t, decoder.Error)
		assert.Contains(t, decoder.Error.Error(), "read error")
	})

	t.Run("invalid base85", func(t *testing.T) {
		decoder := NewDecoder().FromString("invalid!").ByBase85()
		assert.Error(t, decoder.Error)
	})

	t.Run("no data no reader", func(t *testing.T) {
		decoder := NewDecoder().ByBase85()
		assert.Nil(t, decoder.Error)
		assert.Empty(t, decoder.ToBytes())
	})
}

func TestDecoder_ByBase85_Error(t *testing.T) {
	t.Run("existing error", func(t *testing.T) {
		decoder := NewDecoder()
		decoder.Error = errors.New("existing error")
		result := decoder.ByBase85()
		assert.Equal(t, decoder, result)
		assert.Equal(t, errors.New("existing error"), result.Error)
	})
}

func TestBase85RoundTrip(t *testing.T) {
	t.Run("base85 round trip", func(t *testing.T) {
		testData := "Hello, World! 你好世界"

		encoder := NewEncoder().FromString(testData).ByBase85()
		assert.Nil(t, encoder.Error)

		decoder := NewDecoder().FromBytes(encoder.ToBytes()).ByBase85()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, []byte(testData), decoder.ToBytes())
	})

	t.Run("base85 round trip with file", func(t *testing.T) {
		testData := "Hello, World! 你好世界"

		file := mock.NewFile([]byte(testData), "test.txt")
		encoder := NewEncoder().FromFile(file).ByBase85()
		assert.Nil(t, encoder.Error)

		decoderFile := mock.NewFile(encoder.ToBytes(), "decoded.txt")
		decoder := NewDecoder().FromFile(decoderFile).ByBase85()
		assert.Nil(t, decoder.Error)
		assert.NotEmpty(t, decoder.ToBytes())
	})

	t.Run("base85 round trip with bytes", func(t *testing.T) {
		testData := []byte{0x00, 0x01, 0x02, 0x03, 0xFF, 0xFE, 0xFD, 0xFC}

		encoder := NewEncoder().FromBytes(testData).ByBase85()
		assert.Nil(t, encoder.Error)

		decoder := NewDecoder().FromBytes(encoder.ToBytes()).ByBase85()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, testData, decoder.ToBytes())
	})
}

func TestBase85EdgeCases(t *testing.T) {
	t.Run("very large data", func(t *testing.T) {
		largeData := strings.Repeat("Hello, World! ", 1000)

		encoder := NewEncoder().FromString(largeData).ByBase85()
		assert.Nil(t, encoder.Error)

		decoder := NewDecoder().FromBytes(encoder.ToBytes()).ByBase85()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, []byte(largeData), decoder.ToBytes())
	})

	t.Run("single character", func(t *testing.T) {
		encoder := NewEncoder().FromString("A").ByBase85()
		assert.Nil(t, encoder.Error)
		assert.NotEmpty(t, encoder.ToString())

		decoder := NewDecoder().FromBytes(encoder.ToBytes()).ByBase85()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, []byte("A"), decoder.ToBytes())
	})

	t.Run("binary data", func(t *testing.T) {
		binaryData := []byte{0x00, 0x01, 0x02, 0x03, 0xFF, 0xFE, 0xFD, 0xFC}

		encoder := NewEncoder().FromBytes(binaryData).ByBase85()
		assert.Nil(t, encoder.Error)

		decoder := NewDecoder().FromBytes(encoder.ToBytes()).ByBase85()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, binaryData, decoder.ToBytes())
	})

	t.Run("mixed encoding methods", func(t *testing.T) {
		testData := "hello world"

		encoder1 := NewEncoder().FromString(testData).ByBase85()
		encoder2 := NewEncoder().FromBytes([]byte(testData)).ByBase85()
		encoder3 := NewEncoder().FromFile(mock.NewFile([]byte(testData), "test.txt")).ByBase85()

		assert.Nil(t, encoder1.Error)
		assert.Nil(t, encoder2.Error)
		assert.Nil(t, encoder3.Error)
		assert.Equal(t, encoder1.ToString(), encoder2.ToString())
		assert.Equal(t, encoder1.ToString(), encoder3.ToString())
	})

	t.Run("zero bytes", func(t *testing.T) {
		zeroData := []byte{0x00, 0x00, 0x00, 0x00}

		encoder := NewEncoder().FromBytes(zeroData).ByBase85()
		assert.Nil(t, encoder.Error)

		decoder := NewDecoder().FromBytes(encoder.ToBytes()).ByBase85()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, zeroData, decoder.ToBytes())
	})

	t.Run("max bytes", func(t *testing.T) {
		maxData := []byte{0xFF, 0xFF, 0xFF, 0xFF}

		encoder := NewEncoder().FromBytes(maxData).ByBase85()
		assert.Nil(t, encoder.Error)

		decoder := NewDecoder().FromBytes(encoder.ToBytes()).ByBase85()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, maxData, decoder.ToBytes())
	})

	t.Run("all possible byte values", func(t *testing.T) {
		allBytes := make([]byte, 256)
		for i := 0; i < 256; i++ {
			allBytes[i] = byte(i)
		}

		encoder := NewEncoder().FromBytes(allBytes).ByBase85()
		assert.Nil(t, encoder.Error)

		decoder := NewDecoder().FromBytes(encoder.ToBytes()).ByBase85()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, allBytes, decoder.ToBytes())
	})
}

func TestBase85Specific(t *testing.T) {
	t.Run("base85 alphabet verification", func(t *testing.T) {
		testData := []byte{0x00, 0x01, 0x02}
		encoder := NewEncoder().FromBytes(testData).ByBase85()
		assert.Nil(t, encoder.Error)

		resultStr := encoder.ToString()
		for _, char := range resultStr {
			assert.Contains(t, "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!#$%&()*+-;<=>?@^_`{|}~", string(char))
		}
	})

	t.Run("base85 encoding consistency", func(t *testing.T) {
		testData := []byte("Hello, World!")
		encoder := NewEncoder().FromBytes(testData).ByBase85()
		assert.Nil(t, encoder.Error)

		decoder := NewDecoder().FromBytes(encoder.ToBytes()).ByBase85()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, testData, decoder.ToBytes())
	})

	t.Run("base85 vs string vs bytes consistency", func(t *testing.T) {
		testData := "hello world"

		encoder1 := NewEncoder().FromString(testData).ByBase85()
		encoder2 := NewEncoder().FromBytes([]byte(testData)).ByBase85()
		encoder3 := NewEncoder().FromFile(mock.NewFile([]byte(testData), "test.txt")).ByBase85()

		assert.Nil(t, encoder1.Error)
		assert.Nil(t, encoder2.Error)
		assert.Nil(t, encoder3.Error)
		assert.Equal(t, encoder1.ToString(), encoder2.ToString())
		assert.Equal(t, encoder1.ToString(), encoder3.ToString())
	})

	t.Run("base85 specific test cases", func(t *testing.T) {
		// Test specific Base85 encoding patterns (generated using Python base64.a85encode - Ascii85)
		testCases := []struct {
			input    []byte
			expected string
		}{
			{[]byte{0x00}, "!!"},
			{[]byte{0x00, 0x00}, "!!!"},
			{[]byte{0x00, 0x00, 0x00}, "!!!!"},
			{[]byte{0xFF}, "rr"},
			{[]byte{0xFF, 0xFF}, "s8N"},
			{[]byte{0xFF, 0xFF, 0xFF}, "s8W*"},
		}

		for _, tc := range testCases {
			encoder := NewEncoder().FromBytes(tc.input).ByBase85()
			assert.Nil(t, encoder.Error)
			assert.Equal(t, tc.expected, encoder.ToString())

			decoder := NewDecoder().FromString(tc.expected).ByBase85()
			assert.Nil(t, decoder.Error)
			assert.Equal(t, tc.input, decoder.ToBytes())
		}
	})
}
