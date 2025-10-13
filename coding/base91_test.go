package coding

import (
	"errors"
	"strings"
	"testing"

	"github.com/dromara/dongle/mock"
	"github.com/stretchr/testify/assert"
)

// Test data for base91 encoding (generated using dongle implementation)
var (
	base91Src     = []byte("hello world")
	base91Encoded = "TPwJh>Io2Tv!lE"
)

// Test data for base91 unicode encoding (generated using dongle implementation)
var (
	base91UnicodeSrc     = []byte("你好世界")
	base91UnicodeEncoded = "I_5k7a9aug!32zR"
)

// Test data for base91 binary encoding (generated using dongle implementation)
var (
	base91BinarySrc     = []byte{0x00, 0x01, 0x02, 0x03, 0xFF, 0xFE, 0xFD, 0xFC}
	base91BinaryEncoded = ":C#(d~(>rs"
)

// Test data for base91 specific bytes (generated using dongle implementation)
var (
	base91SpecificBytesSrc     = []byte{0x00, 0x01, 0x02, 0x03}
	base91SpecificBytesEncoded = ":C#(A"
)

// Test data for base91 single byte (generated using dongle implementation)
var (
	base91SingleByteSrc     = []byte{0x41}
	base91SingleByteEncoded = "%A"
)

// Test data for base91 two bytes (generated using dongle implementation)
var (
	base91TwoBytesSrc     = []byte{0x41, 0x42}
	base91TwoBytesEncoded = "fGC"
)

// Test data for base91 three bytes (generated using dongle implementation)
var (
	base91ThreeBytesSrc     = []byte{0x41, 0x42, 0x43}
	base91ThreeBytesEncoded = "fG^F"
)

// Test data for base91 zero bytes (generated using dongle implementation)
var (
	base91ZeroBytesSrc     = []byte{0x00, 0x00, 0x00, 0x00}
	base91ZeroBytesEncoded = "AAAAA"
)

// Test data for base91 max bytes (generated using dongle implementation)
var (
	base91MaxBytesSrc     = []byte{0xFF, 0xFF, 0xFF, 0xFF}
	base91MaxBytesEncoded = "B\"B\"#"
)

func TestEncoder_ByBase91_Encode(t *testing.T) {
	t.Run("encode string", func(t *testing.T) {
		encoder := NewEncoder().FromString(string(base91Src)).ByBase91()
		assert.Nil(t, encoder.Error)
		assert.Equal(t, base91Encoded, encoder.ToString())
	})

	t.Run("encode bytes", func(t *testing.T) {
		encoder := NewEncoder().FromBytes(base91Src).ByBase91()
		assert.Nil(t, encoder.Error)
		assert.Equal(t, base91Encoded, encoder.ToString())
	})

	t.Run("encode file", func(t *testing.T) {
		file := mock.NewFile(base91Src, "test.txt")
		encoder := NewEncoder().FromFile(file).ByBase91()
		assert.Nil(t, encoder.Error)
		assert.Equal(t, base91Encoded, encoder.ToString())
	})

	t.Run("empty string", func(t *testing.T) {
		encoder := NewEncoder().FromString("").ByBase91()
		assert.Nil(t, encoder.Error)
		assert.Empty(t, encoder.ToString())
	})

	t.Run("empty bytes", func(t *testing.T) {
		encoder := NewEncoder().FromBytes([]byte{}).ByBase91()
		assert.Nil(t, encoder.Error)
		assert.Empty(t, encoder.ToString())
	})

	t.Run("nil bytes", func(t *testing.T) {
		encoder := NewEncoder().FromBytes(nil).ByBase91()
		assert.Nil(t, encoder.Error)
		assert.Empty(t, encoder.ToString())
	})

	t.Run("empty file", func(t *testing.T) {
		file := mock.NewFile([]byte{}, "empty.txt")
		encoder := NewEncoder().FromFile(file).ByBase91()
		assert.Nil(t, encoder.Error)
		assert.Empty(t, encoder.ToString())
	})

	t.Run("unicode string", func(t *testing.T) {
		encoder := NewEncoder().FromString(string(base91UnicodeSrc)).ByBase91()
		assert.Nil(t, encoder.Error)
		assert.Equal(t, base91UnicodeEncoded, encoder.ToString())
	})

	t.Run("binary data", func(t *testing.T) {
		encoder := NewEncoder().FromBytes(base91BinarySrc).ByBase91()
		assert.Nil(t, encoder.Error)
		assert.Equal(t, base91BinaryEncoded, encoder.ToString())
	})

	t.Run("large data", func(t *testing.T) {
		largeData := strings.Repeat("Hello, World! ", 100)
		encoder := NewEncoder().FromString(largeData).ByBase91()
		assert.Nil(t, encoder.Error)
		assert.NotEmpty(t, encoder.ToString())
	})

	t.Run("single byte", func(t *testing.T) {
		encoder := NewEncoder().FromBytes(base91SingleByteSrc).ByBase91()
		assert.Nil(t, encoder.Error)
		assert.Equal(t, base91SingleByteEncoded, encoder.ToString())
	})

	t.Run("two bytes", func(t *testing.T) {
		encoder := NewEncoder().FromBytes(base91TwoBytesSrc).ByBase91()
		assert.Nil(t, encoder.Error)
		assert.Equal(t, base91TwoBytesEncoded, encoder.ToString())
	})

	t.Run("three bytes", func(t *testing.T) {
		encoder := NewEncoder().FromBytes(base91ThreeBytesSrc).ByBase91()
		assert.Nil(t, encoder.Error)
		assert.Equal(t, base91ThreeBytesEncoded, encoder.ToString())
	})

	t.Run("zero bytes", func(t *testing.T) {
		encoder := NewEncoder().FromBytes(base91ZeroBytesSrc).ByBase91()
		assert.Nil(t, encoder.Error)
		assert.Equal(t, base91ZeroBytesEncoded, encoder.ToString())
	})

	t.Run("max bytes", func(t *testing.T) {
		encoder := NewEncoder().FromBytes(base91MaxBytesSrc).ByBase91()
		assert.Nil(t, encoder.Error)
		assert.Equal(t, base91MaxBytesEncoded, encoder.ToString())
	})

	t.Run("specific bytes", func(t *testing.T) {
		encoder := NewEncoder().FromBytes(base91SpecificBytesSrc).ByBase91()
		assert.Nil(t, encoder.Error)
		assert.Equal(t, base91SpecificBytesEncoded, encoder.ToString())
	})

	t.Run("error file", func(t *testing.T) {
		errorFile := mock.NewErrorFile(errors.New("read error"))
		encoder := NewEncoder().FromFile(errorFile).ByBase91()
		assert.Error(t, encoder.Error)
		assert.Contains(t, encoder.Error.Error(), "read error")
	})

	t.Run("no data no reader", func(t *testing.T) {
		encoder := NewEncoder().ByBase91()
		assert.Nil(t, encoder.Error)
		assert.Empty(t, encoder.ToString())
	})
}

func TestEncoder_ByBase91_Error(t *testing.T) {
	t.Run("existing error", func(t *testing.T) {
		encoder := NewEncoder()
		encoder.Error = errors.New("existing error")
		result := encoder.ByBase91()
		assert.Equal(t, encoder, result)
		assert.Equal(t, errors.New("existing error"), result.Error)
	})
}

func TestDecoder_ByBase91_Decode(t *testing.T) {
	t.Run("decode string", func(t *testing.T) {
		decoder := NewDecoder().FromString(base91Encoded).ByBase91()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, base91Src, decoder.ToBytes())
	})

	t.Run("decode bytes", func(t *testing.T) {
		decoder := NewDecoder().FromBytes([]byte(base91Encoded)).ByBase91()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, base91Src, decoder.ToBytes())
	})

	t.Run("decode file", func(t *testing.T) {
		file := mock.NewFile([]byte(base91Encoded), "test.txt")
		decoder := NewDecoder().FromFile(file).ByBase91()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, base91Src, decoder.ToBytes())
	})

	t.Run("empty string", func(t *testing.T) {
		decoder := NewDecoder().FromString("").ByBase91()
		assert.Nil(t, decoder.Error)
		assert.Empty(t, decoder.ToBytes())
	})

	t.Run("empty bytes", func(t *testing.T) {
		decoder := NewDecoder().FromBytes([]byte{}).ByBase91()
		assert.Nil(t, decoder.Error)
		assert.Empty(t, decoder.ToBytes())
	})

	t.Run("nil bytes", func(t *testing.T) {
		decoder := NewDecoder().FromBytes(nil).ByBase91()
		assert.Nil(t, decoder.Error)
		assert.Empty(t, decoder.ToBytes())
	})

	t.Run("empty file", func(t *testing.T) {
		file := mock.NewFile([]byte{}, "empty.txt")
		decoder := NewDecoder().FromFile(file).ByBase91()
		assert.Nil(t, decoder.Error)
		assert.Empty(t, decoder.ToBytes())
	})

	t.Run("unicode string", func(t *testing.T) {
		decoder := NewDecoder().FromString(base91UnicodeEncoded).ByBase91()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, base91UnicodeSrc, decoder.ToBytes())
	})

	t.Run("binary data", func(t *testing.T) {
		decoder := NewDecoder().FromString(base91BinaryEncoded).ByBase91()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, base91BinarySrc, decoder.ToBytes())
	})

	t.Run("single byte", func(t *testing.T) {
		decoder := NewDecoder().FromString(base91SingleByteEncoded).ByBase91()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, base91SingleByteSrc, decoder.ToBytes())
	})

	t.Run("two bytes", func(t *testing.T) {
		decoder := NewDecoder().FromString(base91TwoBytesEncoded).ByBase91()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, base91TwoBytesSrc, decoder.ToBytes())
	})

	t.Run("three bytes", func(t *testing.T) {
		decoder := NewDecoder().FromString(base91ThreeBytesEncoded).ByBase91()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, base91ThreeBytesSrc, decoder.ToBytes())
	})

	t.Run("zero bytes", func(t *testing.T) {
		decoder := NewDecoder().FromString(base91ZeroBytesEncoded).ByBase91()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, base91ZeroBytesSrc, decoder.ToBytes())
	})

	t.Run("max bytes", func(t *testing.T) {
		decoder := NewDecoder().FromString(base91MaxBytesEncoded).ByBase91()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, base91MaxBytesSrc, decoder.ToBytes())
	})

	t.Run("specific bytes", func(t *testing.T) {
		decoder := NewDecoder().FromString(base91SpecificBytesEncoded).ByBase91()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, base91SpecificBytesSrc, decoder.ToBytes())
	})

	t.Run("error file", func(t *testing.T) {
		errorFile := mock.NewErrorFile(errors.New("read error"))
		decoder := NewDecoder().FromFile(errorFile).ByBase91()
		assert.Error(t, decoder.Error)
		assert.Contains(t, decoder.Error.Error(), "read error")
	})

	t.Run("invalid base91", func(t *testing.T) {
		decoder := NewDecoder().FromString("invalid!").ByBase91()
		// Base91 decoder returns decoded result for invalid characters, not error
		assert.Nil(t, decoder.Error)
		assert.NotNil(t, decoder.ToBytes())
		// Verify it returns some decoded bytes
		assert.Equal(t, []byte{255, 173, 45, 237, 176, 19}, decoder.ToBytes())
	})

	t.Run("no data no reader", func(t *testing.T) {
		decoder := NewDecoder().ByBase91()
		assert.Nil(t, decoder.Error)
		assert.Empty(t, decoder.ToBytes())
	})
}

func TestDecoder_ByBase91_Error(t *testing.T) {
	t.Run("existing error", func(t *testing.T) {
		decoder := NewDecoder()
		decoder.Error = errors.New("existing error")
		result := decoder.ByBase91()
		assert.Equal(t, decoder, result)
		assert.Equal(t, errors.New("existing error"), result.Error)
	})
}

func TestBase91RoundTrip(t *testing.T) {
	t.Run("base91 round trip", func(t *testing.T) {
		testData := "Hello, World! 你好世界"

		encoder := NewEncoder().FromString(testData).ByBase91()
		assert.Nil(t, encoder.Error)

		decoder := NewDecoder().FromBytes(encoder.ToBytes()).ByBase91()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, []byte(testData), decoder.ToBytes())
	})

	t.Run("base91 round trip with file", func(t *testing.T) {
		testData := "Hello, World! 你好世界"

		file := mock.NewFile([]byte(testData), "test.txt")
		encoder := NewEncoder().FromFile(file).ByBase91()
		assert.Nil(t, encoder.Error)

		decoderFile := mock.NewFile(encoder.ToBytes(), "decoded.txt")
		decoder := NewDecoder().FromFile(decoderFile).ByBase91()
		assert.Nil(t, decoder.Error)
		assert.NotEmpty(t, decoder.ToBytes())
	})

	t.Run("base91 round trip with bytes", func(t *testing.T) {
		testData := []byte{0x00, 0x01, 0x02, 0x03, 0xFF, 0xFE, 0xFD, 0xFC}

		encoder := NewEncoder().FromBytes(testData).ByBase91()
		assert.Nil(t, encoder.Error)

		decoder := NewDecoder().FromBytes(encoder.ToBytes()).ByBase91()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, testData, decoder.ToBytes())
	})
}

func TestBase91EdgeCases(t *testing.T) {
	t.Run("very large data", func(t *testing.T) {
		largeData := strings.Repeat("Hello, World! ", 1000)

		encoder := NewEncoder().FromString(largeData).ByBase91()
		assert.Nil(t, encoder.Error)

		decoder := NewDecoder().FromBytes(encoder.ToBytes()).ByBase91()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, []byte(largeData), decoder.ToBytes())
	})

	t.Run("single character", func(t *testing.T) {
		encoder := NewEncoder().FromString("A").ByBase91()
		assert.Nil(t, encoder.Error)
		assert.NotEmpty(t, encoder.ToString())

		decoder := NewDecoder().FromBytes(encoder.ToBytes()).ByBase91()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, []byte("A"), decoder.ToBytes())
	})

	t.Run("binary data", func(t *testing.T) {
		binaryData := []byte{0x00, 0x01, 0x02, 0x03, 0xFF, 0xFE, 0xFD, 0xFC}

		encoder := NewEncoder().FromBytes(binaryData).ByBase91()
		assert.Nil(t, encoder.Error)

		decoder := NewDecoder().FromBytes(encoder.ToBytes()).ByBase91()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, binaryData, decoder.ToBytes())
	})

	t.Run("mixed encoding methods", func(t *testing.T) {
		testData := "hello world"

		encoder1 := NewEncoder().FromString(testData).ByBase91()
		encoder2 := NewEncoder().FromBytes([]byte(testData)).ByBase91()
		encoder3 := NewEncoder().FromFile(mock.NewFile([]byte(testData), "test.txt")).ByBase91()

		assert.Nil(t, encoder1.Error)
		assert.Nil(t, encoder2.Error)
		assert.Nil(t, encoder3.Error)
		assert.Equal(t, encoder1.ToString(), encoder2.ToString())
		assert.Equal(t, encoder1.ToString(), encoder3.ToString())
	})

	t.Run("zero bytes", func(t *testing.T) {
		zeroData := []byte{0x00, 0x00, 0x00, 0x00}

		encoder := NewEncoder().FromBytes(zeroData).ByBase91()
		assert.Nil(t, encoder.Error)

		decoder := NewDecoder().FromBytes(encoder.ToBytes()).ByBase91()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, zeroData, decoder.ToBytes())
	})

	t.Run("max bytes", func(t *testing.T) {
		maxData := []byte{0xFF, 0xFF, 0xFF, 0xFF}

		encoder := NewEncoder().FromBytes(maxData).ByBase91()
		assert.Nil(t, encoder.Error)

		decoder := NewDecoder().FromBytes(encoder.ToBytes()).ByBase91()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, maxData, decoder.ToBytes())
	})

	t.Run("all possible byte values", func(t *testing.T) {
		allBytes := make([]byte, 256)
		for i := 0; i < 256; i++ {
			allBytes[i] = byte(i)
		}

		encoder := NewEncoder().FromBytes(allBytes).ByBase91()
		assert.Nil(t, encoder.Error)

		decoder := NewDecoder().FromBytes(encoder.ToBytes()).ByBase91()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, allBytes, decoder.ToBytes())
	})
}

func TestBase91Specific(t *testing.T) {
	t.Run("base91 alphabet verification", func(t *testing.T) {
		testData := []byte{0x00, 0x01, 0x02}
		encoder := NewEncoder().FromBytes(testData).ByBase91()
		assert.Nil(t, encoder.Error)

		resultStr := encoder.ToString()
		base91Alphabet := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!#$%&()*+,./:;<=>?@[]^_`{|}~\""
		for _, char := range resultStr {
			assert.Contains(t, base91Alphabet, string(char))
		}
	})

	t.Run("base91 encoding consistency", func(t *testing.T) {
		testData := []byte("Hello, World!")
		encoder := NewEncoder().FromBytes(testData).ByBase91()
		assert.Nil(t, encoder.Error)

		decoder := NewDecoder().FromBytes(encoder.ToBytes()).ByBase91()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, testData, decoder.ToBytes())
	})

	t.Run("base91 vs string vs bytes consistency", func(t *testing.T) {
		testData := "hello world"

		encoder1 := NewEncoder().FromString(testData).ByBase91()
		encoder2 := NewEncoder().FromBytes([]byte(testData)).ByBase91()
		encoder3 := NewEncoder().FromFile(mock.NewFile([]byte(testData), "test.txt")).ByBase91()

		assert.Nil(t, encoder1.Error)
		assert.Nil(t, encoder2.Error)
		assert.Nil(t, encoder3.Error)
		assert.Equal(t, encoder1.ToString(), encoder2.ToString())
		assert.Equal(t, encoder1.ToString(), encoder3.ToString())
	})

	t.Run("base91 specific test cases", func(t *testing.T) {
		// Test specific Base91 encoding patterns (generated using dongle implementation)
		testCases := []struct {
			input    []byte
			expected string
		}{
			{[]byte{0x00}, "AA"},
			{[]byte{0x00, 0x00}, "AAA"},
			{[]byte{0x00, 0x00, 0x00}, "AAAA"},
			{[]byte{0xFF}, "/C"},
			{[]byte{0xFF, 0xFF}, "B\"H"},
			{[]byte{0xFF, 0xFF, 0xFF}, "B\"tW"},
		}

		for _, tc := range testCases {
			encoder := NewEncoder().FromBytes(tc.input).ByBase91()
			assert.Nil(t, encoder.Error)
			assert.Equal(t, tc.expected, encoder.ToString())

			decoder := NewDecoder().FromString(tc.expected).ByBase91()
			assert.Nil(t, decoder.Error)
			assert.Equal(t, tc.input, decoder.ToBytes())
		}
	})
}
