package coding

import (
	"errors"
	"strings"
	"testing"

	"github.com/dromara/dongle/mock"
	"github.com/stretchr/testify/assert"
)

// Test data for base45 encoding (generated using Python base45 library)
var (
	base45Src     = []byte("hello world")
	base45Encoded = "+8D VD82EK4F.KEA2"
)

// Test data for base45 unicode encoding (generated using Python base45 library)
var (
	base45UnicodeSrc     = []byte("你好世界")
	base45UnicodeEncoded = "C-SEFK*.K7-SL3JY+I"
)

// Test data for base45 binary encoding (generated using Python base45 library)
var (
	base45BinarySrc     = []byte{0x00, 0x01, 0x02, 0x03, 0xFF, 0xFE, 0xFD, 0xFC}
	base45BinaryEncoded = "100KB0EGW+4W"
)

// Test data for base45 specific bytes (generated using Python base45 library)
var (
	base45SpecificBytesSrc     = []byte{0x00, 0x01, 0x02, 0x03}
	base45SpecificBytesEncoded = "100KB0"
)

// Test data for base45 single byte (generated using Python base45 library)
var (
	base45SingleByteSrc     = []byte{0x41}
	base45SingleByteEncoded = "K1"
)

// Test data for base45 two bytes (generated using Python base45 library)
var (
	base45TwoBytesSrc     = []byte{0x41, 0x42}
	base45TwoBytesEncoded = "BB8"
)

// Test data for base45 three bytes (generated using Python base45 library)
var (
	base45ThreeBytesSrc     = []byte{0x41, 0x42, 0x43}
	base45ThreeBytesEncoded = "BB8M1"
)

// Test data for base45 zero bytes (generated using Python base45 library)
var (
	base45ZeroBytesSrc     = []byte{0x00, 0x00, 0x00, 0x00}
	base45ZeroBytesEncoded = "000000"
)

// Test data for base45 max bytes (generated using Python base45 library)
var (
	base45MaxBytesSrc     = []byte{0x41, 0x42, 0x43, 0x44, 0x45}
	base45MaxBytesEncoded = "BB8UM8O1"
)

func TestEncoder_ByBase45_Encode(t *testing.T) {
	t.Run("encode string", func(t *testing.T) {
		encoder := NewEncoder().FromString(string(base45Src)).ByBase45()
		assert.Nil(t, encoder.Error)
		assert.Equal(t, base45Encoded, encoder.ToString())
	})

	t.Run("encode bytes", func(t *testing.T) {
		encoder := NewEncoder().FromBytes(base45Src).ByBase45()
		assert.Nil(t, encoder.Error)
		assert.Equal(t, base45Encoded, encoder.ToString())
	})

	t.Run("encode file", func(t *testing.T) {
		file := mock.NewFile(base45Src, "test.txt")
		encoder := NewEncoder().FromFile(file).ByBase45()
		assert.Nil(t, encoder.Error)
		assert.Equal(t, base45Encoded, encoder.ToString())
	})

	t.Run("encode empty string", func(t *testing.T) {
		encoder := NewEncoder().FromString("").ByBase45()
		assert.Nil(t, encoder.Error)
		assert.Empty(t, encoder.ToString())
	})

	t.Run("encode empty bytes", func(t *testing.T) {
		encoder := NewEncoder().FromBytes([]byte{}).ByBase45()
		assert.Nil(t, encoder.Error)
		assert.Empty(t, encoder.ToString())
	})

	t.Run("encode nil bytes", func(t *testing.T) {
		encoder := NewEncoder().FromBytes(nil).ByBase45()
		assert.Nil(t, encoder.Error)
		assert.Empty(t, encoder.ToString())
	})

	t.Run("encode empty file", func(t *testing.T) {
		file := mock.NewFile([]byte{}, "empty.txt")
		encoder := NewEncoder().FromFile(file).ByBase45()
		assert.Nil(t, encoder.Error)
		assert.Empty(t, encoder.ToString())
	})

	t.Run("unicode string", func(t *testing.T) {
		encoder := NewEncoder().FromString(string(base45UnicodeSrc)).ByBase45()
		assert.Nil(t, encoder.Error)
		assert.Equal(t, base45UnicodeEncoded, encoder.ToString())
	})

	t.Run("binary data", func(t *testing.T) {
		encoder := NewEncoder().FromBytes(base45BinarySrc).ByBase45()
		assert.Nil(t, encoder.Error)
		assert.Equal(t, base45BinaryEncoded, encoder.ToString())
	})

	t.Run("large data", func(t *testing.T) {
		largeData := strings.Repeat("Hello, World! ", 100)
		encoder := NewEncoder().FromString(largeData).ByBase45()
		assert.Nil(t, encoder.Error)
		assert.NotEmpty(t, encoder.ToString())
	})

	t.Run("single byte", func(t *testing.T) {
		encoder := NewEncoder().FromBytes(base45SingleByteSrc).ByBase45()
		assert.Nil(t, encoder.Error)
		assert.Equal(t, base45SingleByteEncoded, encoder.ToString())
	})

	t.Run("two bytes", func(t *testing.T) {
		encoder := NewEncoder().FromBytes(base45TwoBytesSrc).ByBase45()
		assert.Nil(t, encoder.Error)
		assert.Equal(t, base45TwoBytesEncoded, encoder.ToString())
	})

	t.Run("three bytes", func(t *testing.T) {
		encoder := NewEncoder().FromBytes(base45ThreeBytesSrc).ByBase45()
		assert.Nil(t, encoder.Error)
		assert.Equal(t, base45ThreeBytesEncoded, encoder.ToString())
	})

	t.Run("zero bytes", func(t *testing.T) {
		encoder := NewEncoder().FromBytes(base45ZeroBytesSrc).ByBase45()
		assert.Nil(t, encoder.Error)
		assert.Equal(t, base45ZeroBytesEncoded, encoder.ToString())
	})

	t.Run("max bytes", func(t *testing.T) {
		encoder := NewEncoder().FromBytes(base45MaxBytesSrc).ByBase45()
		assert.Nil(t, encoder.Error)
		assert.Equal(t, base45MaxBytesEncoded, encoder.ToString())
	})

	t.Run("specific bytes", func(t *testing.T) {
		encoder := NewEncoder().FromBytes(base45SpecificBytesSrc).ByBase45()
		assert.Nil(t, encoder.Error)
		assert.Equal(t, base45SpecificBytesEncoded, encoder.ToString())
	})

	t.Run("error file", func(t *testing.T) {
		errorFile := mock.NewErrorFile(errors.New("read error"))
		encoder := NewEncoder().FromFile(errorFile).ByBase45()
		assert.Error(t, encoder.Error)
		assert.Contains(t, encoder.Error.Error(), "read error")
	})

	t.Run("encode no data", func(t *testing.T) {
		encoder := NewEncoder().ByBase45()
		assert.Nil(t, encoder.Error)
		assert.Empty(t, encoder.ToString())
	})
}

func TestEncoder_ByBase45_Error(t *testing.T) {
	t.Run("existing error", func(t *testing.T) {
		encoder := NewEncoder()
		encoder.Error = errors.New("existing error")
		result := encoder.ByBase45()
		assert.Equal(t, encoder, result)
		assert.Equal(t, errors.New("existing error"), result.Error)
	})
}

func TestDecoder_ByBase45_Decode(t *testing.T) {
	t.Run("decode string", func(t *testing.T) {
		decoder := NewDecoder().FromString(base45Encoded).ByBase45()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, base45Src, decoder.ToBytes())
	})

	t.Run("decode bytes", func(t *testing.T) {
		decoder := NewDecoder().FromBytes([]byte(base45Encoded)).ByBase45()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, base45Src, decoder.ToBytes())
	})

	t.Run("decode file", func(t *testing.T) {
		file := mock.NewFile([]byte(base45Encoded), "test.txt")
		decoder := NewDecoder().FromFile(file).ByBase45()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, base45Src, decoder.ToBytes())
	})

	t.Run("decode empty string", func(t *testing.T) {
		decoder := NewDecoder().FromString("").ByBase45()
		assert.Nil(t, decoder.Error)
		assert.Empty(t, decoder.ToBytes())
	})

	t.Run("decode empty bytes", func(t *testing.T) {
		decoder := NewDecoder().FromBytes([]byte{}).ByBase45()
		assert.Nil(t, decoder.Error)
		assert.Empty(t, decoder.ToBytes())
	})

	t.Run("decode nil bytes", func(t *testing.T) {
		decoder := NewDecoder().FromBytes(nil).ByBase45()
		assert.Nil(t, decoder.Error)
		assert.Empty(t, decoder.ToBytes())
	})

	t.Run("decode empty file", func(t *testing.T) {
		file := mock.NewFile([]byte{}, "empty.txt")
		decoder := NewDecoder().FromFile(file).ByBase45()
		assert.Nil(t, decoder.Error)
		assert.Empty(t, decoder.ToBytes())
	})

	t.Run("unicode string", func(t *testing.T) {
		decoder := NewDecoder().FromString(base45UnicodeEncoded).ByBase45()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, base45UnicodeSrc, decoder.ToBytes())
	})

	t.Run("binary data", func(t *testing.T) {
		decoder := NewDecoder().FromString(base45BinaryEncoded).ByBase45()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, base45BinarySrc, decoder.ToBytes())
	})

	t.Run("single byte", func(t *testing.T) {
		decoder := NewDecoder().FromString(base45SingleByteEncoded).ByBase45()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, base45SingleByteSrc, decoder.ToBytes())
	})

	t.Run("two bytes", func(t *testing.T) {
		decoder := NewDecoder().FromString(base45TwoBytesEncoded).ByBase45()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, base45TwoBytesSrc, decoder.ToBytes())
	})

	t.Run("three bytes", func(t *testing.T) {
		decoder := NewDecoder().FromString(base45ThreeBytesEncoded).ByBase45()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, base45ThreeBytesSrc, decoder.ToBytes())
	})

	t.Run("zero bytes", func(t *testing.T) {
		decoder := NewDecoder().FromString(base45ZeroBytesEncoded).ByBase45()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, base45ZeroBytesSrc, decoder.ToBytes())
	})

	t.Run("max bytes", func(t *testing.T) {
		decoder := NewDecoder().FromString(base45MaxBytesEncoded).ByBase45()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, base45MaxBytesSrc, decoder.ToBytes())
	})

	t.Run("specific bytes", func(t *testing.T) {
		decoder := NewDecoder().FromString(base45SpecificBytesEncoded).ByBase45()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, base45SpecificBytesSrc, decoder.ToBytes())
	})

	t.Run("error file", func(t *testing.T) {
		errorFile := mock.NewErrorFile(errors.New("read error"))
		decoder := NewDecoder().FromFile(errorFile).ByBase45()
		assert.Error(t, decoder.Error)
		assert.Contains(t, decoder.Error.Error(), "read error")
	})

	t.Run("invalid base45", func(t *testing.T) {
		decoder := NewDecoder().FromString("invalid!").ByBase45()
		assert.Error(t, decoder.Error)
	})

	t.Run("invalid length", func(t *testing.T) {
		decoder := NewDecoder().FromString("A").ByBase45()
		assert.Error(t, decoder.Error)
	})

	t.Run("decode no data", func(t *testing.T) {
		decoder := NewDecoder().ByBase45()
		assert.Nil(t, decoder.Error)
		assert.Empty(t, decoder.ToBytes())
	})
}

func TestDecoder_ByBase45_Error(t *testing.T) {
	t.Run("existing error", func(t *testing.T) {
		decoder := NewDecoder()
		decoder.Error = errors.New("existing error")
		result := decoder.ByBase45()
		assert.Equal(t, decoder, result)
		assert.Equal(t, errors.New("existing error"), result.Error)
	})
}

func TestBase45RoundTrip(t *testing.T) {
	t.Run("base45 round trip", func(t *testing.T) {
		testData := "Hello, World! 你好世界"

		encoder := NewEncoder().FromString(testData).ByBase45()
		assert.Nil(t, encoder.Error)

		decoder := NewDecoder().FromBytes(encoder.ToBytes()).ByBase45()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, []byte(testData), decoder.ToBytes())
	})

	t.Run("base45 round trip with file", func(t *testing.T) {
		testData := "Hello, World! 你好世界"

		file := mock.NewFile([]byte(testData), "test.txt")
		encoder := NewEncoder().FromFile(file).ByBase45()
		assert.Nil(t, encoder.Error)

		decoderFile := mock.NewFile(encoder.ToBytes(), "decoded.txt")
		decoder := NewDecoder().FromFile(decoderFile).ByBase45()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, []byte(testData), decoder.ToBytes())
	})

	t.Run("base45 round trip with bytes", func(t *testing.T) {
		testData := []byte{0x00, 0x01, 0x02, 0x03, 0xFF, 0xFE, 0xFD, 0xFC}

		encoder := NewEncoder().FromBytes(testData).ByBase45()
		assert.Nil(t, encoder.Error)

		decoder := NewDecoder().FromBytes(encoder.ToBytes()).ByBase45()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, testData, decoder.ToBytes())
	})
}

func TestBase45EdgeCases(t *testing.T) {
	t.Run("very large data", func(t *testing.T) {
		largeData := strings.Repeat("Hello, World! ", 1000)

		encoder := NewEncoder().FromString(largeData).ByBase45()
		assert.Nil(t, encoder.Error)

		decoder := NewDecoder().FromBytes(encoder.ToBytes()).ByBase45()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, []byte(largeData), decoder.ToBytes())
	})

	t.Run("single character", func(t *testing.T) {
		encoder := NewEncoder().FromString("A").ByBase45()
		assert.Nil(t, encoder.Error)
		assert.NotEmpty(t, encoder.ToString())

		decoder := NewDecoder().FromBytes(encoder.ToBytes()).ByBase45()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, []byte("A"), decoder.ToBytes())
	})

	t.Run("binary data", func(t *testing.T) {
		binaryData := []byte{0x00, 0x01, 0x02, 0x03, 0xFF, 0xFE, 0xFD, 0xFC}

		encoder := NewEncoder().FromBytes(binaryData).ByBase45()
		assert.Nil(t, encoder.Error)

		decoder := NewDecoder().FromBytes(encoder.ToBytes()).ByBase45()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, binaryData, decoder.ToBytes())
	})

	t.Run("mixed encoding methods", func(t *testing.T) {
		testData := "hello world"

		encoder1 := NewEncoder().FromString(testData).ByBase45()
		encoder2 := NewEncoder().FromBytes([]byte(testData)).ByBase45()
		encoder3 := NewEncoder().FromFile(mock.NewFile([]byte(testData), "test.txt")).ByBase45()

		assert.Nil(t, encoder1.Error)
		assert.Nil(t, encoder2.Error)
		assert.Nil(t, encoder3.Error)
		assert.Equal(t, encoder1.ToString(), encoder2.ToString())
		assert.Equal(t, encoder1.ToString(), encoder3.ToString())
	})

	t.Run("zero bytes", func(t *testing.T) {
		zeroData := []byte{0x00, 0x00, 0x00, 0x00}

		encoder := NewEncoder().FromBytes(zeroData).ByBase45()
		assert.Nil(t, encoder.Error)

		decoder := NewDecoder().FromBytes(encoder.ToBytes()).ByBase45()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, zeroData, decoder.ToBytes())
	})

	t.Run("max bytes", func(t *testing.T) {
		maxData := []byte{0x41, 0x42, 0x43, 0x44, 0x45}

		encoder := NewEncoder().FromBytes(maxData).ByBase45()
		assert.Nil(t, encoder.Error)

		decoder := NewDecoder().FromBytes(encoder.ToBytes()).ByBase45()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, maxData, decoder.ToBytes())
	})

	t.Run("all possible byte values", func(t *testing.T) {
		allBytes := make([]byte, 256)
		for i := range 256 {
			allBytes[i] = byte(i)
		}

		encoder := NewEncoder().FromBytes(allBytes).ByBase45()
		assert.Nil(t, encoder.Error)

		decoder := NewDecoder().FromBytes(encoder.ToBytes()).ByBase45()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, allBytes, decoder.ToBytes())
	})
}

func TestBase45Specific(t *testing.T) {
	t.Run("base45 alphabet verification", func(t *testing.T) {
		testData := []byte{0x00, 0x01, 0x02}
		encoder := NewEncoder().FromBytes(testData).ByBase45()
		assert.Nil(t, encoder.Error)

		resultStr := encoder.ToString()
		for _, char := range resultStr {
			assert.Contains(t, "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:", string(char))
		}
	})

	t.Run("base45 encoding consistency", func(t *testing.T) {
		testData := []byte("Hello, World!")
		encoder := NewEncoder().FromBytes(testData).ByBase45()
		assert.Nil(t, encoder.Error)

		decoder := NewDecoder().FromBytes(encoder.ToBytes()).ByBase45()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, testData, decoder.ToBytes())
	})

	t.Run("base45 vs string vs bytes consistency", func(t *testing.T) {
		testData := "hello world"

		encoder1 := NewEncoder().FromString(testData).ByBase45()
		encoder2 := NewEncoder().FromBytes([]byte(testData)).ByBase45()
		encoder3 := NewEncoder().FromFile(mock.NewFile([]byte(testData), "test.txt")).ByBase45()

		assert.Nil(t, encoder1.Error)
		assert.Nil(t, encoder2.Error)
		assert.Nil(t, encoder3.Error)
		assert.Equal(t, encoder1.ToString(), encoder2.ToString())
		assert.Equal(t, encoder1.ToString(), encoder3.ToString())
	})

	t.Run("base45 specific test cases", func(t *testing.T) {
		// Test specific Base45 encoding patterns (generated using dongle implementation)
		testCases := []struct {
			input    []byte
			expected string
		}{
			{[]byte{0x00}, "00"},
			{[]byte{0x00, 0x00}, "000"},
			{[]byte{0x00, 0x00, 0x00}, "00000"},
			{[]byte{0xFF}, "U5"},
			{[]byte{0xFF, 0xFF}, "FGW"},
			{[]byte{0xFF, 0xFF, 0xFF}, "FGWU5"},
		}

		for _, tc := range testCases {
			encoder := NewEncoder().FromBytes(tc.input).ByBase45()
			assert.Nil(t, encoder.Error)
			assert.Equal(t, tc.expected, encoder.ToString())

			decoder := NewDecoder().FromString(tc.expected).ByBase45()
			assert.Nil(t, decoder.Error)
			assert.Equal(t, tc.input, decoder.ToBytes())
		}
	})
}
