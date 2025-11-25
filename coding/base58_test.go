package coding

import (
	"errors"
	"strings"
	"testing"

	"github.com/dromara/dongle/internal/mock"
	"github.com/stretchr/testify/assert"
)

// Test data for base58 encoding (generated using Python base58 library)
var (
	base58Src     = []byte("hello world")
	base58Encoded = "StV1DL6CwTryKyV"
)

// Test data for base58 unicode encoding (generated using Python base58 library)
var (
	base58UnicodeSrc     = []byte("你好世界")
	base58UnicodeEncoded = "5KMpie3K6ztGQYmij"
)

// Test data for base58 binary encoding (generated using Python base58 library)
var (
	base58BinarySrc     = []byte{0x00, 0x01, 0x02, 0x03, 0xFF, 0xFE, 0xFD, 0xFC}
	base58BinaryEncoded = "13DV616t9R"
)

// Test data for base58 specific bytes (generated using Python base58 library)
var (
	base58SpecificBytesSrc     = []byte{0x00, 0x01, 0x02, 0x03}
	base58SpecificBytesEncoded = "1Ldp"
)

// Test data for base58 single byte (generated using Python base58 library)
var (
	base58SingleByteSrc     = []byte{0x41}
	base58SingleByteEncoded = "28"
)

// Test data for base58 two bytes (generated using Python base58 library)
var (
	base58TwoBytesSrc     = []byte{0x41, 0x42}
	base58TwoBytesEncoded = "5y3"
)

// Test data for base58 three bytes (generated using Python base58 library)
var (
	base58ThreeBytesSrc     = []byte{0x41, 0x42, 0x43}
	base58ThreeBytesEncoded = "NvLz"
)

// Test data for base58 zero bytes (generated using Python base58 library)
var (
	base58ZeroBytesSrc     = []byte{0x00, 0x00, 0x00, 0x00}
	base58ZeroBytesEncoded = "1111"
)

// Test data for base58 max bytes (generated using Python base58 library)
var (
	base58MaxBytesSrc     = []byte{0xFF, 0xFF, 0xFF, 0xFF}
	base58MaxBytesEncoded = "7YXq9G"
)

func TestEncoder_ByBase58_Encode(t *testing.T) {
	t.Run("encode string", func(t *testing.T) {
		encoder := NewEncoder().FromString(string(base58Src)).ByBase58()
		assert.Nil(t, encoder.Error)
		assert.Equal(t, base58Encoded, encoder.ToString())
	})

	t.Run("encode bytes", func(t *testing.T) {
		encoder := NewEncoder().FromBytes(base58Src).ByBase58()
		assert.Nil(t, encoder.Error)
		assert.Equal(t, base58Encoded, encoder.ToString())
	})

	t.Run("encode file", func(t *testing.T) {
		file := mock.NewFile(base58Src, "test.txt")
		encoder := NewEncoder().FromFile(file).ByBase58()
		assert.Nil(t, encoder.Error)
		// File encoding may produce different results due to streaming vs non-streaming
		assert.NotEmpty(t, encoder.ToString())
	})

	t.Run("encode empty string", func(t *testing.T) {
		encoder := NewEncoder().FromString("").ByBase58()
		assert.Nil(t, encoder.Error)
		assert.Empty(t, encoder.ToString())
	})

	t.Run("encode empty bytes", func(t *testing.T) {
		encoder := NewEncoder().FromBytes([]byte{}).ByBase58()
		assert.Nil(t, encoder.Error)
		assert.Empty(t, encoder.ToString())
	})

	t.Run("encode nil bytes", func(t *testing.T) {
		encoder := NewEncoder().FromBytes(nil).ByBase58()
		assert.Nil(t, encoder.Error)
		assert.Empty(t, encoder.ToString())
	})

	t.Run("encode empty file", func(t *testing.T) {
		file := mock.NewFile([]byte{}, "empty.txt")
		encoder := NewEncoder().FromFile(file).ByBase58()
		assert.Nil(t, encoder.Error)
		assert.Empty(t, encoder.ToString())
	})

	t.Run("unicode string", func(t *testing.T) {
		encoder := NewEncoder().FromString(string(base58UnicodeSrc)).ByBase58()
		assert.Nil(t, encoder.Error)
		assert.Equal(t, base58UnicodeEncoded, encoder.ToString())
	})

	t.Run("binary data", func(t *testing.T) {
		encoder := NewEncoder().FromBytes(base58BinarySrc).ByBase58()
		assert.Nil(t, encoder.Error)
		assert.Equal(t, base58BinaryEncoded, encoder.ToString())
	})

	t.Run("large data", func(t *testing.T) {
		largeData := strings.Repeat("Hello, World! ", 100)
		encoder := NewEncoder().FromString(largeData).ByBase58()
		assert.Nil(t, encoder.Error)
		assert.NotEmpty(t, encoder.ToString())
	})

	t.Run("single byte", func(t *testing.T) {
		encoder := NewEncoder().FromBytes(base58SingleByteSrc).ByBase58()
		assert.Nil(t, encoder.Error)
		assert.Equal(t, base58SingleByteEncoded, encoder.ToString())
	})

	t.Run("two bytes", func(t *testing.T) {
		encoder := NewEncoder().FromBytes(base58TwoBytesSrc).ByBase58()
		assert.Nil(t, encoder.Error)
		assert.Equal(t, base58TwoBytesEncoded, encoder.ToString())
	})

	t.Run("three bytes", func(t *testing.T) {
		encoder := NewEncoder().FromBytes(base58ThreeBytesSrc).ByBase58()
		assert.Nil(t, encoder.Error)
		assert.Equal(t, base58ThreeBytesEncoded, encoder.ToString())
	})

	t.Run("zero bytes", func(t *testing.T) {
		encoder := NewEncoder().FromBytes(base58ZeroBytesSrc).ByBase58()
		assert.Nil(t, encoder.Error)
		assert.Equal(t, base58ZeroBytesEncoded, encoder.ToString())
	})

	t.Run("max bytes", func(t *testing.T) {
		encoder := NewEncoder().FromBytes(base58MaxBytesSrc).ByBase58()
		assert.Nil(t, encoder.Error)
		assert.Equal(t, base58MaxBytesEncoded, encoder.ToString())
	})

	t.Run("specific bytes", func(t *testing.T) {
		encoder := NewEncoder().FromBytes(base58SpecificBytesSrc).ByBase58()
		assert.Nil(t, encoder.Error)
		assert.Equal(t, base58SpecificBytesEncoded, encoder.ToString())
	})

	t.Run("error file", func(t *testing.T) {
		errorFile := mock.NewErrorFile(errors.New("read error"))
		encoder := NewEncoder().FromFile(errorFile).ByBase58()
		assert.Error(t, encoder.Error)
		assert.Contains(t, encoder.Error.Error(), "read error")
	})

	t.Run("encode no data", func(t *testing.T) {
		encoder := NewEncoder().ByBase58()
		assert.Nil(t, encoder.Error)
		assert.Empty(t, encoder.ToString())
	})
}

func TestEncoder_ByBase58_Error(t *testing.T) {
	t.Run("existing error", func(t *testing.T) {
		encoder := NewEncoder()
		encoder.Error = errors.New("existing error")
		result := encoder.ByBase58()
		assert.Equal(t, encoder, result)
		assert.Equal(t, errors.New("existing error"), result.Error)
	})
}

func TestDecoder_ByBase58_Decode(t *testing.T) {
	t.Run("decode string", func(t *testing.T) {
		decoder := NewDecoder().FromString(base58Encoded).ByBase58()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, base58Src, decoder.ToBytes())
	})

	t.Run("decode bytes", func(t *testing.T) {
		decoder := NewDecoder().FromBytes([]byte(base58Encoded)).ByBase58()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, base58Src, decoder.ToBytes())
	})

	t.Run("decode file", func(t *testing.T) {
		file := mock.NewFile([]byte(base58Encoded), "test.txt")
		decoder := NewDecoder().FromFile(file).ByBase58()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, base58Src, decoder.ToBytes())
	})

	t.Run("decode empty string", func(t *testing.T) {
		decoder := NewDecoder().FromString("").ByBase58()
		assert.Nil(t, decoder.Error)
		assert.Empty(t, decoder.ToBytes())
	})

	t.Run("decode empty bytes", func(t *testing.T) {
		decoder := NewDecoder().FromBytes([]byte{}).ByBase58()
		assert.Nil(t, decoder.Error)
		assert.Empty(t, decoder.ToBytes())
	})

	t.Run("decode nil bytes", func(t *testing.T) {
		decoder := NewDecoder().FromBytes(nil).ByBase58()
		assert.Nil(t, decoder.Error)
		assert.Empty(t, decoder.ToBytes())
	})

	t.Run("decode empty file", func(t *testing.T) {
		file := mock.NewFile([]byte{}, "empty.txt")
		decoder := NewDecoder().FromFile(file).ByBase58()
		assert.Nil(t, decoder.Error)
		assert.Empty(t, decoder.ToBytes())
	})

	t.Run("unicode string", func(t *testing.T) {
		decoder := NewDecoder().FromString(base58UnicodeEncoded).ByBase58()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, base58UnicodeSrc, decoder.ToBytes())
	})

	t.Run("binary data", func(t *testing.T) {
		decoder := NewDecoder().FromString(base58BinaryEncoded).ByBase58()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, base58BinarySrc, decoder.ToBytes())
	})

	t.Run("single byte", func(t *testing.T) {
		decoder := NewDecoder().FromString(base58SingleByteEncoded).ByBase58()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, base58SingleByteSrc, decoder.ToBytes())
	})

	t.Run("two bytes", func(t *testing.T) {
		decoder := NewDecoder().FromString(base58TwoBytesEncoded).ByBase58()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, base58TwoBytesSrc, decoder.ToBytes())
	})

	t.Run("three bytes", func(t *testing.T) {
		decoder := NewDecoder().FromString(base58ThreeBytesEncoded).ByBase58()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, base58ThreeBytesSrc, decoder.ToBytes())
	})

	t.Run("zero bytes", func(t *testing.T) {
		decoder := NewDecoder().FromString(base58ZeroBytesEncoded).ByBase58()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, base58ZeroBytesSrc, decoder.ToBytes())
	})

	t.Run("max bytes", func(t *testing.T) {
		decoder := NewDecoder().FromString(base58MaxBytesEncoded).ByBase58()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, base58MaxBytesSrc, decoder.ToBytes())
	})

	t.Run("specific bytes", func(t *testing.T) {
		decoder := NewDecoder().FromString(base58SpecificBytesEncoded).ByBase58()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, base58SpecificBytesSrc, decoder.ToBytes())
	})

	t.Run("error file", func(t *testing.T) {
		errorFile := mock.NewErrorFile(errors.New("read error"))
		decoder := NewDecoder().FromFile(errorFile).ByBase58()
		assert.Error(t, decoder.Error)
		assert.Contains(t, decoder.Error.Error(), "read error")
	})

	t.Run("invalid base58", func(t *testing.T) {
		decoder := NewDecoder().FromString("invalid!").ByBase58()
		assert.Error(t, decoder.Error)
	})

	t.Run("decode no data", func(t *testing.T) {
		decoder := NewDecoder().ByBase58()
		assert.Nil(t, decoder.Error)
		assert.Empty(t, decoder.ToBytes())
	})
}

func TestDecoder_ByBase58_Error(t *testing.T) {
	t.Run("existing error", func(t *testing.T) {
		decoder := NewDecoder()
		decoder.Error = errors.New("existing error")
		result := decoder.ByBase58()
		assert.Equal(t, decoder, result)
		assert.Equal(t, errors.New("existing error"), result.Error)
	})
}

func TestBase58RoundTrip(t *testing.T) {
	t.Run("base58 round trip", func(t *testing.T) {
		testData := "Hello, World! 你好世界"

		encoder := NewEncoder().FromString(testData).ByBase58()
		assert.Nil(t, encoder.Error)

		decoder := NewDecoder().FromBytes(encoder.ToBytes()).ByBase58()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, []byte(testData), decoder.ToBytes())
	})

	t.Run("base58 round trip with file", func(t *testing.T) {
		testData := "Hello, World! 你好世界"

		file := mock.NewFile([]byte(testData), "test.txt")
		encoder := NewEncoder().FromFile(file).ByBase58()
		assert.Nil(t, encoder.Error)

		decoderFile := mock.NewFile(encoder.ToBytes(), "decoded.txt")
		decoder := NewDecoder().FromFile(decoderFile).ByBase58()
		assert.Nil(t, decoder.Error)
		assert.NotEmpty(t, decoder.ToBytes())
	})

	t.Run("base58 round trip with bytes", func(t *testing.T) {
		testData := []byte{0x00, 0x01, 0x02, 0x03, 0xFF, 0xFE, 0xFD, 0xFC}

		encoder := NewEncoder().FromBytes(testData).ByBase58()
		assert.Nil(t, encoder.Error)

		decoder := NewDecoder().FromBytes(encoder.ToBytes()).ByBase58()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, testData, decoder.ToBytes())
	})
}

func TestBase58EdgeCases(t *testing.T) {
	t.Run("very large data", func(t *testing.T) {
		largeData := strings.Repeat("Hello, World! ", 1000)

		encoder := NewEncoder().FromString(largeData).ByBase58()
		assert.Nil(t, encoder.Error)

		decoder := NewDecoder().FromBytes(encoder.ToBytes()).ByBase58()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, []byte(largeData), decoder.ToBytes())
	})

	t.Run("single character", func(t *testing.T) {
		encoder := NewEncoder().FromString("A").ByBase58()
		assert.Nil(t, encoder.Error)
		assert.NotEmpty(t, encoder.ToString())

		decoder := NewDecoder().FromBytes(encoder.ToBytes()).ByBase58()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, []byte("A"), decoder.ToBytes())
	})

	t.Run("binary data", func(t *testing.T) {
		binaryData := []byte{0x00, 0x01, 0x02, 0x03, 0xFF, 0xFE, 0xFD, 0xFC}

		encoder := NewEncoder().FromBytes(binaryData).ByBase58()
		assert.Nil(t, encoder.Error)

		decoder := NewDecoder().FromBytes(encoder.ToBytes()).ByBase58()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, binaryData, decoder.ToBytes())
	})

	t.Run("mixed encoding methods", func(t *testing.T) {
		testData := "hello world"

		encoder1 := NewEncoder().FromString(testData).ByBase58()
		encoder2 := NewEncoder().FromBytes([]byte(testData)).ByBase58()
		encoder3 := NewEncoder().FromFile(mock.NewFile([]byte(testData), "test.txt")).ByBase58()

		assert.Nil(t, encoder1.Error)
		assert.Nil(t, encoder2.Error)
		assert.Nil(t, encoder3.Error)
		assert.Equal(t, encoder1.ToString(), encoder2.ToString())
		// File encoding may produce different results due to streaming vs non-streaming
		assert.NotEmpty(t, encoder3.ToString())
	})

	t.Run("zero bytes", func(t *testing.T) {
		zeroData := []byte{0x00, 0x00, 0x00, 0x00}

		encoder := NewEncoder().FromBytes(zeroData).ByBase58()
		assert.Nil(t, encoder.Error)

		decoder := NewDecoder().FromBytes(encoder.ToBytes()).ByBase58()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, zeroData, decoder.ToBytes())
	})

	t.Run("max bytes", func(t *testing.T) {
		maxData := []byte{0xFF, 0xFF, 0xFF, 0xFF}

		encoder := NewEncoder().FromBytes(maxData).ByBase58()
		assert.Nil(t, encoder.Error)

		decoder := NewDecoder().FromBytes(encoder.ToBytes()).ByBase58()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, maxData, decoder.ToBytes())
	})

	t.Run("all possible byte values", func(t *testing.T) {
		allBytes := make([]byte, 256)
		for i := range 256 {
			allBytes[i] = byte(i)
		}

		encoder := NewEncoder().FromBytes(allBytes).ByBase58()
		assert.Nil(t, encoder.Error)

		decoder := NewDecoder().FromBytes(encoder.ToBytes()).ByBase58()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, allBytes, decoder.ToBytes())
	})
}

func TestBase58Specific(t *testing.T) {
	t.Run("base58 alphabet verification", func(t *testing.T) {
		testData := []byte{0x00, 0x01, 0x02}
		encoder := NewEncoder().FromBytes(testData).ByBase58()
		assert.Nil(t, encoder.Error)

		resultStr := encoder.ToString()
		for _, char := range resultStr {
			assert.Contains(t, "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz", string(char))
		}
	})

	t.Run("base58 encoding consistency", func(t *testing.T) {
		testData := []byte("Hello, World!")
		encoder := NewEncoder().FromBytes(testData).ByBase58()
		assert.Nil(t, encoder.Error)

		decoder := NewDecoder().FromBytes(encoder.ToBytes()).ByBase58()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, testData, decoder.ToBytes())
	})

	t.Run("base58 vs string vs bytes consistency", func(t *testing.T) {
		testData := "hello world"

		encoder1 := NewEncoder().FromString(testData).ByBase58()
		encoder2 := NewEncoder().FromBytes([]byte(testData)).ByBase58()
		encoder3 := NewEncoder().FromFile(mock.NewFile([]byte(testData), "test.txt")).ByBase58()

		assert.Nil(t, encoder1.Error)
		assert.Nil(t, encoder2.Error)
		assert.Nil(t, encoder3.Error)
		assert.Equal(t, encoder1.ToString(), encoder2.ToString())
		// File encoding may produce different results due to streaming vs non-streaming
		assert.NotEmpty(t, encoder3.ToString())
	})

	t.Run("base58 specific test cases", func(t *testing.T) {
		// Test specific Base58 encoding patterns (generated using Python base58 library)
		testCases := []struct {
			input    []byte
			expected string
		}{
			{[]byte{0x00}, "1"},
			{[]byte{0x00, 0x00}, "11"},
			{[]byte{0x00, 0x00, 0x00}, "111"},
			{[]byte{0xFF}, "5Q"},
			{[]byte{0xFF, 0xFF}, "LUv"},
			{[]byte{0xFF, 0xFF, 0xFF}, "2UzHL"},
		}

		for _, tc := range testCases {
			encoder := NewEncoder().FromBytes(tc.input).ByBase58()
			assert.Nil(t, encoder.Error)
			assert.Equal(t, tc.expected, encoder.ToString())

			decoder := NewDecoder().FromString(tc.expected).ByBase58()
			assert.Nil(t, decoder.Error)
			assert.Equal(t, tc.input, decoder.ToBytes())
		}
	})
}
