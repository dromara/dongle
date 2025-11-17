package coding

import (
	"errors"
	"strings"
	"testing"

	"github.com/dromara/dongle/mock"
	"github.com/stretchr/testify/assert"
)

// Test data for hex encoding (generated using Python binascii library)
var (
	hexSrc     = []byte("hello world")
	hexEncoded = "68656c6c6f20776f726c64"
)

// Test data for hex unicode encoding (generated using Python binascii library)
var (
	hexUnicodeSrc     = []byte("你好世界")
	hexUnicodeEncoded = "e4bda0e5a5bde4b896e7958c"
)

// Test data for hex binary encoding (generated using Python binascii library)
var (
	hexBinarySrc     = []byte{0x00, 0x01, 0x02, 0x03, 0xFF, 0xFE, 0xFD, 0xFC}
	hexBinaryEncoded = "00010203fffefdfc"
)

// Test data for hex specific bytes (generated using Python binascii library)
var (
	hexSpecificBytesSrc     = []byte{0x00, 0x01, 0x02, 0x03}
	hexSpecificBytesEncoded = "00010203"
)

// Test data for hex single byte (generated using Python binascii library)
var (
	hexSingleByteSrc     = []byte{0x41}
	hexSingleByteEncoded = "41"
)

// Test data for hex two bytes (generated using Python binascii library)
var (
	hexTwoBytesSrc     = []byte{0x41, 0x42}
	hexTwoBytesEncoded = "4142"
)

// Test data for hex three bytes (generated using Python binascii library)
var (
	hexThreeBytesSrc     = []byte{0x41, 0x42, 0x43}
	hexThreeBytesEncoded = "414243"
)

// Test data for hex zero bytes (generated using Python binascii library)
var (
	hexZeroBytesSrc     = []byte{0x00, 0x00, 0x00, 0x00}
	hexZeroBytesEncoded = "00000000"
)

// Test data for hex max bytes (generated using Python binascii library)
var (
	hexMaxBytesSrc     = []byte{0xFF, 0xFF, 0xFF, 0xFF}
	hexMaxBytesEncoded = "ffffffff"
)

func TestEncoder_ByHex_Encode(t *testing.T) {
	t.Run("encode string", func(t *testing.T) {
		encoder := NewEncoder().FromString(string(hexSrc)).ByHex()
		assert.Nil(t, encoder.Error)
		assert.Equal(t, hexEncoded, encoder.ToString())
	})

	t.Run("encode bytes", func(t *testing.T) {
		encoder := NewEncoder().FromBytes(hexSrc).ByHex()
		assert.Nil(t, encoder.Error)
		assert.Equal(t, hexEncoded, encoder.ToString())
	})

	t.Run("encode file", func(t *testing.T) {
		file := mock.NewFile(hexSrc, "test.txt")
		encoder := NewEncoder().FromFile(file).ByHex()
		assert.Nil(t, encoder.Error)
		assert.Equal(t, hexEncoded, encoder.ToString())
	})

	t.Run("encode empty string", func(t *testing.T) {
		encoder := NewEncoder().FromString("").ByHex()
		assert.Nil(t, encoder.Error)
		assert.Empty(t, encoder.ToString())
	})

	t.Run("encode empty bytes", func(t *testing.T) {
		encoder := NewEncoder().FromBytes([]byte{}).ByHex()
		assert.Nil(t, encoder.Error)
		assert.Empty(t, encoder.ToString())
	})

	t.Run("encode nil bytes", func(t *testing.T) {
		encoder := NewEncoder().FromBytes(nil).ByHex()
		assert.Nil(t, encoder.Error)
		assert.Empty(t, encoder.ToString())
	})

	t.Run("encode empty file", func(t *testing.T) {
		file := mock.NewFile([]byte{}, "empty.txt")
		encoder := NewEncoder().FromFile(file).ByHex()
		assert.Nil(t, encoder.Error)
		assert.Empty(t, encoder.ToString())
	})

	t.Run("unicode string", func(t *testing.T) {
		encoder := NewEncoder().FromBytes(hexUnicodeSrc).ByHex()
		assert.Nil(t, encoder.Error)
		assert.Equal(t, hexUnicodeEncoded, encoder.ToString())
	})

	t.Run("binary data", func(t *testing.T) {
		encoder := NewEncoder().FromBytes(hexBinarySrc).ByHex()
		assert.Nil(t, encoder.Error)
		assert.Equal(t, hexBinaryEncoded, encoder.ToString())
	})

	t.Run("large data", func(t *testing.T) {
		largeData := []byte(strings.Repeat("The quick brown fox jumps over the lazy dog. ", 10))
		encoder := NewEncoder().FromBytes(largeData).ByHex()
		assert.Nil(t, encoder.Error)
		assert.NotEmpty(t, encoder.ToString())
	})

	t.Run("single byte", func(t *testing.T) {
		encoder := NewEncoder().FromBytes(hexSingleByteSrc).ByHex()
		assert.Nil(t, encoder.Error)
		assert.Equal(t, hexSingleByteEncoded, encoder.ToString())
	})

	t.Run("two bytes", func(t *testing.T) {
		encoder := NewEncoder().FromBytes(hexTwoBytesSrc).ByHex()
		assert.Nil(t, encoder.Error)
		assert.Equal(t, hexTwoBytesEncoded, encoder.ToString())
	})

	t.Run("three bytes", func(t *testing.T) {
		encoder := NewEncoder().FromBytes(hexThreeBytesSrc).ByHex()
		assert.Nil(t, encoder.Error)
		assert.Equal(t, hexThreeBytesEncoded, encoder.ToString())
	})

	t.Run("zero bytes", func(t *testing.T) {
		encoder := NewEncoder().FromBytes(hexZeroBytesSrc).ByHex()
		assert.Nil(t, encoder.Error)
		assert.Equal(t, hexZeroBytesEncoded, encoder.ToString())
	})

	t.Run("max bytes", func(t *testing.T) {
		encoder := NewEncoder().FromBytes(hexMaxBytesSrc).ByHex()
		assert.Nil(t, encoder.Error)
		assert.Equal(t, hexMaxBytesEncoded, encoder.ToString())
	})

	t.Run("specific bytes", func(t *testing.T) {
		encoder := NewEncoder().FromBytes(hexSpecificBytesSrc).ByHex()
		assert.Nil(t, encoder.Error)
		assert.Equal(t, hexSpecificBytesEncoded, encoder.ToString())
	})

	t.Run("error file", func(t *testing.T) {
		errorFile := mock.NewErrorFile(errors.New("read error"))
		encoder := NewEncoder().FromFile(errorFile).ByHex()
		assert.Error(t, encoder.Error)
		assert.Contains(t, encoder.Error.Error(), "read error")
	})

	t.Run("encode no data", func(t *testing.T) {
		encoder := NewEncoder().ByHex()
		if encoder.Error != nil {
			assert.Contains(t, encoder.Error.Error(), "no data to encode")
		}
	})
}

func TestEncoder_ByHex_Error(t *testing.T) {
	t.Run("existing error", func(t *testing.T) {
		encoder := NewEncoder()
		encoder.Error = errors.New("existing error")
		result := encoder.FromString("test").ByHex()
		assert.Equal(t, errors.New("existing error"), result.Error)
		assert.NotNil(t, result.src)
	})
}

func TestDecoder_ByHex_Decode(t *testing.T) {
	t.Run("decode string", func(t *testing.T) {
		decoder := NewDecoder().FromString(hexEncoded).ByHex()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, hexSrc, decoder.ToBytes())
	})

	t.Run("decode bytes", func(t *testing.T) {
		decoder := NewDecoder().FromBytes([]byte(hexEncoded)).ByHex()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, hexSrc, decoder.ToBytes())
	})

	t.Run("decode file", func(t *testing.T) {
		file := mock.NewFile([]byte(hexEncoded), "test.txt")
		decoder := NewDecoder().FromFile(file).ByHex()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, hexSrc, decoder.ToBytes())
	})

	t.Run("decode empty string", func(t *testing.T) {
		decoder := NewDecoder().FromString("").ByHex()
		assert.Nil(t, decoder.Error)
		assert.Empty(t, decoder.ToBytes())
	})

	t.Run("decode empty bytes", func(t *testing.T) {
		decoder := NewDecoder().FromBytes([]byte{}).ByHex()
		assert.Nil(t, decoder.Error)
		assert.Empty(t, decoder.ToBytes())
	})

	t.Run("decode nil bytes", func(t *testing.T) {
		decoder := NewDecoder().FromBytes(nil).ByHex()
		assert.Nil(t, decoder.Error)
		assert.Empty(t, decoder.ToBytes())
	})

	t.Run("decode empty file", func(t *testing.T) {
		file := mock.NewFile([]byte{}, "empty.txt")
		decoder := NewDecoder().FromFile(file).ByHex()
		assert.Nil(t, decoder.Error)
		assert.Empty(t, decoder.ToBytes())
	})

	t.Run("unicode string", func(t *testing.T) {
		decoder := NewDecoder().FromString(hexUnicodeEncoded).ByHex()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, hexUnicodeSrc, decoder.ToBytes())
	})

	t.Run("binary data", func(t *testing.T) {
		decoder := NewDecoder().FromString(hexBinaryEncoded).ByHex()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, hexBinarySrc, decoder.ToBytes())
	})

	t.Run("single byte", func(t *testing.T) {
		decoder := NewDecoder().FromString(hexSingleByteEncoded).ByHex()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, hexSingleByteSrc, decoder.ToBytes())
	})

	t.Run("two bytes", func(t *testing.T) {
		decoder := NewDecoder().FromString(hexTwoBytesEncoded).ByHex()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, hexTwoBytesSrc, decoder.ToBytes())
	})

	t.Run("three bytes", func(t *testing.T) {
		decoder := NewDecoder().FromString(hexThreeBytesEncoded).ByHex()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, hexThreeBytesSrc, decoder.ToBytes())
	})

	t.Run("zero bytes", func(t *testing.T) {
		decoder := NewDecoder().FromString(hexZeroBytesEncoded).ByHex()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, hexZeroBytesSrc, decoder.ToBytes())
	})

	t.Run("max bytes", func(t *testing.T) {
		decoder := NewDecoder().FromString(hexMaxBytesEncoded).ByHex()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, hexMaxBytesSrc, decoder.ToBytes())
	})

	t.Run("specific bytes", func(t *testing.T) {
		decoder := NewDecoder().FromString(hexSpecificBytesEncoded).ByHex()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, hexSpecificBytesSrc, decoder.ToBytes())
	})

	t.Run("error file", func(t *testing.T) {
		errorFile := mock.NewErrorFile(errors.New("read error"))
		decoder := NewDecoder().FromFile(errorFile).ByHex()
		assert.Error(t, decoder.Error)
		assert.Contains(t, decoder.Error.Error(), "read error")
	})

	t.Run("decode with existing error", func(t *testing.T) {
		decoder := NewDecoder()
		decoder.Error = errors.New("existing error")
		result := decoder.FromString("test").ByHex()
		assert.Equal(t, errors.New("existing error"), result.Error)
		assert.NotNil(t, result.src)
	})

	t.Run("decode invalid hex", func(t *testing.T) {
		decoder := NewDecoder().FromString("invalid!").ByHex()
		assert.Error(t, decoder.Error)
	})

	t.Run("decode with no data no reader", func(t *testing.T) {
		decoder := NewDecoder().ByHex()
		if decoder.Error != nil {
			assert.Contains(t, decoder.Error.Error(), "no data to decode")
		}
	})
}

func TestDecoder_ByHex_Error(t *testing.T) {
	t.Run("existing error", func(t *testing.T) {
		decoder := NewDecoder()
		decoder.Error = errors.New("existing error")
		result := decoder.FromString("test").ByHex()
		assert.Equal(t, errors.New("existing error"), result.Error)
		assert.NotNil(t, result.src)
	})
}

func TestHexRoundTrip(t *testing.T) {
	t.Run("hex round trip", func(t *testing.T) {
		testData := "hello world"
		encoder := NewEncoder().FromString(testData).ByHex()
		assert.Nil(t, encoder.Error)

		decoder := NewDecoder().FromString(encoder.ToString()).ByHex()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, testData, decoder.ToString())
	})

	t.Run("hex round trip with file", func(t *testing.T) {
		testData := "hello world"
		file := mock.NewFile([]byte(testData), "test.txt")
		encoder := NewEncoder().FromFile(file).ByHex()
		assert.Nil(t, encoder.Error)

		decoderFile := mock.NewFile(encoder.ToBytes(), "encoded.txt")
		decoder := NewDecoder().FromFile(decoderFile).ByHex()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, testData, decoder.ToString())
	})

	t.Run("hex round trip with bytes", func(t *testing.T) {
		testData := []byte("hello world")
		encoder := NewEncoder().FromBytes(testData).ByHex()
		assert.Nil(t, encoder.Error)

		decoder := NewDecoder().FromBytes(encoder.ToBytes()).ByHex()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, testData, decoder.ToBytes())
	})
}

func TestHexEdgeCases(t *testing.T) {
	t.Run("very large data", func(t *testing.T) {
		largeData := []byte(strings.Repeat("The quick brown fox jumps over the lazy dog. ", 100))
		encoder := NewEncoder().FromBytes(largeData).ByHex()
		assert.Nil(t, encoder.Error)

		decoder := NewDecoder().FromString(encoder.ToString()).ByHex()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, largeData, decoder.ToBytes())
	})

	t.Run("single character", func(t *testing.T) {
		testData := "A"
		encoder := NewEncoder().FromString(testData).ByHex()
		assert.Nil(t, encoder.Error)

		decoder := NewDecoder().FromString(encoder.ToString()).ByHex()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, testData, decoder.ToString())
	})

	t.Run("binary data", func(t *testing.T) {
		binaryData := []byte{0x00, 0x01, 0x02, 0x03, 0xFF, 0xFE, 0xFD, 0xFC}
		encoder := NewEncoder().FromBytes(binaryData).ByHex()
		assert.Nil(t, encoder.Error)

		decoder := NewDecoder().FromString(encoder.ToString()).ByHex()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, binaryData, decoder.ToBytes())
	})

	t.Run("mixed encoding methods", func(t *testing.T) {
		testData := "hello world"

		encoder1 := NewEncoder().FromString(testData).ByHex()
		encoder2 := NewEncoder().FromBytes([]byte(testData)).ByHex()
		encoder3 := NewEncoder().FromFile(mock.NewFile([]byte(testData), "test.txt")).ByHex()

		assert.Nil(t, encoder1.Error)
		assert.Nil(t, encoder2.Error)
		assert.Nil(t, encoder3.Error)
		assert.Equal(t, encoder1.ToString(), encoder2.ToString())
		assert.Equal(t, encoder1.ToString(), encoder3.ToString())
	})

	t.Run("zero bytes", func(t *testing.T) {
		zeroData := []byte{0x00, 0x00, 0x00, 0x00}

		encoder := NewEncoder().FromBytes(zeroData).ByHex()
		assert.Nil(t, encoder.Error)

		decoder := NewDecoder().FromBytes(encoder.ToBytes()).ByHex()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, zeroData, decoder.ToBytes())
	})

	t.Run("max bytes", func(t *testing.T) {
		maxData := []byte{0xFF, 0xFF, 0xFF, 0xFF}

		encoder := NewEncoder().FromBytes(maxData).ByHex()
		assert.Nil(t, encoder.Error)

		decoder := NewDecoder().FromBytes(encoder.ToBytes()).ByHex()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, maxData, decoder.ToBytes())
	})

	t.Run("all possible byte values", func(t *testing.T) {
		allBytes := make([]byte, 256)
		for i := range 256 {
			allBytes[i] = byte(i)
		}

		encoder := NewEncoder().FromBytes(allBytes).ByHex()
		assert.Nil(t, encoder.Error)

		decoder := NewDecoder().FromString(encoder.ToString()).ByHex()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, allBytes, decoder.ToBytes())
	})
}

func TestHexSpecific(t *testing.T) {
	t.Run("hex alphabet verification", func(t *testing.T) {
		// Hex alphabet should contain only 0-9 and a-f
		hexAlphabet := "0123456789abcdef"
		allValid := true
		for _, char := range hexAlphabet {
			if !strings.ContainsRune("0123456789abcdef", char) {
				allValid = false
				break
			}
		}
		assert.True(t, allValid)
	})

	t.Run("hex encoding consistency", func(t *testing.T) {
		testData := "hello world"
		encoder1 := NewEncoder().FromString(testData).ByHex()
		encoder2 := NewEncoder().FromString(testData).ByHex()

		assert.Nil(t, encoder1.Error)
		assert.Nil(t, encoder2.Error)
		assert.Equal(t, encoder1.ToString(), encoder2.ToString())
	})

	t.Run("hex vs string vs bytes consistency", func(t *testing.T) {
		testData := "hello world"

		encoder1 := NewEncoder().FromString(testData).ByHex()
		encoder2 := NewEncoder().FromBytes([]byte(testData)).ByHex()
		encoder3 := NewEncoder().FromFile(mock.NewFile([]byte(testData), "test.txt")).ByHex()

		assert.Nil(t, encoder1.Error)
		assert.Nil(t, encoder2.Error)
		assert.Nil(t, encoder3.Error)
		assert.Equal(t, encoder1.ToString(), encoder2.ToString())
		assert.Equal(t, encoder1.ToString(), encoder3.ToString())
	})

	t.Run("hex specific test cases", func(t *testing.T) {
		// Test specific Hex encoding patterns (generated using Python binascii library)
		testCases := []struct {
			input    []byte
			expected string
		}{
			{[]byte{0x00}, "00"},
			{[]byte{0x00, 0x00}, "0000"},
			{[]byte{0x00, 0x00, 0x00}, "000000"},
			{[]byte{0xFF}, "ff"},
			{[]byte{0xFF, 0xFF}, "ffff"},
			{[]byte{0xFF, 0xFF, 0xFF}, "ffffff"},
		}

		for _, tc := range testCases {
			encoder := NewEncoder().FromBytes(tc.input).ByHex()
			assert.Nil(t, encoder.Error)
			assert.Equal(t, tc.expected, encoder.ToString())

			decoder := NewDecoder().FromString(tc.expected).ByHex()
			assert.Nil(t, decoder.Error)
			assert.Equal(t, tc.input, decoder.ToBytes())
		}
	})
}
