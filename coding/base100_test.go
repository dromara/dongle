package coding

import (
	"errors"
	"strings"
	"testing"

	"github.com/dromara/dongle/mock"
	"github.com/stretchr/testify/assert"
)

// Test data for base100 encoding (generated using dongle implementation)
var (
	base100Src     = []byte("hello world")
	base100Encoded = []byte{0xf0, 0x9f, 0x91, 0x9f, 0xf0, 0x9f, 0x91, 0x9c, 0xf0, 0x9f, 0x91, 0xa3, 0xf0, 0x9f, 0x91, 0xa3, 0xf0, 0x9f, 0x91, 0xa6, 0xf0, 0x9f, 0x90, 0x97, 0xf0, 0x9f, 0x91, 0xae, 0xf0, 0x9f, 0x91, 0xa6, 0xf0, 0x9f, 0x91, 0xa9, 0xf0, 0x9f, 0x91, 0xa3, 0xf0, 0x9f, 0x91, 0x9b}
)

// Test data for base100 unicode encoding (generated using dongle implementation)
var (
	base100UnicodeSrc     = []byte("你好世界")
	base100UnicodeEncoded = []byte{0xf0, 0x9f, 0x93, 0x9b, 0xf0, 0x9f, 0x92, 0xb4, 0xf0, 0x9f, 0x92, 0x97, 0xf0, 0x9f, 0x93, 0x9c, 0xf0, 0x9f, 0x92, 0x9c, 0xf0, 0x9f, 0x92, 0xb4, 0xf0, 0x9f, 0x93, 0x9b, 0xf0, 0x9f, 0x92, 0xaf, 0xf0, 0x9f, 0x92, 0x8d, 0xf0, 0x9f, 0x93, 0x9e, 0xf0, 0x9f, 0x92, 0x8c, 0xf0, 0x9f, 0x92, 0x83}
)

// Test data for base100 binary encoding (generated using dongle implementation)
var (
	base100BinarySrc     = []byte{0x00, 0x01, 0x02, 0x03, 0xFF, 0xFE, 0xFD, 0xFC}
	base100BinaryEncoded = []byte{0xf0, 0x9f, 0x8f, 0xb7, 0xf0, 0x9f, 0x8f, 0xb8, 0xf0, 0x9f, 0x8f, 0xb9, 0xf0, 0x9f, 0x8f, 0xba, 0xf0, 0x9f, 0x93, 0xb6, 0xf0, 0x9f, 0x93, 0xb5, 0xf0, 0x9f, 0x93, 0xb4, 0xf0, 0x9f, 0x93, 0xb3}
)

// Test data for base100 specific bytes (generated using dongle implementation)
var (
	base100SpecificBytesSrc     = []byte{0x00, 0x01, 0x02, 0x03}
	base100SpecificBytesEncoded = []byte{0xf0, 0x9f, 0x8f, 0xb7, 0xf0, 0x9f, 0x8f, 0xb8, 0xf0, 0x9f, 0x8f, 0xb9, 0xf0, 0x9f, 0x8f, 0xba}
)

// Test data for base100 single byte (generated using dongle implementation)
var (
	base100SingleByteSrc     = []byte{0x41}
	base100SingleByteEncoded = []byte{0xf0, 0x9f, 0x90, 0xb8}
)

// Test data for base100 two bytes (generated using dongle implementation)
var (
	base100TwoBytesSrc     = []byte{0x41, 0x42}
	base100TwoBytesEncoded = []byte{0xf0, 0x9f, 0x90, 0xb8, 0xf0, 0x9f, 0x90, 0xb9}
)

// Test data for base100 three bytes (generated using dongle implementation)
var (
	base100ThreeBytesSrc     = []byte{0x41, 0x42, 0x43}
	base100ThreeBytesEncoded = []byte{0xf0, 0x9f, 0x90, 0xb8, 0xf0, 0x9f, 0x90, 0xb9, 0xf0, 0x9f, 0x90, 0xba}
)

// Test data for base100 zero bytes (generated using dongle implementation)
var (
	base100ZeroBytesSrc     = []byte{0x00, 0x00, 0x00, 0x00}
	base100ZeroBytesEncoded = []byte{0xf0, 0x9f, 0x8f, 0xb7, 0xf0, 0x9f, 0x8f, 0xb7, 0xf0, 0x9f, 0x8f, 0xb7, 0xf0, 0x9f, 0x8f, 0xb7}
)

// Test data for base100 max bytes (generated using dongle implementation)
var (
	base100MaxBytesSrc     = []byte{0xFF, 0xFF, 0xFF, 0xFF}
	base100MaxBytesEncoded = []byte{0xf0, 0x9f, 0x93, 0xb6, 0xf0, 0x9f, 0x93, 0xb6, 0xf0, 0x9f, 0x93, 0xb6, 0xf0, 0x9f, 0x93, 0xb6}
)

func TestEncoder_ByBase100_Encode(t *testing.T) {
	t.Run("encode string", func(t *testing.T) {
		encoder := NewEncoder().FromString(string(base100Src)).ByBase100()
		assert.Nil(t, encoder.Error)
		assert.Equal(t, base100Encoded, encoder.ToBytes())
	})

	t.Run("encode bytes", func(t *testing.T) {
		encoder := NewEncoder().FromBytes(base100Src).ByBase100()
		assert.Nil(t, encoder.Error)
		assert.Equal(t, base100Encoded, encoder.ToBytes())
	})

	t.Run("encode file", func(t *testing.T) {
		file := mock.NewFile(base100Src, "test.txt")
		encoder := NewEncoder().FromFile(file).ByBase100()
		assert.Nil(t, encoder.Error)
		assert.Equal(t, base100Encoded, encoder.ToBytes())
	})

	t.Run("encode empty string", func(t *testing.T) {
		encoder := NewEncoder().FromString("").ByBase100()
		assert.Nil(t, encoder.Error)
		assert.Empty(t, encoder.ToBytes())
	})

	t.Run("encode empty bytes", func(t *testing.T) {
		encoder := NewEncoder().FromBytes([]byte{}).ByBase100()
		assert.Nil(t, encoder.Error)
		assert.Empty(t, encoder.ToBytes())
	})

	t.Run("encode nil bytes", func(t *testing.T) {
		encoder := NewEncoder().FromBytes(nil).ByBase100()
		assert.Nil(t, encoder.Error)
		assert.Empty(t, encoder.ToBytes())
	})

	t.Run("encode empty file", func(t *testing.T) {
		file := mock.NewFile([]byte{}, "empty.txt")
		encoder := NewEncoder().FromFile(file).ByBase100()
		assert.Nil(t, encoder.Error)
		assert.Empty(t, encoder.ToBytes())
	})

	t.Run("unicode string", func(t *testing.T) {
		encoder := NewEncoder().FromString(string(base100UnicodeSrc)).ByBase100()
		assert.Nil(t, encoder.Error)
		assert.Equal(t, base100UnicodeEncoded, encoder.ToBytes())
	})

	t.Run("binary data", func(t *testing.T) {
		encoder := NewEncoder().FromBytes(base100BinarySrc).ByBase100()
		assert.Nil(t, encoder.Error)
		assert.Equal(t, base100BinaryEncoded, encoder.ToBytes())
	})

	t.Run("large data", func(t *testing.T) {
		largeData := strings.Repeat("Hello, World! ", 100)
		encoder := NewEncoder().FromString(largeData).ByBase100()
		assert.Nil(t, encoder.Error)
		assert.NotEmpty(t, encoder.ToBytes())
	})

	t.Run("single byte", func(t *testing.T) {
		encoder := NewEncoder().FromBytes(base100SingleByteSrc).ByBase100()
		assert.Nil(t, encoder.Error)
		assert.Equal(t, base100SingleByteEncoded, encoder.ToBytes())
	})

	t.Run("two bytes", func(t *testing.T) {
		encoder := NewEncoder().FromBytes(base100TwoBytesSrc).ByBase100()
		assert.Nil(t, encoder.Error)
		assert.Equal(t, base100TwoBytesEncoded, encoder.ToBytes())
	})

	t.Run("three bytes", func(t *testing.T) {
		encoder := NewEncoder().FromBytes(base100ThreeBytesSrc).ByBase100()
		assert.Nil(t, encoder.Error)
		assert.Equal(t, base100ThreeBytesEncoded, encoder.ToBytes())
	})

	t.Run("zero bytes", func(t *testing.T) {
		encoder := NewEncoder().FromBytes(base100ZeroBytesSrc).ByBase100()
		assert.Nil(t, encoder.Error)
		assert.Equal(t, base100ZeroBytesEncoded, encoder.ToBytes())
	})

	t.Run("max bytes", func(t *testing.T) {
		encoder := NewEncoder().FromBytes(base100MaxBytesSrc).ByBase100()
		assert.Nil(t, encoder.Error)
		assert.Equal(t, base100MaxBytesEncoded, encoder.ToBytes())
	})

	t.Run("specific bytes", func(t *testing.T) {
		encoder := NewEncoder().FromBytes(base100SpecificBytesSrc).ByBase100()
		assert.Nil(t, encoder.Error)
		assert.Equal(t, base100SpecificBytesEncoded, encoder.ToBytes())
	})

	t.Run("error file", func(t *testing.T) {
		errorFile := mock.NewErrorFile(errors.New("read error"))
		encoder := NewEncoder().FromFile(errorFile).ByBase100()
		assert.Error(t, encoder.Error)
		assert.Contains(t, encoder.Error.Error(), "read error")
	})

	t.Run("encode no data", func(t *testing.T) {
		encoder := NewEncoder().ByBase100()
		assert.Nil(t, encoder.Error)
		assert.Empty(t, encoder.ToBytes())
	})
}

func TestEncoder_ByBase100_Error(t *testing.T) {
	t.Run("existing error", func(t *testing.T) {
		encoder := NewEncoder()
		encoder.Error = errors.New("existing error")
		result := encoder.ByBase100()
		assert.Equal(t, encoder, result)
		assert.Equal(t, errors.New("existing error"), result.Error)
	})
}

func TestDecoder_ByBase100_Decode(t *testing.T) {
	t.Run("decode string", func(t *testing.T) {
		decoder := NewDecoder().FromBytes(base100Encoded).ByBase100()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, base100Src, decoder.ToBytes())
	})

	t.Run("decode bytes", func(t *testing.T) {
		decoder := NewDecoder().FromBytes(base100Encoded).ByBase100()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, base100Src, decoder.ToBytes())
	})

	t.Run("decode file", func(t *testing.T) {
		file := mock.NewFile(base100Encoded, "test.txt")
		decoder := NewDecoder().FromFile(file).ByBase100()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, base100Src, decoder.ToBytes())
	})

	t.Run("decode empty string", func(t *testing.T) {
		decoder := NewDecoder().FromString("").ByBase100()
		assert.Nil(t, decoder.Error)
		assert.Empty(t, decoder.ToBytes())
	})

	t.Run("decode empty bytes", func(t *testing.T) {
		decoder := NewDecoder().FromBytes([]byte{}).ByBase100()
		assert.Nil(t, decoder.Error)
		assert.Empty(t, decoder.ToBytes())
	})

	t.Run("decode nil bytes", func(t *testing.T) {
		decoder := NewDecoder().FromBytes(nil).ByBase100()
		assert.Nil(t, decoder.Error)
		assert.Empty(t, decoder.ToBytes())
	})

	t.Run("decode empty file", func(t *testing.T) {
		file := mock.NewFile([]byte{}, "empty.txt")
		decoder := NewDecoder().FromFile(file).ByBase100()
		assert.Nil(t, decoder.Error)
		assert.Empty(t, decoder.ToBytes())
	})

	t.Run("unicode string", func(t *testing.T) {
		decoder := NewDecoder().FromBytes(base100UnicodeEncoded).ByBase100()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, base100UnicodeSrc, decoder.ToBytes())
	})

	t.Run("binary data", func(t *testing.T) {
		decoder := NewDecoder().FromBytes(base100BinaryEncoded).ByBase100()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, base100BinarySrc, decoder.ToBytes())
	})

	t.Run("single byte", func(t *testing.T) {
		decoder := NewDecoder().FromBytes(base100SingleByteEncoded).ByBase100()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, base100SingleByteSrc, decoder.ToBytes())
	})

	t.Run("two bytes", func(t *testing.T) {
		decoder := NewDecoder().FromBytes(base100TwoBytesEncoded).ByBase100()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, base100TwoBytesSrc, decoder.ToBytes())
	})

	t.Run("three bytes", func(t *testing.T) {
		decoder := NewDecoder().FromBytes(base100ThreeBytesEncoded).ByBase100()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, base100ThreeBytesSrc, decoder.ToBytes())
	})

	t.Run("zero bytes", func(t *testing.T) {
		decoder := NewDecoder().FromBytes(base100ZeroBytesEncoded).ByBase100()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, base100ZeroBytesSrc, decoder.ToBytes())
	})

	t.Run("max bytes", func(t *testing.T) {
		decoder := NewDecoder().FromBytes(base100MaxBytesEncoded).ByBase100()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, base100MaxBytesSrc, decoder.ToBytes())
	})

	t.Run("specific bytes", func(t *testing.T) {
		decoder := NewDecoder().FromBytes(base100SpecificBytesEncoded).ByBase100()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, base100SpecificBytesSrc, decoder.ToBytes())
	})

	t.Run("error file", func(t *testing.T) {
		errorFile := mock.NewErrorFile(errors.New("read error"))
		decoder := NewDecoder().FromFile(errorFile).ByBase100()
		assert.Error(t, decoder.Error)
		assert.Contains(t, decoder.Error.Error(), "read error")
	})

	t.Run("invalid base100", func(t *testing.T) {
		// Create invalid base100 data (not divisible by 4)
		invalidData := []byte{0xf0, 0x9f, 0x90, 0xb8, 0xf0} // 5 bytes, not divisible by 4
		decoder := NewDecoder().FromBytes(invalidData).ByBase100()
		assert.Error(t, decoder.Error)
	})

	t.Run("decode no data", func(t *testing.T) {
		decoder := NewDecoder().ByBase100()
		assert.Nil(t, decoder.Error)
		assert.Empty(t, decoder.ToBytes())
	})
}

func TestDecoder_ByBase100_Error(t *testing.T) {
	t.Run("existing error", func(t *testing.T) {
		decoder := NewDecoder()
		decoder.Error = errors.New("existing error")
		result := decoder.ByBase100()
		assert.Equal(t, decoder, result)
		assert.Equal(t, errors.New("existing error"), result.Error)
	})
}

func TestBase100RoundTrip(t *testing.T) {
	t.Run("base100 round trip", func(t *testing.T) {
		testData := "Hello, World! 你好世界"

		encoder := NewEncoder().FromString(testData).ByBase100()
		assert.Nil(t, encoder.Error)

		decoder := NewDecoder().FromBytes(encoder.ToBytes()).ByBase100()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, []byte(testData), decoder.ToBytes())
	})

	t.Run("base100 round trip with file", func(t *testing.T) {
		testData := "Hello, World! 你好世界"

		file := mock.NewFile([]byte(testData), "test.txt")
		encoder := NewEncoder().FromFile(file).ByBase100()
		assert.Nil(t, encoder.Error)

		decoderFile := mock.NewFile(encoder.ToBytes(), "decoded.txt")
		decoder := NewDecoder().FromFile(decoderFile).ByBase100()
		assert.Nil(t, decoder.Error)
		assert.NotEmpty(t, decoder.ToBytes())
	})

	t.Run("base100 round trip with bytes", func(t *testing.T) {
		testData := []byte{0x00, 0x01, 0x02, 0x03, 0xFF, 0xFE, 0xFD, 0xFC}

		encoder := NewEncoder().FromBytes(testData).ByBase100()
		assert.Nil(t, encoder.Error)

		decoder := NewDecoder().FromBytes(encoder.ToBytes()).ByBase100()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, testData, decoder.ToBytes())
	})
}

func TestBase100EdgeCases(t *testing.T) {
	t.Run("very large data", func(t *testing.T) {
		largeData := strings.Repeat("Hello, World! ", 1000)

		encoder := NewEncoder().FromString(largeData).ByBase100()
		assert.Nil(t, encoder.Error)

		decoder := NewDecoder().FromBytes(encoder.ToBytes()).ByBase100()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, []byte(largeData), decoder.ToBytes())
	})

	t.Run("single character", func(t *testing.T) {
		encoder := NewEncoder().FromString("A").ByBase100()
		assert.Nil(t, encoder.Error)
		assert.NotEmpty(t, encoder.ToBytes())

		decoder := NewDecoder().FromBytes(encoder.ToBytes()).ByBase100()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, []byte("A"), decoder.ToBytes())
	})

	t.Run("binary data", func(t *testing.T) {
		binaryData := []byte{0x00, 0x01, 0x02, 0x03, 0xFF, 0xFE, 0xFD, 0xFC}

		encoder := NewEncoder().FromBytes(binaryData).ByBase100()
		assert.Nil(t, encoder.Error)

		decoder := NewDecoder().FromBytes(encoder.ToBytes()).ByBase100()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, binaryData, decoder.ToBytes())
	})

	t.Run("mixed encoding methods", func(t *testing.T) {
		testData := "hello world"

		encoder1 := NewEncoder().FromString(testData).ByBase100()
		encoder2 := NewEncoder().FromBytes([]byte(testData)).ByBase100()
		encoder3 := NewEncoder().FromFile(mock.NewFile([]byte(testData), "test.txt")).ByBase100()

		assert.Nil(t, encoder1.Error)
		assert.Nil(t, encoder2.Error)
		assert.Nil(t, encoder3.Error)
		assert.Equal(t, encoder1.ToBytes(), encoder2.ToBytes())
		assert.Equal(t, encoder1.ToBytes(), encoder3.ToBytes())
	})

	t.Run("zero bytes", func(t *testing.T) {
		zeroData := []byte{0x00, 0x00, 0x00, 0x00}

		encoder := NewEncoder().FromBytes(zeroData).ByBase100()
		assert.Nil(t, encoder.Error)

		decoder := NewDecoder().FromBytes(encoder.ToBytes()).ByBase100()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, zeroData, decoder.ToBytes())
	})

	t.Run("max bytes", func(t *testing.T) {
		maxData := []byte{0xFF, 0xFF, 0xFF, 0xFF}

		encoder := NewEncoder().FromBytes(maxData).ByBase100()
		assert.Nil(t, encoder.Error)

		decoder := NewDecoder().FromBytes(encoder.ToBytes()).ByBase100()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, maxData, decoder.ToBytes())
	})

	t.Run("all possible byte values", func(t *testing.T) {
		allBytes := make([]byte, 256)
		for i := range 256 {
			allBytes[i] = byte(i)
		}

		encoder := NewEncoder().FromBytes(allBytes).ByBase100()
		assert.Nil(t, encoder.Error)

		decoder := NewDecoder().FromBytes(encoder.ToBytes()).ByBase100()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, allBytes, decoder.ToBytes())
	})
}

func TestBase100Specific(t *testing.T) {
	t.Run("base100 emoji verification", func(t *testing.T) {
		// Test that base100 encoding produces emoji sequences
		testData := []byte{0x41, 0x42, 0x43} // 'ABC'
		encoder := NewEncoder().FromBytes(testData).ByBase100()
		assert.Nil(t, encoder.Error)

		// Base100 should produce 4-byte sequences starting with 0xf0, 0x9f
		result := encoder.ToBytes()
		assert.Equal(t, 12, len(result)) // 3 bytes * 4 bytes per byte

		// Check that each 4-byte sequence starts with 0xf0, 0x9f
		for i := 0; i < len(result); i += 4 {
			assert.Equal(t, byte(0xf0), result[i])
			assert.Equal(t, byte(0x9f), result[i+1])
		}
	})

	t.Run("base100 encoding expansion", func(t *testing.T) {
		// Test that base100 encoding expands data by 4x
		testData := []byte{0x41, 0x42, 0x43} // 3 bytes
		encoder := NewEncoder().FromBytes(testData).ByBase100()
		assert.Nil(t, encoder.Error)

		// Base100 should expand data by 4x
		assert.Equal(t, len(testData)*4, len(encoder.ToBytes()))
	})

	t.Run("base100 encoding consistency", func(t *testing.T) {
		testData := []byte("Hello, World!")
		encoder := NewEncoder().FromBytes(testData).ByBase100()
		assert.Nil(t, encoder.Error)

		decoder := NewDecoder().FromBytes(encoder.ToBytes()).ByBase100()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, testData, decoder.ToBytes())
	})

	t.Run("base100 vs string vs bytes consistency", func(t *testing.T) {
		testData := "hello world"

		encoder1 := NewEncoder().FromString(testData).ByBase100()
		encoder2 := NewEncoder().FromBytes([]byte(testData)).ByBase100()
		encoder3 := NewEncoder().FromFile(mock.NewFile([]byte(testData), "test.txt")).ByBase100()

		assert.Nil(t, encoder1.Error)
		assert.Nil(t, encoder2.Error)
		assert.Nil(t, encoder3.Error)
		assert.Equal(t, encoder1.ToBytes(), encoder2.ToBytes())
		assert.Equal(t, encoder1.ToBytes(), encoder3.ToBytes())
	})

	t.Run("base100 byte value mapping", func(t *testing.T) {
		// Test specific byte value mapping
		testByte := byte(65) // 'A'
		encoder := NewEncoder().FromBytes([]byte{testByte}).ByBase100()
		assert.Nil(t, encoder.Error)

		// Expected: 0xf0, 0x9f, byte2, byte3 where:
		// byte2 = ((65 + 55) / 64) + 0x8f = (120 / 64) + 0x8f = 1 + 0x8f = 0x90
		// byte3 = (65 + 55) % 64 + 0x80 = 120 % 64 + 0x80 = 56 + 0x80 = 0xb8
		expected := []byte{0xf0, 0x9f, 0x90, 0xb8}
		assert.Equal(t, expected, encoder.ToBytes())
	})

	t.Run("base100 invalid data handling", func(t *testing.T) {
		// Test invalid data handling
		invalidData := []byte{0xf0, 0x9f, 0x90, 0xb8, 0xf0} // 5 bytes, not divisible by 4
		decoder := NewDecoder().FromBytes(invalidData).ByBase100()
		assert.Error(t, decoder.Error)

		// Test corrupt data with wrong first two bytes
		corruptData := []byte{0xf1, 0x9f, 0x90, 0xb8} // Wrong first byte
		decoder = NewDecoder().FromBytes(corruptData).ByBase100()
		assert.Error(t, decoder.Error)

		// Test invalid data with wrong second byte
		invalidData2 := []byte{0xf0, 0x9e, 0x90, 0xb8} // Wrong second byte
		decoder = NewDecoder().FromBytes(invalidData2).ByBase100()
		assert.Error(t, decoder.Error)
	})
}
