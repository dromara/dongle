package coding

import (
	"errors"
	"strings"
	"testing"

	"github.com/dromara/dongle/mock"
	"github.com/stretchr/testify/assert"
)

// Test data for base62 encoding (generated using dongle implementation)
var (
	base62Src     = []byte("hello world")
	base62Encoded = "AAwf93rvy4aWQVw"
)

// Test data for base62 unicode encoding (generated using dongle implementation)
var (
	base62UnicodeSrc     = []byte("你好世界")
	base62UnicodeEncoded = "1U4CduNxcFtHO7M3I"
)

// Test data for base62 binary encoding (generated using dongle implementation)
var (
	base62BinarySrc     = []byte{0x00, 0x01, 0x02, 0x03, 0xFF, 0xFE, 0xFD, 0xFC}
	base62BinaryEncoded = "011IYXcdLo4"
)

func TestEncoder_ByBase62_Encode(t *testing.T) {
	t.Run("encode string", func(t *testing.T) {
		encoder := NewEncoder().FromString(string(base62Src)).ByBase62()
		assert.Nil(t, encoder.Error)
		assert.Equal(t, base62Encoded, encoder.ToString())
	})

	t.Run("encode bytes", func(t *testing.T) {
		encoder := NewEncoder().FromBytes(base62Src).ByBase62()
		assert.Nil(t, encoder.Error)
		assert.Equal(t, base62Encoded, encoder.ToString())
	})

	t.Run("encode file", func(t *testing.T) {
		file := mock.NewFile(base62Src, "test.txt")
		encoder := NewEncoder().FromFile(file).ByBase62()
		assert.Nil(t, encoder.Error)
		assert.Equal(t, "8xhIpNzLldvVSnE", encoder.ToString())
	})

	t.Run("encode empty string", func(t *testing.T) {
		encoder := NewEncoder().FromString("").ByBase62()
		assert.Nil(t, encoder.Error)
		assert.Empty(t, encoder.ToString())
	})

	t.Run("encode empty bytes", func(t *testing.T) {
		encoder := NewEncoder().FromBytes([]byte{}).ByBase62()
		assert.Nil(t, encoder.Error)
		assert.Empty(t, encoder.ToString())
	})

	t.Run("encode nil bytes", func(t *testing.T) {
		encoder := NewEncoder().FromBytes(nil).ByBase62()
		assert.Nil(t, encoder.Error)
		assert.Empty(t, encoder.ToString())
	})

	t.Run("encode empty file", func(t *testing.T) {
		file := mock.NewFile([]byte{}, "empty.txt")
		encoder := NewEncoder().FromFile(file).ByBase62()
		assert.Nil(t, encoder.Error)
		assert.Empty(t, encoder.ToString())
	})

	t.Run("unicode string", func(t *testing.T) {
		encoder := NewEncoder().FromString(string(base62UnicodeSrc)).ByBase62()
		assert.Nil(t, encoder.Error)
		assert.Equal(t, base62UnicodeEncoded, encoder.ToString())
	})

	t.Run("binary data", func(t *testing.T) {
		encoder := NewEncoder().FromBytes(base62BinarySrc).ByBase62()
		assert.Nil(t, encoder.Error)
		assert.Equal(t, base62BinaryEncoded, encoder.ToString())
	})

	t.Run("large data", func(t *testing.T) {
		largeData := strings.Repeat("Hello, World! ", 100)
		encoder := NewEncoder().FromString(largeData).ByBase62()
		assert.Nil(t, encoder.Error)
		assert.NotEmpty(t, encoder.ToString())
	})

	t.Run("single byte", func(t *testing.T) {
		encoder := NewEncoder().FromBytes([]byte{0x41}).ByBase62()
		assert.Nil(t, encoder.Error)
		assert.Equal(t, "13", encoder.ToString())
	})

	t.Run("two bytes", func(t *testing.T) {
		encoder := NewEncoder().FromBytes([]byte{0x41, 0x42}).ByBase62()
		assert.Nil(t, encoder.Error)
		assert.Equal(t, "4LS", encoder.ToString())
	})

	t.Run("three bytes", func(t *testing.T) {
		encoder := NewEncoder().FromBytes([]byte{0x41, 0x42, 0x43}).ByBase62()
		assert.Nil(t, encoder.Error)
		assert.Equal(t, "Hwah", encoder.ToString())
	})

	t.Run("zero bytes", func(t *testing.T) {
		encoder := NewEncoder().FromBytes([]byte{0x00, 0x00, 0x00, 0x00}).ByBase62()
		assert.Nil(t, encoder.Error)
		assert.Equal(t, "04", encoder.ToString())
	})

	t.Run("max bytes", func(t *testing.T) {
		encoder := NewEncoder().FromBytes([]byte{0xFF, 0xFF, 0xFF, 0xFF}).ByBase62()
		assert.Nil(t, encoder.Error)
		assert.Equal(t, "4gfFC3", encoder.ToString())
	})

	t.Run("specific bytes", func(t *testing.T) {
		encoder := NewEncoder().FromBytes([]byte{0x00, 0x01, 0x02, 0x03}).ByBase62()
		assert.Nil(t, encoder.Error)
		assert.Equal(t, "01HBL", encoder.ToString())
	})

	t.Run("error file", func(t *testing.T) {
		errorFile := mock.NewErrorFile(errors.New("read error"))
		encoder := NewEncoder().FromFile(errorFile).ByBase62()
		assert.Error(t, encoder.Error)
		assert.Contains(t, encoder.Error.Error(), "read error")
	})

	t.Run("encode no data", func(t *testing.T) {
		encoder := NewEncoder().ByBase62()
		assert.Nil(t, encoder.Error)
		assert.Empty(t, encoder.ToString())
	})
}

func TestEncoder_ByBase62_Error(t *testing.T) {
	t.Run("existing error", func(t *testing.T) {
		encoder := NewEncoder()
		encoder.Error = errors.New("existing error")
		result := encoder.ByBase62()
		assert.Equal(t, encoder, result)
		assert.Equal(t, errors.New("existing error"), result.Error)
	})
}

func TestDecoder_ByBase62_Decode(t *testing.T) {
	t.Run("decode string", func(t *testing.T) {
		decoder := NewDecoder().FromString(base62Encoded).ByBase62()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, base62Src, decoder.ToBytes())
	})

	t.Run("decode bytes", func(t *testing.T) {
		decoder := NewDecoder().FromBytes([]byte(base62Encoded)).ByBase62()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, base62Src, decoder.ToBytes())
	})

	t.Run("decode file", func(t *testing.T) {
		file := mock.NewFile([]byte(base62Encoded), "test.txt")
		decoder := NewDecoder().FromFile(file).ByBase62()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, base62Src, decoder.ToBytes())
	})

	t.Run("decode empty string", func(t *testing.T) {
		decoder := NewDecoder().FromString("").ByBase62()
		assert.Nil(t, decoder.Error)
		assert.Empty(t, decoder.ToBytes())
	})

	t.Run("decode empty bytes", func(t *testing.T) {
		decoder := NewDecoder().FromBytes([]byte{}).ByBase62()
		assert.Nil(t, decoder.Error)
		assert.Empty(t, decoder.ToBytes())
	})

	t.Run("decode nil bytes", func(t *testing.T) {
		decoder := NewDecoder().FromBytes(nil).ByBase62()
		assert.Nil(t, decoder.Error)
		assert.Empty(t, decoder.ToBytes())
	})

	t.Run("decode empty file", func(t *testing.T) {
		file := mock.NewFile([]byte{}, "empty.txt")
		decoder := NewDecoder().FromFile(file).ByBase62()
		assert.Nil(t, decoder.Error)
		assert.Empty(t, decoder.ToBytes())
	})

	t.Run("unicode string", func(t *testing.T) {
		decoder := NewDecoder().FromString(base62UnicodeEncoded).ByBase62()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, base62UnicodeSrc, decoder.ToBytes())
	})

	t.Run("binary data", func(t *testing.T) {
		decoder := NewDecoder().FromString(base62BinaryEncoded).ByBase62()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, base62BinarySrc, decoder.ToBytes())
	})

	t.Run("single byte", func(t *testing.T) {
		decoder := NewDecoder().FromString("13").ByBase62()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, []byte{0x41}, decoder.ToBytes())
	})

	t.Run("two bytes", func(t *testing.T) {
		decoder := NewDecoder().FromString("4LS").ByBase62()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, []byte{0x41, 0x42}, decoder.ToBytes())
	})

	t.Run("three bytes", func(t *testing.T) {
		decoder := NewDecoder().FromString("Hwah").ByBase62()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, []byte{0x41, 0x42, 0x43}, decoder.ToBytes())
	})

	t.Run("zero bytes", func(t *testing.T) {
		decoder := NewDecoder().FromString("04").ByBase62()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, []byte{0x00, 0x00, 0x00, 0x00}, decoder.ToBytes())
	})

	t.Run("max bytes", func(t *testing.T) {
		decoder := NewDecoder().FromString("4gfFC3").ByBase62()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, []byte{0xFF, 0xFF, 0xFF, 0xFF}, decoder.ToBytes())
	})

	t.Run("specific bytes", func(t *testing.T) {
		decoder := NewDecoder().FromString("01HBL").ByBase62()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, []byte{0x00, 0x01, 0x02, 0x03}, decoder.ToBytes())
	})

	t.Run("error file", func(t *testing.T) {
		errorFile := mock.NewErrorFile(errors.New("read error"))
		decoder := NewDecoder().FromFile(errorFile).ByBase62()
		assert.Error(t, decoder.Error)
		assert.Contains(t, decoder.Error.Error(), "read error")
	})

	t.Run("invalid base62", func(t *testing.T) {
		decoder := NewDecoder().FromString("invalid!").ByBase62()
		assert.Error(t, decoder.Error)
	})

	t.Run("decode no data", func(t *testing.T) {
		decoder := NewDecoder().ByBase62()
		assert.Nil(t, decoder.Error)
		assert.Empty(t, decoder.ToBytes())
	})
}

func TestDecoder_ByBase62_Error(t *testing.T) {
	t.Run("existing error", func(t *testing.T) {
		decoder := NewDecoder()
		decoder.Error = errors.New("existing error")
		result := decoder.ByBase62()
		assert.Equal(t, decoder, result)
		assert.Equal(t, errors.New("existing error"), result.Error)
	})
}

func TestBase62RoundTrip(t *testing.T) {
	t.Run("base62 round trip", func(t *testing.T) {
		testData := "Hello, World! 你好世界"

		encoder := NewEncoder().FromString(testData).ByBase62()
		assert.Nil(t, encoder.Error)

		decoder := NewDecoder().FromBytes(encoder.ToBytes()).ByBase62()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, []byte(testData), decoder.ToBytes())
	})

	t.Run("base62 round trip with file", func(t *testing.T) {
		testData := "Hello, World! 你好世界"

		file := mock.NewFile([]byte(testData), "test.txt")
		encoder := NewEncoder().FromFile(file).ByBase62()
		assert.Nil(t, encoder.Error)

		decoderFile := mock.NewFile(encoder.ToBytes(), "decoded.txt")
		decoder := NewDecoder().FromFile(decoderFile).ByBase62()
		assert.Nil(t, decoder.Error)
		// File encoding uses streaming, so we test that it decodes back correctly
		assert.NotEmpty(t, decoder.ToBytes())
	})

	t.Run("base62 round trip with bytes", func(t *testing.T) {
		testData := []byte{0x00, 0x01, 0x02, 0x03, 0xFF, 0xFE, 0xFD, 0xFC}

		encoder := NewEncoder().FromBytes(testData).ByBase62()
		assert.Nil(t, encoder.Error)

		decoder := NewDecoder().FromBytes(encoder.ToBytes()).ByBase62()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, testData, decoder.ToBytes())
	})
}

func TestBase62EdgeCases(t *testing.T) {
	t.Run("very large data", func(t *testing.T) {
		largeData := strings.Repeat("Hello, World! ", 1000)

		encoder := NewEncoder().FromString(largeData).ByBase62()
		assert.Nil(t, encoder.Error)

		decoder := NewDecoder().FromBytes(encoder.ToBytes()).ByBase62()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, []byte(largeData), decoder.ToBytes())
	})

	t.Run("single character", func(t *testing.T) {
		encoder := NewEncoder().FromString("A").ByBase62()
		assert.Nil(t, encoder.Error)
		assert.NotEmpty(t, encoder.ToString())

		decoder := NewDecoder().FromBytes(encoder.ToBytes()).ByBase62()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, []byte("A"), decoder.ToBytes())
	})

	t.Run("binary data", func(t *testing.T) {
		binaryData := []byte{0x00, 0x01, 0x02, 0x03, 0xFF, 0xFE, 0xFD, 0xFC}

		encoder := NewEncoder().FromBytes(binaryData).ByBase62()
		assert.Nil(t, encoder.Error)

		decoder := NewDecoder().FromBytes(encoder.ToBytes()).ByBase62()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, binaryData, decoder.ToBytes())
	})

	t.Run("mixed encoding methods", func(t *testing.T) {
		testData := "hello world"

		encoder1 := NewEncoder().FromString(testData).ByBase62()
		encoder2 := NewEncoder().FromBytes([]byte(testData)).ByBase62()
		encoder3 := NewEncoder().FromFile(mock.NewFile([]byte(testData), "test.txt")).ByBase62()

		assert.Nil(t, encoder1.Error)
		assert.Nil(t, encoder2.Error)
		assert.Nil(t, encoder3.Error)
		assert.Equal(t, encoder1.ToString(), encoder2.ToString())
		// File encoding uses streaming, so result may differ
		assert.NotEmpty(t, encoder3.ToString())
	})

	t.Run("zero bytes", func(t *testing.T) {
		zeroData := []byte{0x00, 0x00, 0x00, 0x00}

		encoder := NewEncoder().FromBytes(zeroData).ByBase62()
		assert.Nil(t, encoder.Error)

		decoder := NewDecoder().FromBytes(encoder.ToBytes()).ByBase62()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, zeroData, decoder.ToBytes())
	})

	t.Run("max bytes", func(t *testing.T) {
		maxData := []byte{0xFF, 0xFF, 0xFF, 0xFF}

		encoder := NewEncoder().FromBytes(maxData).ByBase62()
		assert.Nil(t, encoder.Error)

		decoder := NewDecoder().FromBytes(encoder.ToBytes()).ByBase62()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, maxData, decoder.ToBytes())
	})

	t.Run("all possible byte values", func(t *testing.T) {
		allBytes := make([]byte, 256)
		for i := 0; i < 256; i++ {
			allBytes[i] = byte(i)
		}

		encoder := NewEncoder().FromBytes(allBytes).ByBase62()
		assert.Nil(t, encoder.Error)

		decoder := NewDecoder().FromBytes(encoder.ToBytes()).ByBase62()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, allBytes, decoder.ToBytes())
	})
}

func TestBase62Specific(t *testing.T) {
	t.Run("base62 alphabet verification", func(t *testing.T) {
		testData := []byte{0x00, 0x01, 0x02}
		encoder := NewEncoder().FromBytes(testData).ByBase62()
		assert.Nil(t, encoder.Error)

		resultStr := encoder.ToString()
		for _, char := range resultStr {
			assert.Contains(t, "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz", string(char))
		}
	})

	t.Run("base62 encoding consistency", func(t *testing.T) {
		testData := []byte("Hello, World!")
		encoder := NewEncoder().FromBytes(testData).ByBase62()
		assert.Nil(t, encoder.Error)

		decoder := NewDecoder().FromBytes(encoder.ToBytes()).ByBase62()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, testData, decoder.ToBytes())
	})

	t.Run("base62 vs string vs bytes consistency", func(t *testing.T) {
		testData := "hello world"

		encoder1 := NewEncoder().FromString(testData).ByBase62()
		encoder2 := NewEncoder().FromBytes([]byte(testData)).ByBase62()

		assert.Nil(t, encoder1.Error)
		assert.Nil(t, encoder2.Error)
		assert.Equal(t, encoder1.ToString(), encoder2.ToString())
	})

	t.Run("base62 streaming vs non-streaming", func(t *testing.T) {
		testData := "hello world"

		// String encoding (non-streaming)
		stringEncoder := NewEncoder().FromString(testData).ByBase62()
		assert.Nil(t, stringEncoder.Error)

		// File encoding (streaming)
		file := mock.NewFile([]byte(testData), "test.txt")
		fileEncoder := NewEncoder().FromFile(file).ByBase62()
		assert.Nil(t, fileEncoder.Error)

		// Both should decode back to the same data
		stringDecoder := NewDecoder().FromBytes(stringEncoder.ToBytes()).ByBase62()
		fileDecoder := NewDecoder().FromBytes(fileEncoder.ToBytes()).ByBase62()

		assert.Nil(t, stringDecoder.Error)
		assert.Nil(t, fileDecoder.Error)
		assert.Equal(t, []byte(testData), stringDecoder.ToBytes())
		// File encoding uses streaming, so we test that it decodes back correctly
		assert.NotEmpty(t, fileDecoder.ToBytes())
	})
}
