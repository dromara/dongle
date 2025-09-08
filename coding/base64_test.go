package coding

import (
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/dromara/dongle/mock"
)

func TestEncoder_ByBase64(t *testing.T) {
	t.Run("encode string", func(t *testing.T) {
		encoder := NewEncoder().FromString("hello world").ByBase64()
		assert.Nil(t, encoder.Error)
		assert.NotEmpty(t, encoder.dst)
	})

	t.Run("encode empty string", func(t *testing.T) {
		encoder := NewEncoder().FromString("").ByBase64()
		assert.Nil(t, encoder.Error)
		assert.Nil(t, encoder.dst)
	})

	t.Run("encode bytes", func(t *testing.T) {
		encoder := NewEncoder().FromBytes([]byte{0x00, 0x01, 0x02, 0x03}).ByBase64()
		assert.Nil(t, encoder.Error)
		assert.NotEmpty(t, encoder.dst)
	})

	t.Run("encode empty bytes", func(t *testing.T) {
		encoder := NewEncoder().FromBytes([]byte{}).ByBase64()
		assert.Nil(t, encoder.Error)
		assert.Nil(t, encoder.dst)
	})

	t.Run("encode nil bytes", func(t *testing.T) {
		encoder := NewEncoder().FromBytes(nil).ByBase64()
		assert.Nil(t, encoder.Error)
		assert.Nil(t, encoder.dst)
	})

	t.Run("encode with file", func(t *testing.T) {
		file := mock.NewFile([]byte("hello world"), "test.txt")
		encoder := NewEncoder().FromFile(file).ByBase64()
		assert.Nil(t, encoder.Error)
		assert.NotEmpty(t, encoder.dst)
	})

	t.Run("encode with empty file", func(t *testing.T) {
		file := mock.NewFile([]byte{}, "empty.txt")
		encoder := NewEncoder().FromFile(file).ByBase64()
		assert.Nil(t, encoder.Error)
		assert.Equal(t, []byte{}, encoder.dst)
	})

	t.Run("encode with error file", func(t *testing.T) {
		errorFile := mock.NewErrorFile(errors.New("read error"))
		encoder := NewEncoder().FromFile(errorFile).ByBase64()
		assert.Error(t, encoder.Error)
		assert.Contains(t, encoder.Error.Error(), "read error")
	})

	t.Run("encode with existing error", func(t *testing.T) {
		encoder := NewEncoder()
		encoder.Error = errors.New("existing error")
		result := encoder.FromString("hello world").ByBase64()
		assert.Equal(t, encoder, result)
		assert.Equal(t, errors.New("existing error"), result.Error)
	})

	t.Run("encode unicode string", func(t *testing.T) {
		encoder := NewEncoder().FromString("你好世界").ByBase64()
		assert.Nil(t, encoder.Error)
		assert.NotEmpty(t, encoder.dst)
	})

	t.Run("encode large data", func(t *testing.T) {
		largeData := strings.Repeat("Hello, World! ", 100)
		encoder := NewEncoder().FromString(largeData).ByBase64()
		assert.Nil(t, encoder.Error)
		assert.NotEmpty(t, encoder.dst)
	})

	t.Run("encode single byte", func(t *testing.T) {
		encoder := NewEncoder().FromBytes([]byte{0x41}).ByBase64()
		assert.Nil(t, encoder.Error)
		assert.NotEmpty(t, encoder.dst)
	})

	t.Run("encode two bytes", func(t *testing.T) {
		encoder := NewEncoder().FromBytes([]byte{0x41, 0x42}).ByBase64()
		assert.Nil(t, encoder.Error)
		assert.NotEmpty(t, encoder.dst)
	})

	t.Run("encode three bytes", func(t *testing.T) {
		encoder := NewEncoder().FromBytes([]byte{0x41, 0x42, 0x43}).ByBase64()
		assert.Nil(t, encoder.Error)
		assert.NotEmpty(t, encoder.dst)
	})

	t.Run("encode zero bytes", func(t *testing.T) {
		encoder := NewEncoder().FromBytes([]byte{0x00, 0x00, 0x00, 0x00}).ByBase64()
		assert.Nil(t, encoder.Error)
		assert.NotEmpty(t, encoder.dst)
	})

	t.Run("encode max bytes", func(t *testing.T) {
		encoder := NewEncoder().FromBytes([]byte{0xFF, 0xFF, 0xFF, 0xFF}).ByBase64()
		assert.Nil(t, encoder.Error)
		assert.NotEmpty(t, encoder.dst)
	})
}

func TestDecoder_ByBase64(t *testing.T) {
	t.Run("decode string", func(t *testing.T) {
		encoder := NewEncoder().FromString("hello world").ByBase64()
		assert.Nil(t, encoder.Error)

		decoder := NewDecoder().FromBytes(encoder.dst).ByBase64()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, []byte("hello world"), decoder.dst)
	})

	t.Run("decode empty string", func(t *testing.T) {
		decoder := NewDecoder().FromString("").ByBase64()
		assert.Nil(t, decoder.Error)
		assert.Nil(t, decoder.dst)
	})

	t.Run("decode bytes", func(t *testing.T) {
		encoder := NewEncoder().FromBytes([]byte{0x00, 0x01, 0x02, 0x03}).ByBase64()
		assert.Nil(t, encoder.Error)

		decoder := NewDecoder().FromBytes(encoder.dst).ByBase64()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, []byte{0x00, 0x01, 0x02, 0x03}, decoder.dst)
	})

	t.Run("decode empty bytes", func(t *testing.T) {
		decoder := NewDecoder().FromBytes([]byte{}).ByBase64()
		assert.Nil(t, decoder.Error)
		assert.Nil(t, decoder.dst)
	})

	t.Run("decode nil bytes", func(t *testing.T) {
		decoder := NewDecoder().FromBytes(nil).ByBase64()
		assert.Nil(t, decoder.Error)
		assert.Nil(t, decoder.dst)
	})

	t.Run("decode with file", func(t *testing.T) {
		encoder := NewEncoder().FromString("hello world").ByBase64()
		assert.Nil(t, encoder.Error)

		file := mock.NewFile(encoder.dst, "test.txt")
		decoder := NewDecoder().FromFile(file).ByBase64()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, []byte("hello world"), decoder.dst)
	})

	t.Run("decode with empty file", func(t *testing.T) {
		file := mock.NewFile([]byte{}, "empty.txt")
		decoder := NewDecoder().FromFile(file).ByBase64()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, []byte{}, decoder.dst)
	})

	t.Run("decode with error file", func(t *testing.T) {
		errorFile := mock.NewErrorFile(errors.New("read error"))
		decoder := NewDecoder().FromFile(errorFile).ByBase64()
		assert.Error(t, decoder.Error)
		assert.Contains(t, decoder.Error.Error(), "read error")
	})

	t.Run("decode with existing error", func(t *testing.T) {
		decoder := NewDecoder()
		decoder.Error = errors.New("existing error")
		result := decoder.FromString("test").ByBase64()
		assert.Equal(t, decoder, result)
		assert.Equal(t, errors.New("existing error"), result.Error)
	})

	t.Run("decode invalid base64", func(t *testing.T) {
		decoder := NewDecoder().FromString("invalid!").ByBase64()
		assert.Error(t, decoder.Error)
	})

	t.Run("decode unicode string", func(t *testing.T) {
		encoder := NewEncoder().FromString("你好世界").ByBase64()
		assert.Nil(t, encoder.Error)

		decoder := NewDecoder().FromBytes(encoder.dst).ByBase64()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, []byte("你好世界"), decoder.dst)
	})

	t.Run("decode single byte encoded", func(t *testing.T) {
		encoder := NewEncoder().FromBytes([]byte{0x41}).ByBase64()
		assert.Nil(t, encoder.Error)

		decoder := NewDecoder().FromBytes(encoder.dst).ByBase64()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, []byte{0x41}, decoder.dst)
	})

	t.Run("decode two bytes encoded", func(t *testing.T) {
		encoder := NewEncoder().FromBytes([]byte{0x41, 0x42}).ByBase64()
		assert.Nil(t, encoder.Error)

		decoder := NewDecoder().FromBytes(encoder.dst).ByBase64()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, []byte{0x41, 0x42}, decoder.dst)
	})

	t.Run("decode three bytes encoded", func(t *testing.T) {
		encoder := NewEncoder().FromBytes([]byte{0x41, 0x42, 0x43}).ByBase64()
		assert.Nil(t, encoder.Error)

		decoder := NewDecoder().FromBytes(encoder.dst).ByBase64()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, []byte{0x41, 0x42, 0x43}, decoder.dst)
	})

	t.Run("decode zero bytes encoded", func(t *testing.T) {
		encoder := NewEncoder().FromBytes([]byte{0x00, 0x00, 0x00, 0x00}).ByBase64()
		assert.Nil(t, encoder.Error)

		decoder := NewDecoder().FromBytes(encoder.dst).ByBase64()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, []byte{0x00, 0x00, 0x00, 0x00}, decoder.dst)
	})

	t.Run("decode max bytes encoded", func(t *testing.T) {
		encoder := NewEncoder().FromBytes([]byte{0xFF, 0xFF, 0xFF, 0xFF}).ByBase64()
		assert.Nil(t, encoder.Error)

		decoder := NewDecoder().FromBytes(encoder.dst).ByBase64()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, []byte{0xFF, 0xFF, 0xFF, 0xFF}, decoder.dst)
	})
}

func TestEncoder_ByBase64Url(t *testing.T) {
	t.Run("encode string", func(t *testing.T) {
		encoder := NewEncoder().FromString("hello world").ByBase64Url()
		assert.Nil(t, encoder.Error)
		assert.NotEmpty(t, encoder.dst)
	})

	t.Run("encode empty string", func(t *testing.T) {
		encoder := NewEncoder().FromString("").ByBase64Url()
		assert.Nil(t, encoder.Error)
		assert.Nil(t, encoder.dst)
	})

	t.Run("encode bytes", func(t *testing.T) {
		encoder := NewEncoder().FromBytes([]byte{0x00, 0x01, 0x02, 0x03}).ByBase64Url()
		assert.Nil(t, encoder.Error)
		assert.NotEmpty(t, encoder.dst)
	})

	t.Run("encode empty bytes", func(t *testing.T) {
		encoder := NewEncoder().FromBytes([]byte{}).ByBase64Url()
		assert.Nil(t, encoder.Error)
		assert.Nil(t, encoder.dst)
	})

	t.Run("encode nil bytes", func(t *testing.T) {
		encoder := NewEncoder().FromBytes(nil).ByBase64Url()
		assert.Nil(t, encoder.Error)
		assert.Nil(t, encoder.dst)
	})

	t.Run("encode with file", func(t *testing.T) {
		file := mock.NewFile([]byte("hello world"), "test.txt")
		encoder := NewEncoder().FromFile(file).ByBase64Url()
		assert.Nil(t, encoder.Error)
		assert.NotEmpty(t, encoder.dst)
	})

	t.Run("encode with empty file", func(t *testing.T) {
		file := mock.NewFile([]byte{}, "empty.txt")
		encoder := NewEncoder().FromFile(file).ByBase64Url()
		assert.Nil(t, encoder.Error)
		assert.Equal(t, []byte{}, encoder.dst)
	})

	t.Run("encode with error file", func(t *testing.T) {
		errorFile := mock.NewErrorFile(errors.New("read error"))
		encoder := NewEncoder().FromFile(errorFile).ByBase64Url()
		assert.Error(t, encoder.Error)
		assert.Contains(t, encoder.Error.Error(), "read error")
	})

	t.Run("encode with existing error", func(t *testing.T) {
		encoder := NewEncoder()
		encoder.Error = errors.New("existing error")
		result := encoder.FromString("hello world").ByBase64Url()
		assert.Equal(t, encoder, result)
		assert.Equal(t, errors.New("existing error"), result.Error)
	})

	t.Run("encode unicode string", func(t *testing.T) {
		encoder := NewEncoder().FromString("你好世界").ByBase64Url()
		assert.Nil(t, encoder.Error)
		assert.NotEmpty(t, encoder.dst)
	})

	t.Run("encode large data", func(t *testing.T) {
		largeData := strings.Repeat("Hello, World! ", 100)
		encoder := NewEncoder().FromString(largeData).ByBase64Url()
		assert.Nil(t, encoder.Error)
		assert.NotEmpty(t, encoder.dst)
	})

	t.Run("encode single byte", func(t *testing.T) {
		encoder := NewEncoder().FromBytes([]byte{0x41}).ByBase64Url()
		assert.Nil(t, encoder.Error)
		assert.NotEmpty(t, encoder.dst)
	})

	t.Run("encode two bytes", func(t *testing.T) {
		encoder := NewEncoder().FromBytes([]byte{0x41, 0x42}).ByBase64Url()
		assert.Nil(t, encoder.Error)
		assert.NotEmpty(t, encoder.dst)
	})

	t.Run("encode three bytes", func(t *testing.T) {
		encoder := NewEncoder().FromBytes([]byte{0x41, 0x42, 0x43}).ByBase64Url()
		assert.Nil(t, encoder.Error)
		assert.NotEmpty(t, encoder.dst)
	})

	t.Run("encode zero bytes", func(t *testing.T) {
		encoder := NewEncoder().FromBytes([]byte{0x00, 0x00, 0x00, 0x00}).ByBase64Url()
		assert.Nil(t, encoder.Error)
		assert.NotEmpty(t, encoder.dst)
	})

	t.Run("encode max bytes", func(t *testing.T) {
		encoder := NewEncoder().FromBytes([]byte{0xFF, 0xFF, 0xFF, 0xFF}).ByBase64Url()
		assert.Nil(t, encoder.Error)
		assert.NotEmpty(t, encoder.dst)
	})
}

func TestDecoder_ByBase64Url(t *testing.T) {
	t.Run("decode string", func(t *testing.T) {
		encoder := NewEncoder().FromString("hello world").ByBase64Url()
		assert.Nil(t, encoder.Error)

		decoder := NewDecoder().FromBytes(encoder.dst).ByBase64Url()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, []byte("hello world"), decoder.dst)
	})

	t.Run("decode empty string", func(t *testing.T) {
		decoder := NewDecoder().FromString("").ByBase64Url()
		assert.Nil(t, decoder.Error)
		assert.Nil(t, decoder.dst)
	})

	t.Run("decode bytes", func(t *testing.T) {
		encoder := NewEncoder().FromBytes([]byte{0x00, 0x01, 0x02, 0x03}).ByBase64Url()
		assert.Nil(t, encoder.Error)

		decoder := NewDecoder().FromBytes(encoder.dst).ByBase64Url()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, []byte{0x00, 0x01, 0x02, 0x03}, decoder.dst)
	})

	t.Run("decode empty bytes", func(t *testing.T) {
		decoder := NewDecoder().FromBytes([]byte{}).ByBase64Url()
		assert.Nil(t, decoder.Error)
		assert.Nil(t, decoder.dst)
	})

	t.Run("decode nil bytes", func(t *testing.T) {
		decoder := NewDecoder().FromBytes(nil).ByBase64Url()
		assert.Nil(t, decoder.Error)
		assert.Nil(t, decoder.dst)
	})

	t.Run("decode with file", func(t *testing.T) {
		encoder := NewEncoder().FromString("hello world").ByBase64Url()
		assert.Nil(t, encoder.Error)

		file := mock.NewFile(encoder.dst, "test.txt")
		decoder := NewDecoder().FromFile(file).ByBase64Url()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, []byte("hello world"), decoder.dst)
	})

	t.Run("decode with empty file", func(t *testing.T) {
		file := mock.NewFile([]byte{}, "empty.txt")
		decoder := NewDecoder().FromFile(file).ByBase64Url()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, []byte{}, decoder.dst)
	})

	t.Run("decode with error file", func(t *testing.T) {
		errorFile := mock.NewErrorFile(errors.New("read error"))
		decoder := NewDecoder().FromFile(errorFile).ByBase64Url()
		assert.Error(t, decoder.Error)
		assert.Contains(t, decoder.Error.Error(), "read error")
	})

	t.Run("decode with existing error", func(t *testing.T) {
		decoder := NewDecoder()
		decoder.Error = errors.New("existing error")
		result := decoder.FromString("test").ByBase64Url()
		assert.Equal(t, decoder, result)
		assert.Equal(t, errors.New("existing error"), result.Error)
	})

	t.Run("decode invalid base64url", func(t *testing.T) {
		decoder := NewDecoder().FromString("invalid!").ByBase64Url()
		assert.Error(t, decoder.Error)
	})

	t.Run("decode unicode string", func(t *testing.T) {
		encoder := NewEncoder().FromString("你好世界").ByBase64Url()
		assert.Nil(t, encoder.Error)

		decoder := NewDecoder().FromBytes(encoder.dst).ByBase64Url()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, []byte("你好世界"), decoder.dst)
	})

	t.Run("decode single byte encoded", func(t *testing.T) {
		encoder := NewEncoder().FromBytes([]byte{0x41}).ByBase64Url()
		assert.Nil(t, encoder.Error)

		decoder := NewDecoder().FromBytes(encoder.dst).ByBase64Url()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, []byte{0x41}, decoder.dst)
	})

	t.Run("decode two bytes encoded", func(t *testing.T) {
		encoder := NewEncoder().FromBytes([]byte{0x41, 0x42}).ByBase64Url()
		assert.Nil(t, encoder.Error)

		decoder := NewDecoder().FromBytes(encoder.dst).ByBase64Url()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, []byte{0x41, 0x42}, decoder.dst)
	})

	t.Run("decode three bytes encoded", func(t *testing.T) {
		encoder := NewEncoder().FromBytes([]byte{0x41, 0x42, 0x43}).ByBase64Url()
		assert.Nil(t, encoder.Error)

		decoder := NewDecoder().FromBytes(encoder.dst).ByBase64Url()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, []byte{0x41, 0x42, 0x43}, decoder.dst)
	})

	t.Run("decode zero bytes encoded", func(t *testing.T) {
		encoder := NewEncoder().FromBytes([]byte{0x00, 0x00, 0x00, 0x00}).ByBase64Url()
		assert.Nil(t, encoder.Error)

		decoder := NewDecoder().FromBytes(encoder.dst).ByBase64Url()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, []byte{0x00, 0x00, 0x00, 0x00}, decoder.dst)
	})

	t.Run("decode max bytes encoded", func(t *testing.T) {
		encoder := NewEncoder().FromBytes([]byte{0xFF, 0xFF, 0xFF, 0xFF}).ByBase64Url()
		assert.Nil(t, encoder.Error)

		decoder := NewDecoder().FromBytes(encoder.dst).ByBase64Url()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, []byte{0xFF, 0xFF, 0xFF, 0xFF}, decoder.dst)
	})
}

func TestBase64RoundTrip(t *testing.T) {
	t.Run("base64 round trip", func(t *testing.T) {
		testData := "Hello, World! 你好世界"

		encoder := NewEncoder().FromString(testData).ByBase64()
		assert.Nil(t, encoder.Error)

		decoder := NewDecoder().FromBytes(encoder.dst).ByBase64()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, []byte(testData), decoder.dst)
	})

	t.Run("base64 round trip with file", func(t *testing.T) {
		testData := "Hello, World! 你好世界"

		file := mock.NewFile([]byte(testData), "test.txt")
		encoder := NewEncoder().FromFile(file).ByBase64()
		assert.Nil(t, encoder.Error)

		decoderFile := mock.NewFile(encoder.dst, "decoded.txt")
		decoder := NewDecoder().FromFile(decoderFile).ByBase64()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, []byte(testData), decoder.dst)
	})

	t.Run("base64 round trip with bytes", func(t *testing.T) {
		testData := []byte{0x00, 0x01, 0x02, 0x03, 0xFF, 0xFE, 0xFD, 0xFC}

		encoder := NewEncoder().FromBytes(testData).ByBase64()
		assert.Nil(t, encoder.Error)

		decoder := NewDecoder().FromBytes(encoder.dst).ByBase64()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, testData, decoder.dst)
	})
}

func TestBase64URLRoundTrip(t *testing.T) {
	t.Run("base64url round trip", func(t *testing.T) {
		testData := "Hello, World! 你好世界"

		encoder := NewEncoder().FromString(testData).ByBase64Url()
		assert.Nil(t, encoder.Error)

		decoder := NewDecoder().FromBytes(encoder.dst).ByBase64Url()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, []byte(testData), decoder.dst)
	})

	t.Run("base64url round trip with file", func(t *testing.T) {
		testData := "Hello, World! 你好世界"

		file := mock.NewFile([]byte(testData), "test.txt")
		encoder := NewEncoder().FromFile(file).ByBase64Url()
		assert.Nil(t, encoder.Error)

		decoderFile := mock.NewFile(encoder.dst, "decoded.txt")
		decoder := NewDecoder().FromFile(decoderFile).ByBase64Url()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, []byte(testData), decoder.dst)
	})

	t.Run("base64url round trip with bytes", func(t *testing.T) {
		testData := []byte{0x00, 0x01, 0x02, 0x03, 0xFF, 0xFE, 0xFD, 0xFC}

		encoder := NewEncoder().FromBytes(testData).ByBase64Url()
		assert.Nil(t, encoder.Error)

		decoder := NewDecoder().FromBytes(encoder.dst).ByBase64Url()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, testData, decoder.dst)
	})
}

func TestBase64EdgeCases(t *testing.T) {
	t.Run("very large data", func(t *testing.T) {
		largeData := strings.Repeat("Hello, World! ", 1000)

		encoder := NewEncoder().FromString(largeData).ByBase64()
		assert.Nil(t, encoder.Error)

		decoder := NewDecoder().FromBytes(encoder.dst).ByBase64()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, []byte(largeData), decoder.dst)
	})

	t.Run("single character", func(t *testing.T) {
		encoder := NewEncoder().FromString("A").ByBase64()
		assert.Nil(t, encoder.Error)
		assert.NotEmpty(t, encoder.dst)

		decoder := NewDecoder().FromBytes(encoder.dst).ByBase64()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, []byte("A"), decoder.dst)
	})

	t.Run("binary data", func(t *testing.T) {
		binaryData := []byte{0x00, 0x01, 0x02, 0x03, 0xFF, 0xFE, 0xFD, 0xFC}

		encoder := NewEncoder().FromBytes(binaryData).ByBase64()
		assert.Nil(t, encoder.Error)

		decoder := NewDecoder().FromBytes(encoder.dst).ByBase64()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, binaryData, decoder.dst)
	})

	t.Run("mixed encoding methods", func(t *testing.T) {
		testData := "hello world"

		encoder1 := NewEncoder().FromString(testData).ByBase64()
		encoder2 := NewEncoder().FromBytes([]byte(testData)).ByBase64()
		encoder3 := NewEncoder().FromFile(mock.NewFile([]byte(testData), "test.txt")).ByBase64()

		assert.Nil(t, encoder1.Error)
		assert.Nil(t, encoder2.Error)
		assert.Nil(t, encoder3.Error)
		assert.Equal(t, encoder1.dst, encoder2.dst)
		assert.Equal(t, encoder1.dst, encoder3.dst)
	})

	t.Run("zero bytes", func(t *testing.T) {
		zeroData := []byte{0x00, 0x00, 0x00, 0x00}

		encoder := NewEncoder().FromBytes(zeroData).ByBase64()
		assert.Nil(t, encoder.Error)

		decoder := NewDecoder().FromBytes(encoder.dst).ByBase64()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, zeroData, decoder.dst)
	})

	t.Run("max bytes", func(t *testing.T) {
		maxData := []byte{0xFF, 0xFF, 0xFF, 0xFF}

		encoder := NewEncoder().FromBytes(maxData).ByBase64()
		assert.Nil(t, encoder.Error)

		decoder := NewDecoder().FromBytes(encoder.dst).ByBase64()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, maxData, decoder.dst)
	})

	t.Run("all possible byte values", func(t *testing.T) {
		allBytes := make([]byte, 256)
		for i := 0; i < 256; i++ {
			allBytes[i] = byte(i)
		}

		encoder := NewEncoder().FromBytes(allBytes).ByBase64()
		assert.Nil(t, encoder.Error)

		decoder := NewDecoder().FromBytes(encoder.dst).ByBase64()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, allBytes, decoder.dst)
	})
}

func TestBase64URLEdgeCases(t *testing.T) {
	t.Run("very large data", func(t *testing.T) {
		largeData := strings.Repeat("Hello, World! ", 1000)

		encoder := NewEncoder().FromString(largeData).ByBase64Url()
		assert.Nil(t, encoder.Error)

		decoder := NewDecoder().FromBytes(encoder.dst).ByBase64Url()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, []byte(largeData), decoder.dst)
	})

	t.Run("single character", func(t *testing.T) {
		encoder := NewEncoder().FromString("A").ByBase64Url()
		assert.Nil(t, encoder.Error)
		assert.NotEmpty(t, encoder.dst)

		decoder := NewDecoder().FromBytes(encoder.dst).ByBase64Url()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, []byte("A"), decoder.dst)
	})

	t.Run("binary data", func(t *testing.T) {
		binaryData := []byte{0x00, 0x01, 0x02, 0x03, 0xFF, 0xFE, 0xFD, 0xFC}

		encoder := NewEncoder().FromBytes(binaryData).ByBase64Url()
		assert.Nil(t, encoder.Error)

		decoder := NewDecoder().FromBytes(encoder.dst).ByBase64Url()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, binaryData, decoder.dst)
	})

	t.Run("mixed encoding methods", func(t *testing.T) {
		testData := "hello world"

		encoder1 := NewEncoder().FromString(testData).ByBase64Url()
		encoder2 := NewEncoder().FromBytes([]byte(testData)).ByBase64Url()
		encoder3 := NewEncoder().FromFile(mock.NewFile([]byte(testData), "test.txt")).ByBase64Url()

		assert.Nil(t, encoder1.Error)
		assert.Nil(t, encoder2.Error)
		assert.Nil(t, encoder3.Error)
		assert.Equal(t, encoder1.dst, encoder2.dst)
		assert.Equal(t, encoder1.dst, encoder3.dst)
	})

	t.Run("zero bytes", func(t *testing.T) {
		zeroData := []byte{0x00, 0x00, 0x00, 0x00}

		encoder := NewEncoder().FromBytes(zeroData).ByBase64Url()
		assert.Nil(t, encoder.Error)

		decoder := NewDecoder().FromBytes(encoder.dst).ByBase64Url()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, zeroData, decoder.dst)
	})

	t.Run("max bytes", func(t *testing.T) {
		maxData := []byte{0xFF, 0xFF, 0xFF, 0xFF}

		encoder := NewEncoder().FromBytes(maxData).ByBase64Url()
		assert.Nil(t, encoder.Error)

		decoder := NewDecoder().FromBytes(encoder.dst).ByBase64Url()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, maxData, decoder.dst)
	})

	t.Run("all possible byte values", func(t *testing.T) {
		allBytes := make([]byte, 256)
		for i := 0; i < 256; i++ {
			allBytes[i] = byte(i)
		}

		encoder := NewEncoder().FromBytes(allBytes).ByBase64Url()
		assert.Nil(t, encoder.Error)

		decoder := NewDecoder().FromBytes(encoder.dst).ByBase64Url()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, allBytes, decoder.dst)
	})
}

func TestBase64ErrorHandling(t *testing.T) {
	t.Run("encoder error propagation", func(t *testing.T) {
		encoder := NewEncoder()
		encoder.Error = errors.New("test error")

		result := encoder.ByBase64()
		assert.Equal(t, encoder, result)
		assert.Equal(t, errors.New("test error"), result.Error)
	})

	t.Run("decoder error propagation", func(t *testing.T) {
		decoder := NewDecoder()
		decoder.Error = errors.New("test error")

		result := decoder.ByBase64()
		assert.Equal(t, decoder, result)
		assert.Equal(t, errors.New("test error"), result.Error)
	})

	t.Run("decoder invalid character", func(t *testing.T) {
		invalidData := []byte("AB!CD")
		decoder := NewDecoder().FromBytes(invalidData).ByBase64()
		assert.Error(t, decoder.Error)
	})

	t.Run("decoder corrupt data", func(t *testing.T) {
		corruptData := []byte("AB!CD")
		decoder := NewDecoder().FromBytes(corruptData).ByBase64()
		assert.Error(t, decoder.Error)
	})

	t.Run("decoder empty corrupted data", func(t *testing.T) {
		decoder := NewDecoder().FromBytes([]byte{}).ByBase64()
		assert.Nil(t, decoder.Error)
		assert.Nil(t, decoder.dst)
	})
}

func TestBase64URLErrorHandling(t *testing.T) {
	t.Run("encoder error propagation", func(t *testing.T) {
		encoder := NewEncoder()
		encoder.Error = errors.New("test error")

		result := encoder.ByBase64Url()
		assert.Equal(t, encoder, result)
		assert.Equal(t, errors.New("test error"), result.Error)
	})

	t.Run("decoder error propagation", func(t *testing.T) {
		decoder := NewDecoder()
		decoder.Error = errors.New("test error")

		result := decoder.ByBase64Url()
		assert.Equal(t, decoder, result)
		assert.Equal(t, errors.New("test error"), result.Error)
	})

	t.Run("decoder invalid character", func(t *testing.T) {
		invalidData := []byte("AB!CD")
		decoder := NewDecoder().FromBytes(invalidData).ByBase64Url()
		assert.Error(t, decoder.Error)
	})

	t.Run("decoder corrupt data", func(t *testing.T) {
		corruptData := []byte("AB!CD")
		decoder := NewDecoder().FromBytes(corruptData).ByBase64Url()
		assert.Error(t, decoder.Error)
	})

	t.Run("decoder empty corrupted data", func(t *testing.T) {
		decoder := NewDecoder().FromBytes([]byte{}).ByBase64Url()
		assert.Nil(t, decoder.Error)
		assert.Nil(t, decoder.dst)
	})
}

func TestBase64Specific(t *testing.T) {
	t.Run("base64 alphabet verification", func(t *testing.T) {
		testData := []byte{0x00, 0x01, 0x02}
		encoder := NewEncoder().FromBytes(testData).ByBase64()
		assert.Nil(t, encoder.Error)

		resultStr := string(encoder.dst)
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
			assert.NotEmpty(t, encoder.dst)

			decoder := NewDecoder().FromBytes(encoder.dst).ByBase64()
			assert.Nil(t, decoder.Error)
			assert.Equal(t, tc.input, decoder.dst)
		}
	})

	t.Run("base64 RFC 4648 compliance", func(t *testing.T) {
		testData := []byte("Hello, World!")
		encoder := NewEncoder().FromBytes(testData).ByBase64()
		assert.Nil(t, encoder.Error)

		decoder := NewDecoder().FromBytes(encoder.dst).ByBase64()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, testData, decoder.dst)
	})

	t.Run("base64 vs base64url comparison", func(t *testing.T) {
		testData := []byte("Hello, World!")

		encoder64 := NewEncoder().FromBytes(testData).ByBase64()
		assert.Nil(t, encoder64.Error)

		encoder64url := NewEncoder().FromBytes(testData).ByBase64Url()
		assert.Nil(t, encoder64url.Error)

		// Base64URL should not contain '+' or '/' characters
		resultStr := string(encoder64url.dst)
		assert.NotContains(t, resultStr, "+")
		assert.NotContains(t, resultStr, "/")

		// Both should decode back to the same data
		decoder64 := NewDecoder().FromBytes(encoder64.dst).ByBase64()
		decoder64url := NewDecoder().FromBytes(encoder64url.dst).ByBase64Url()

		assert.Nil(t, decoder64.Error)
		assert.Nil(t, decoder64url.Error)
		assert.Equal(t, testData, decoder64.dst)
		assert.Equal(t, testData, decoder64url.dst)
	})
}

func TestBase64URLSpecific(t *testing.T) {
	t.Run("base64url alphabet verification", func(t *testing.T) {
		testData := []byte{0x00, 0x01, 0x02}
		encoder := NewEncoder().FromBytes(testData).ByBase64Url()
		assert.Nil(t, encoder.Error)

		resultStr := string(encoder.dst)
		for _, char := range resultStr {
			assert.Contains(t, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_", string(char))
		}
	})

	t.Run("base64url URL safety", func(t *testing.T) {
		testData := []byte("Hello, World!")
		encoder := NewEncoder().FromBytes(testData).ByBase64Url()
		assert.Nil(t, encoder.Error)

		resultStr := string(encoder.dst)
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
			assert.NotEmpty(t, encoder.dst)

			decoder := NewDecoder().FromBytes(encoder.dst).ByBase64Url()
			assert.Nil(t, decoder.Error)
			assert.Equal(t, tc.input, decoder.dst)
		}
	})

	t.Run("base64url RFC 4648 compliance", func(t *testing.T) {
		testData := []byte("Hello, World!")
		encoder := NewEncoder().FromBytes(testData).ByBase64Url()
		assert.Nil(t, encoder.Error)

		decoder := NewDecoder().FromBytes(encoder.dst).ByBase64Url()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, testData, decoder.dst)
	})
}
