package coding

import (
	"errors"
	"strings"
	"testing"

	"github.com/dromara/dongle/mock"
	"github.com/stretchr/testify/assert"
)

func TestEncoder_ByHex(t *testing.T) {
	t.Run("encode string", func(t *testing.T) {
		encoder := NewEncoder().FromString("hello world").ByHex()
		assert.Nil(t, encoder.Error)
		// Hex encoding of "hello world" = "68656c6c6f20776f726c64"
		assert.Equal(t, []byte("68656c6c6f20776f726c64"), encoder.dst)
	})

	t.Run("encode empty string", func(t *testing.T) {
		encoder := NewEncoder().FromString("").ByHex()
		assert.Nil(t, encoder.Error)
		assert.Nil(t, encoder.dst)
	})

	t.Run("encode bytes", func(t *testing.T) {
		encoder := NewEncoder().FromBytes([]byte{0x00, 0x01, 0x02, 0x03}).ByHex()
		assert.Nil(t, encoder.Error)
		// Hex encoding of [0x00, 0x01, 0x02, 0x03] = "00010203"
		assert.Equal(t, []byte("00010203"), encoder.dst)
	})

	t.Run("encode empty bytes", func(t *testing.T) {
		encoder := NewEncoder().FromBytes([]byte{}).ByHex()
		assert.Nil(t, encoder.Error)
		assert.Nil(t, encoder.dst)
	})

	t.Run("encode nil bytes", func(t *testing.T) {
		encoder := NewEncoder().FromBytes(nil).ByHex()
		assert.Nil(t, encoder.Error)
		assert.Nil(t, encoder.dst)
	})

	t.Run("encode with file", func(t *testing.T) {
		file := mock.NewFile([]byte("hello world"), "test.txt")
		encoder := NewEncoder().FromFile(file).ByHex()
		assert.Nil(t, encoder.Error)
		// Hex encoding of "hello world" = "68656c6c6f20776f726c64"
		assert.Equal(t, []byte("68656c6c6f20776f726c64"), encoder.dst)
	})

	t.Run("encode with empty file", func(t *testing.T) {
		file := mock.NewFile([]byte{}, "empty.txt")
		encoder := NewEncoder().FromFile(file).ByHex()
		assert.Nil(t, encoder.Error)
		assert.Equal(t, []byte{}, encoder.dst)
	})

	t.Run("encode with error file", func(t *testing.T) {
		errorFile := mock.NewErrorFile(errors.New("read error"))
		encoder := NewEncoder().FromFile(errorFile).ByHex()
		assert.Error(t, encoder.Error)
		assert.Contains(t, encoder.Error.Error(), "read error")
	})

	t.Run("encode with existing error", func(t *testing.T) {
		encoder := NewEncoder()
		encoder.Error = errors.New("existing error")
		result := encoder.FromString("hello world").ByHex()
		assert.Equal(t, encoder, result)
		assert.Equal(t, "existing error", result.Error.Error())
	})

	t.Run("encode unicode string", func(t *testing.T) {
		encoder := NewEncoder().FromString("你好世界").ByHex()
		assert.Nil(t, encoder.Error)
		// Hex encoding of "你好世界" = "e4bda0e5a5bde4b896e7958c"
		assert.Equal(t, []byte("e4bda0e5a5bde4b896e7958c"), encoder.dst)
	})

	t.Run("encode large data", func(t *testing.T) {
		largeData := strings.Repeat("Hello, World! ", 100)
		encoder := NewEncoder().FromString(largeData).ByHex()
		assert.Nil(t, encoder.Error)
		// For large data, test round-trip instead of exact value
		decoder := NewDecoder().FromBytes(encoder.dst).ByHex()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, []byte(largeData), decoder.dst)
	})

	t.Run("encode single byte", func(t *testing.T) {
		encoder := NewEncoder().FromBytes([]byte{0x41}).ByHex()
		assert.Nil(t, encoder.Error)
		// Hex encoding of byte 0x41 = "41"
		assert.Equal(t, []byte("41"), encoder.dst)
	})

	t.Run("encode two bytes", func(t *testing.T) {
		encoder := NewEncoder().FromBytes([]byte{0x41, 0x42}).ByHex()
		assert.Nil(t, encoder.Error)
		// Hex encoding of bytes [0x41, 0x42] = "4142"
		assert.Equal(t, []byte("4142"), encoder.dst)
	})

	t.Run("encode three bytes", func(t *testing.T) {
		encoder := NewEncoder().FromBytes([]byte{0x41, 0x42, 0x43}).ByHex()
		assert.Nil(t, encoder.Error)
		// Hex encoding of bytes [0x41, 0x42, 0x43] = "414243"
		assert.Equal(t, []byte("414243"), encoder.dst)
	})

	t.Run("encode zero bytes", func(t *testing.T) {
		encoder := NewEncoder().FromBytes([]byte{0x00, 0x00, 0x00, 0x00}).ByHex()
		assert.Nil(t, encoder.Error)
		// Hex encoding of zero bytes = "00000000"
		assert.Equal(t, []byte("00000000"), encoder.dst)
	})

	t.Run("encode max bytes", func(t *testing.T) {
		encoder := NewEncoder().FromBytes([]byte{0xFF, 0xFF, 0xFF, 0xFF}).ByHex()
		assert.Nil(t, encoder.Error)
		// Hex encoding of max bytes = "ffffffff"
		assert.Equal(t, []byte("ffffffff"), encoder.dst)
	})
}

func TestDecoder_ByHex(t *testing.T) {
	t.Run("decode string", func(t *testing.T) {
		encoder := NewEncoder().FromString("hello world").ByHex()
		assert.Nil(t, encoder.Error)

		decoder := NewDecoder().FromBytes(encoder.dst).ByHex()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, []byte("hello world"), decoder.dst)
	})

	t.Run("decode empty string", func(t *testing.T) {
		decoder := NewDecoder().FromString("").ByHex()
		assert.Nil(t, decoder.Error)
		assert.Nil(t, decoder.dst)
	})

	t.Run("decode bytes", func(t *testing.T) {
		encoder := NewEncoder().FromBytes([]byte{0x00, 0x01, 0x02, 0x03}).ByHex()
		assert.Nil(t, encoder.Error)

		decoder := NewDecoder().FromBytes(encoder.dst).ByHex()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, []byte{0x00, 0x01, 0x02, 0x03}, decoder.dst)
	})

	t.Run("decode empty bytes", func(t *testing.T) {
		decoder := NewDecoder().FromBytes([]byte{}).ByHex()
		assert.Nil(t, decoder.Error)
		assert.Nil(t, decoder.dst)
	})

	t.Run("decode nil bytes", func(t *testing.T) {
		decoder := NewDecoder().FromBytes(nil).ByHex()
		assert.Nil(t, decoder.Error)
		assert.Nil(t, decoder.dst)
	})

	t.Run("decode with file", func(t *testing.T) {
		encoder := NewEncoder().FromString("hello world").ByHex()
		assert.Nil(t, encoder.Error)

		file := mock.NewFile(encoder.dst, "test.txt")
		decoder := NewDecoder().FromFile(file).ByHex()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, []byte("hello world"), decoder.dst)
	})

	t.Run("decode with empty file", func(t *testing.T) {
		file := mock.NewFile([]byte{}, "empty.txt")
		decoder := NewDecoder().FromFile(file).ByHex()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, []byte{}, decoder.dst)
	})

	t.Run("decode with error file", func(t *testing.T) {
		errorFile := mock.NewErrorFile(errors.New("read error"))
		decoder := NewDecoder().FromFile(errorFile).ByHex()
		assert.Error(t, decoder.Error)
		assert.Contains(t, decoder.Error.Error(), "read error")
	})

	t.Run("decode with existing error", func(t *testing.T) {
		decoder := NewDecoder()
		decoder.Error = errors.New("existing error")
		result := decoder.FromString("test").ByHex()
		assert.Equal(t, decoder, result)
		assert.Equal(t, "existing error", result.Error.Error())
	})

	t.Run("decode invalid hex", func(t *testing.T) {
		decoder := NewDecoder().FromString("invalid!").ByHex()
		assert.Error(t, decoder.Error)
	})

	t.Run("decode unicode string", func(t *testing.T) {
		encoder := NewEncoder().FromString("你好世界").ByHex()
		assert.Nil(t, encoder.Error)

		decoder := NewDecoder().FromBytes(encoder.dst).ByHex()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, []byte("你好世界"), decoder.dst)
	})

	t.Run("decode single byte encoded", func(t *testing.T) {
		encoder := NewEncoder().FromBytes([]byte{0x41}).ByHex()
		assert.Nil(t, encoder.Error)

		decoder := NewDecoder().FromBytes(encoder.dst).ByHex()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, []byte{0x41}, decoder.dst)
	})

	t.Run("decode two bytes encoded", func(t *testing.T) {
		encoder := NewEncoder().FromBytes([]byte{0x41, 0x42}).ByHex()
		assert.Nil(t, encoder.Error)

		decoder := NewDecoder().FromBytes(encoder.dst).ByHex()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, []byte{0x41, 0x42}, decoder.dst)
	})

	t.Run("decode three bytes encoded", func(t *testing.T) {
		encoder := NewEncoder().FromBytes([]byte{0x41, 0x42, 0x43}).ByHex()
		assert.Nil(t, encoder.Error)

		decoder := NewDecoder().FromBytes(encoder.dst).ByHex()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, []byte{0x41, 0x42, 0x43}, decoder.dst)
	})

	t.Run("decode zero bytes encoded", func(t *testing.T) {
		encoder := NewEncoder().FromBytes([]byte{0x00, 0x00, 0x00, 0x00}).ByHex()
		assert.Nil(t, encoder.Error)

		decoder := NewDecoder().FromBytes(encoder.dst).ByHex()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, []byte{0x00, 0x00, 0x00, 0x00}, decoder.dst)
	})

	t.Run("decode max bytes encoded", func(t *testing.T) {
		encoder := NewEncoder().FromBytes([]byte{0xFF, 0xFF, 0xFF, 0xFF}).ByHex()
		assert.Nil(t, encoder.Error)

		decoder := NewDecoder().FromBytes(encoder.dst).ByHex()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, []byte{0xFF, 0xFF, 0xFF, 0xFF}, decoder.dst)
	})
}

func TestError_ByHex(t *testing.T) {
	t.Run("encoder error propagation", func(t *testing.T) {
		encoder := NewEncoder()
		encoder.Error = errors.New("test error")

		result := encoder.ByHex()
		assert.Equal(t, encoder, result)
		assert.Equal(t, "test error", result.Error.Error())
	})

	t.Run("decoder error propagation", func(t *testing.T) {
		decoder := NewDecoder()
		decoder.Error = errors.New("test error")

		result := decoder.ByHex()
		assert.Equal(t, decoder, result)
		assert.Equal(t, "test error", result.Error.Error())
	})

	t.Run("decoder with error file", func(t *testing.T) {
		errorFile := mock.NewErrorFile(errors.New("read error"))
		decoder := NewDecoder().FromFile(errorFile).ByHex()
		assert.Error(t, decoder.Error)
		assert.Contains(t, decoder.Error.Error(), "read error")
	})

	t.Run("encoder with error file", func(t *testing.T) {
		errorFile := mock.NewErrorFile(errors.New("read error"))
		encoder := NewEncoder().FromFile(errorFile).ByHex()
		assert.Error(t, encoder.Error)
		assert.Contains(t, encoder.Error.Error(), "read error")
	})

	t.Run("decoder invalid character", func(t *testing.T) {
		invalidData := []byte("AB!CD")
		decoder := NewDecoder().FromBytes(invalidData).ByHex()
		assert.Error(t, decoder.Error)
	})

	t.Run("decoder odd length hex", func(t *testing.T) {
		oddLengthData := []byte("ABC")
		decoder := NewDecoder().FromBytes(oddLengthData).ByHex()
		assert.Error(t, decoder.Error)
	})

	t.Run("decoder non-hex characters", func(t *testing.T) {
		nonHexData := []byte("GHIJKL")
		decoder := NewDecoder().FromBytes(nonHexData).ByHex()
		assert.Error(t, decoder.Error)
	})

	t.Run("hex alphabet verification", func(t *testing.T) {
		testData := []byte{0x00, 0x01, 0x02}
		encoder := NewEncoder().FromBytes(testData).ByHex()
		assert.Nil(t, encoder.Error)

		resultStr := string(encoder.dst)
		for _, char := range resultStr {
			assert.Contains(t, "0123456789abcdef", string(char))
		}
	})

	t.Run("hex case sensitivity", func(t *testing.T) {
		testData := []byte{0x41, 0x42, 0x43}

		encoder := NewEncoder().FromBytes(testData).ByHex()
		assert.Nil(t, encoder.Error)

		// Hex encoding should be lowercase
		resultStr := string(encoder.dst)
		assert.Equal(t, strings.ToLower(resultStr), resultStr)
	})

	t.Run("hex encoding efficiency", func(t *testing.T) {
		testData := []byte{0x00, 0x01, 0x02, 0x03}
		encoder := NewEncoder().FromBytes(testData).ByHex()
		assert.Nil(t, encoder.Error)

		// Hex encoding should double the size
		assert.Equal(t, len(testData)*2, len(encoder.dst))
	})

	t.Run("hex decoding efficiency", func(t *testing.T) {
		hexData := []byte("00010203")
		decoder := NewDecoder().FromBytes(hexData).ByHex()
		assert.Nil(t, decoder.Error)

		// Hex decoding should halve the size
		assert.Equal(t, len(hexData)/2, len(decoder.dst))
	})
}
