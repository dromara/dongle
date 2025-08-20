package coding

import (
	"errors"
	"strings"
	"testing"

	"gitee.com/golang-package/dongle/mock"
	"github.com/stretchr/testify/assert"
)

func TestEncoder_ByBase62(t *testing.T) {
	t.Run("encode string", func(t *testing.T) {
		encoder := NewEncoder().FromString("hello world").ByBase62()
		assert.Nil(t, encoder.Error)
		// Base62 encoding of "hello world" = "AAwf93rvy4aWQVw"
		assert.Equal(t, []byte("AAwf93rvy4aWQVw"), encoder.dst)
	})

	t.Run("encode empty string", func(t *testing.T) {
		encoder := NewEncoder().FromString("").ByBase62()
		assert.Nil(t, encoder.Error)
		assert.Nil(t, encoder.dst)
	})

	t.Run("encode bytes", func(t *testing.T) {
		encoder := NewEncoder().FromBytes([]byte{0x00, 0x01, 0x02, 0x03}).ByBase62()
		assert.Nil(t, encoder.Error)
		// Base62 encoding of [0x00, 0x01, 0x02, 0x03] = "01HBL"
		assert.Equal(t, []byte("01HBL"), encoder.dst)
	})

	t.Run("encode empty bytes", func(t *testing.T) {
		encoder := NewEncoder().FromBytes([]byte{}).ByBase62()
		assert.Nil(t, encoder.Error)
		assert.Nil(t, encoder.dst)
	})

	t.Run("encode nil bytes", func(t *testing.T) {
		encoder := NewEncoder().FromBytes(nil).ByBase62()
		assert.Nil(t, encoder.Error)
		assert.Nil(t, encoder.dst)
	})

	t.Run("encode with file", func(t *testing.T) {
		file := mock.NewFile([]byte("hello world"), "test.txt")
		encoder := NewEncoder().FromFile(file).ByBase62()
		assert.Nil(t, encoder.Error)
		// Base62 encoding of "hello world" = "AAwf93rvy4aWQVw"
		assert.Equal(t, []byte("AAwf93rvy4aWQVw"), encoder.dst)
	})

	t.Run("encode with empty file", func(t *testing.T) {
		file := mock.NewFile([]byte{}, "empty.txt")
		encoder := NewEncoder().FromFile(file).ByBase62()
		assert.Nil(t, encoder.Error)
		assert.Equal(t, []byte{}, encoder.dst)
	})

	t.Run("encode with error file", func(t *testing.T) {
		errorFile := mock.NewErrorFile(errors.New("read error"))
		encoder := NewEncoder().FromFile(errorFile).ByBase62()
		assert.Error(t, encoder.Error)
		assert.Contains(t, encoder.Error.Error(), "read error")
	})

	t.Run("encode with existing error", func(t *testing.T) {
		encoder := NewEncoder()
		encoder.Error = errors.New("existing error")
		result := encoder.FromString("hello world").ByBase62()
		assert.Equal(t, encoder, result)
		assert.Equal(t, "existing error", result.Error.Error())
	})

	t.Run("encode unicode string", func(t *testing.T) {
		encoder := NewEncoder().FromString("你好世界").ByBase62()
		assert.Nil(t, encoder.Error)
		// Base62 encoding of "你好世界" = "1U4CduNxcFtHO7M3I"
		assert.Equal(t, []byte("1U4CduNxcFtHO7M3I"), encoder.dst)
	})

	t.Run("encode large data", func(t *testing.T) {
		largeData := strings.Repeat("Hello, World! ", 100)
		encoder := NewEncoder().FromString(largeData).ByBase62()
		assert.Nil(t, encoder.Error)
		// For large data, test round-trip instead of exact value
		decoder := NewDecoder().FromBytes(encoder.dst).ByBase62()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, []byte(largeData), decoder.dst)
	})

	t.Run("encode single byte", func(t *testing.T) {
		encoder := NewEncoder().FromBytes([]byte{0x41}).ByBase62()
		assert.Nil(t, encoder.Error)
		// Base62 encoding of byte 0x41 = "13"
		assert.Equal(t, []byte("13"), encoder.dst)
	})

	t.Run("encode two bytes", func(t *testing.T) {
		encoder := NewEncoder().FromBytes([]byte{0x41, 0x42}).ByBase62()
		assert.Nil(t, encoder.Error)
		// Base62 encoding of bytes [0x41, 0x42] = "4LS"
		assert.Equal(t, []byte("4LS"), encoder.dst)
	})

	t.Run("encode three bytes", func(t *testing.T) {
		encoder := NewEncoder().FromBytes([]byte{0x41, 0x42, 0x43}).ByBase62()
		assert.Nil(t, encoder.Error)
		// Base62 encoding of bytes [0x41, 0x42, 0x43] = "Hwah"
		assert.Equal(t, []byte("Hwah"), encoder.dst)
	})

	t.Run("encode zero bytes", func(t *testing.T) {
		encoder := NewEncoder().FromBytes([]byte{0x00, 0x00, 0x00, 0x00}).ByBase62()
		assert.Nil(t, encoder.Error)
		// Base62 encoding of zero bytes = "04"
		assert.Equal(t, []byte("04"), encoder.dst)
	})

	t.Run("encode max bytes", func(t *testing.T) {
		encoder := NewEncoder().FromBytes([]byte{0xFF, 0xFF, 0xFF, 0xFF}).ByBase62()
		assert.Nil(t, encoder.Error)
		// Base62 encoding of max bytes = "4gfFC3"
		assert.Equal(t, []byte("4gfFC3"), encoder.dst)
	})
}

func TestDecoder_ByBase62(t *testing.T) {
	t.Run("decode string", func(t *testing.T) {
		// First encode some data
		encoder := NewEncoder().FromString("hello world").ByBase62()
		assert.Nil(t, encoder.Error)

		// Then decode it
		decoder := NewDecoder().FromBytes(encoder.dst).ByBase62()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, []byte("hello world"), decoder.dst)
	})

	t.Run("decode empty string", func(t *testing.T) {
		decoder := NewDecoder().FromString("").ByBase62()
		assert.Nil(t, decoder.Error)
		assert.Nil(t, decoder.dst)
	})

	t.Run("decode bytes", func(t *testing.T) {
		// First encode some data
		encoder := NewEncoder().FromBytes([]byte{0x00, 0x01, 0x02, 0x03}).ByBase62()
		assert.Nil(t, encoder.Error)

		// Then decode it
		decoder := NewDecoder().FromBytes(encoder.dst).ByBase62()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, []byte{0x00, 0x01, 0x02, 0x03}, decoder.dst)
	})

	t.Run("decode empty bytes", func(t *testing.T) {
		decoder := NewDecoder().FromBytes([]byte{}).ByBase62()
		assert.Nil(t, decoder.Error)
		assert.Nil(t, decoder.dst)
	})

	t.Run("decode nil bytes", func(t *testing.T) {
		decoder := NewDecoder().FromBytes(nil).ByBase62()
		assert.Nil(t, decoder.Error)
		assert.Nil(t, decoder.dst)
	})

	t.Run("decode with file", func(t *testing.T) {
		// First encode some data
		encoder := NewEncoder().FromString("hello world").ByBase62()
		assert.Nil(t, encoder.Error)

		// Then decode with file
		file := mock.NewFile(encoder.dst, "test.txt")
		decoder := NewDecoder().FromFile(file).ByBase62()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, []byte("hello world"), decoder.dst)
	})

	t.Run("decode with empty file", func(t *testing.T) {
		file := mock.NewFile([]byte{}, "empty.txt")
		decoder := NewDecoder().FromFile(file).ByBase62()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, []byte{}, decoder.dst)
	})

	t.Run("decode with error file", func(t *testing.T) {
		errorFile := mock.NewErrorFile(errors.New("read error"))
		decoder := NewDecoder().FromFile(errorFile).ByBase62()
		assert.Error(t, decoder.Error)
		assert.Contains(t, decoder.Error.Error(), "read error")
	})

	t.Run("decode with existing error", func(t *testing.T) {
		decoder := NewDecoder()
		decoder.Error = errors.New("existing error")
		result := decoder.FromString("AAwf93rvy4aWQVw").ByBase62()
		assert.Equal(t, decoder, result)
		assert.Equal(t, "existing error", result.Error.Error())
	})

	t.Run("decode invalid base62", func(t *testing.T) {
		decoder := NewDecoder().FromString("invalid!").ByBase62()
		assert.Error(t, decoder.Error)
	})

	t.Run("decode unicode string", func(t *testing.T) {
		// First encode unicode data
		encoder := NewEncoder().FromString("你好世界").ByBase62()
		assert.Nil(t, encoder.Error)

		// Then decode it
		decoder := NewDecoder().FromBytes(encoder.dst).ByBase62()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, []byte("你好世界"), decoder.dst)
	})

	t.Run("decode single byte encoded", func(t *testing.T) {
		// Encode single byte
		encoder := NewEncoder().FromBytes([]byte{0x41}).ByBase62()
		assert.Nil(t, encoder.Error)

		// Decode it
		decoder := NewDecoder().FromBytes(encoder.dst).ByBase62()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, []byte{0x41}, decoder.dst)
	})

	t.Run("decode two bytes encoded", func(t *testing.T) {
		// Encode two bytes
		encoder := NewEncoder().FromBytes([]byte{0x41, 0x42}).ByBase62()
		assert.Nil(t, encoder.Error)

		// Decode it
		decoder := NewDecoder().FromBytes(encoder.dst).ByBase62()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, []byte{0x41, 0x42}, decoder.dst)
	})

	t.Run("decode three bytes encoded", func(t *testing.T) {
		// Encode three bytes
		encoder := NewEncoder().FromBytes([]byte{0x41, 0x42, 0x43}).ByBase62()
		assert.Nil(t, encoder.Error)

		// Decode it
		decoder := NewDecoder().FromBytes(encoder.dst).ByBase62()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, []byte{0x41, 0x42, 0x43}, decoder.dst)
	})

	t.Run("decode zero bytes encoded", func(t *testing.T) {
		// Encode zero bytes
		encoder := NewEncoder().FromBytes([]byte{0x00, 0x00, 0x00, 0x00}).ByBase62()
		assert.Nil(t, encoder.Error)

		// Decode it
		decoder := NewDecoder().FromBytes(encoder.dst).ByBase62()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, []byte{0x00, 0x00, 0x00, 0x00}, decoder.dst)
	})

	t.Run("decode max bytes encoded", func(t *testing.T) {
		// Encode max bytes
		encoder := NewEncoder().FromBytes([]byte{0xFF, 0xFF, 0xFF, 0xFF}).ByBase62()
		assert.Nil(t, encoder.Error)

		// Decode it
		decoder := NewDecoder().FromBytes(encoder.dst).ByBase62()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, []byte{0xFF, 0xFF, 0xFF, 0xFF}, decoder.dst)
	})
}

func TestError_ByBase62(t *testing.T) {
	t.Run("encoder error propagation", func(t *testing.T) {
		encoder := NewEncoder()
		encoder.Error = errors.New("test error")

		result := encoder.ByBase62()
		assert.Equal(t, encoder, result)
		assert.Equal(t, "test error", result.Error.Error())
	})

	t.Run("decoder error propagation", func(t *testing.T) {
		decoder := NewDecoder()
		decoder.Error = errors.New("test error")

		result := decoder.ByBase62()
		assert.Equal(t, decoder, result)
		assert.Equal(t, "test error", result.Error.Error())
	})

	t.Run("decoder invalid character", func(t *testing.T) {
		// Create data with invalid base62 characters
		invalidData := []byte("invalid!") // '!' is not a valid base62 character
		decoder := NewDecoder().FromBytes(invalidData).ByBase62()
		assert.Error(t, decoder.Error)
	})

	t.Run("decoder corrupt data", func(t *testing.T) {
		// Create corrupt base62 data with invalid characters
		corruptData := []byte("AB!") // '!' is not a valid base62 character
		decoder := NewDecoder().FromBytes(corruptData).ByBase62()
		assert.Error(t, decoder.Error)
	})

	t.Run("decoder with error file", func(t *testing.T) {
		errorFile := mock.NewErrorFile(errors.New("read error"))
		decoder := NewDecoder().FromFile(errorFile).ByBase62()
		assert.Error(t, decoder.Error)
		assert.Contains(t, decoder.Error.Error(), "read error")
	})

	t.Run("encoder with error file", func(t *testing.T) {
		errorFile := mock.NewErrorFile(errors.New("read error"))
		encoder := NewEncoder().FromFile(errorFile).ByBase62()
		assert.Error(t, encoder.Error)
		assert.Contains(t, encoder.Error.Error(), "read error")
	})
}
