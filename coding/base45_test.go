package coding

import (
	"errors"
	"strings"
	"testing"

	"gitee.com/golang-package/dongle/mock"
	"github.com/stretchr/testify/assert"
)

func TestEncoder_ByBase45(t *testing.T) {
	t.Run("encode string", func(t *testing.T) {
		encoder := NewEncoder().FromString("hello world").ByBase45()
		assert.Nil(t, encoder.Error)
		// Base45 encoding of "hello world" = "+8D VD82EK4F.KEA2"
		assert.Equal(t, []byte("+8D VD82EK4F.KEA2"), encoder.dst)
	})

	t.Run("encode empty string", func(t *testing.T) {
		encoder := NewEncoder().FromString("").ByBase45()
		assert.Nil(t, encoder.Error)
		assert.Nil(t, encoder.dst)
	})

	t.Run("encode bytes", func(t *testing.T) {
		encoder := NewEncoder().FromBytes([]byte{0x00, 0x01, 0x02, 0x03}).ByBase45()
		assert.Nil(t, encoder.Error)
		// Base45 encoding of [0x00, 0x01, 0x02, 0x03] = "100KB0"
		assert.Equal(t, []byte("100KB0"), encoder.dst)
	})

	t.Run("encode empty bytes", func(t *testing.T) {
		encoder := NewEncoder().FromBytes([]byte{}).ByBase45()
		assert.Nil(t, encoder.Error)
		assert.Nil(t, encoder.dst)
	})

	t.Run("encode nil bytes", func(t *testing.T) {
		encoder := NewEncoder().FromBytes(nil).ByBase45()
		assert.Nil(t, encoder.Error)
		assert.Nil(t, encoder.dst)
	})

	t.Run("encode with file", func(t *testing.T) {
		file := mock.NewFile([]byte("hello world"), "test.txt")
		encoder := NewEncoder().FromFile(file).ByBase45()
		assert.Nil(t, encoder.Error)
		// Base45 encoding of "hello world" = "+8D VD82EK4F.KEA2"
		assert.Equal(t, []byte("+8D VD82EK4F.KEA2"), encoder.dst)
	})

	t.Run("encode with empty file", func(t *testing.T) {
		file := mock.NewFile([]byte{}, "empty.txt")
		encoder := NewEncoder().FromFile(file).ByBase45()
		assert.Nil(t, encoder.Error)
		assert.Equal(t, []byte{}, encoder.dst)
	})

	t.Run("encode with error file", func(t *testing.T) {
		errorFile := mock.NewErrorFile(errors.New("read error"))
		encoder := NewEncoder().FromFile(errorFile).ByBase45()
		assert.Error(t, encoder.Error)
		assert.Contains(t, encoder.Error.Error(), "read error")
	})

	t.Run("encode with existing error", func(t *testing.T) {
		encoder := NewEncoder()
		encoder.Error = errors.New("existing error")
		result := encoder.FromString("hello world").ByBase45()
		assert.Equal(t, encoder, result)
		assert.Equal(t, errors.New("existing error"), result.Error)
	})

	t.Run("encode unicode string", func(t *testing.T) {
		encoder := NewEncoder().FromString("你好世界").ByBase45()
		assert.Nil(t, encoder.Error)
		// Base45 encoding of "你好世界" = "C-SEFK*.K7-SL3JY+I"
		assert.Equal(t, []byte("C-SEFK*.K7-SL3JY+I"), encoder.dst)
	})

	t.Run("encode large data", func(t *testing.T) {
		largeData := strings.Repeat("Hello, World! ", 100)
		encoder := NewEncoder().FromString(largeData).ByBase45()
		assert.Nil(t, encoder.Error)
		// For large data, test round-trip instead of exact value
		decoder := NewDecoder().FromBytes(encoder.dst).ByBase45()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, []byte(largeData), decoder.dst)
	})

	t.Run("encode single byte", func(t *testing.T) {
		encoder := NewEncoder().FromBytes([]byte{0x41}).ByBase45()
		assert.Nil(t, encoder.Error)
		// Base45 encoding of byte 0x41 = "K1"
		assert.Equal(t, []byte("K1"), encoder.dst)
	})

	t.Run("encode two bytes", func(t *testing.T) {
		encoder := NewEncoder().FromBytes([]byte{0x41, 0x42}).ByBase45()
		assert.Nil(t, encoder.Error)
		// Base45 encoding of bytes [0x41, 0x42] = "BB8"
		assert.Equal(t, []byte("BB8"), encoder.dst)
	})

	t.Run("encode three bytes", func(t *testing.T) {
		encoder := NewEncoder().FromBytes([]byte{0x41, 0x42, 0x43}).ByBase45()
		assert.Nil(t, encoder.Error)
		// Base45 encoding of bytes [0x41, 0x42, 0x43] = "BB8M1"
		assert.Equal(t, []byte("BB8M1"), encoder.dst)
	})

	t.Run("encode zero bytes", func(t *testing.T) {
		encoder := NewEncoder().FromBytes([]byte{0x00, 0x00, 0x00, 0x00}).ByBase45()
		assert.Nil(t, encoder.Error)
		// Base45 encoding of zero bytes = "000000"
		assert.Equal(t, []byte("000000"), encoder.dst)
	})

	t.Run("encode max bytes", func(t *testing.T) {
		encoder := NewEncoder().FromBytes([]byte{0x41, 0x42, 0x43, 0x44, 0x45}).ByBase45()
		assert.Nil(t, encoder.Error)
		// Base45 encoding of bytes [0x41, 0x42, 0x43, 0x44, 0x45] = "BB8UM8O1"
		assert.Equal(t, []byte("BB8UM8O1"), encoder.dst)
	})
}

func TestDecoder_ByBase45(t *testing.T) {
	t.Run("decode string", func(t *testing.T) {
		// First encode some data
		encoder := NewEncoder().FromString("hello world").ByBase45()
		assert.Nil(t, encoder.Error)

		// Then decode it
		decoder := NewDecoder().FromBytes(encoder.dst).ByBase45()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, []byte("hello world"), decoder.dst)
	})

	t.Run("decode empty string", func(t *testing.T) {
		decoder := NewDecoder().FromString("").ByBase45()
		assert.Nil(t, decoder.Error)
		assert.Nil(t, decoder.dst)
	})

	t.Run("decode bytes", func(t *testing.T) {
		// First encode some data
		encoder := NewEncoder().FromBytes([]byte{0x00, 0x01, 0x02, 0x03}).ByBase45()
		assert.Nil(t, encoder.Error)

		// Then decode it
		decoder := NewDecoder().FromBytes(encoder.dst).ByBase45()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, []byte{0x00, 0x01, 0x02, 0x03}, decoder.dst)
	})

	t.Run("decode empty bytes", func(t *testing.T) {
		decoder := NewDecoder().FromBytes([]byte{}).ByBase45()
		assert.Nil(t, decoder.Error)
		assert.Nil(t, decoder.dst)
	})

	t.Run("decode nil bytes", func(t *testing.T) {
		decoder := NewDecoder().FromBytes(nil).ByBase45()
		assert.Nil(t, decoder.Error)
		assert.Nil(t, decoder.dst)
	})

	t.Run("decode with file", func(t *testing.T) {
		// First encode some data
		encoder := NewEncoder().FromString("hello world").ByBase45()
		assert.Nil(t, encoder.Error)

		// Then decode with file
		file := mock.NewFile(encoder.dst, "test.txt")
		decoder := NewDecoder().FromFile(file).ByBase45()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, []byte("hello world"), decoder.dst)
	})

	t.Run("decode with empty file", func(t *testing.T) {
		file := mock.NewFile([]byte{}, "empty.txt")
		decoder := NewDecoder().FromFile(file).ByBase45()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, []byte{}, decoder.dst)
	})

	t.Run("decode with error file", func(t *testing.T) {
		errorFile := mock.NewErrorFile(errors.New("read error"))
		decoder := NewDecoder().FromFile(errorFile).ByBase45()
		assert.Error(t, decoder.Error)
		assert.Contains(t, decoder.Error.Error(), "read error")
	})

	t.Run("decode with existing error", func(t *testing.T) {
		decoder := NewDecoder()
		decoder.Error = errors.New("existing error")
		result := decoder.FromString("test").ByBase45()
		assert.Equal(t, decoder, result)
		assert.Equal(t, errors.New("existing error"), result.Error)
	})

	t.Run("decode invalid base45", func(t *testing.T) {
		decoder := NewDecoder().FromString("invalid!").ByBase45()
		assert.Error(t, decoder.Error)
	})

	t.Run("decode unicode string", func(t *testing.T) {
		// First encode unicode data
		encoder := NewEncoder().FromString("你好世界").ByBase45()
		assert.Nil(t, encoder.Error)

		// Then decode it
		decoder := NewDecoder().FromBytes(encoder.dst).ByBase45()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, []byte("你好世界"), decoder.dst)
	})

	t.Run("decode with invalid length", func(t *testing.T) {
		// Create invalid base45 data (length not divisible by 2 or 3)
		invalidData := []byte("A") // Single character is invalid
		decoder := NewDecoder().FromBytes(invalidData).ByBase45()
		assert.Error(t, decoder.Error)
	})

	t.Run("decode single byte encoded", func(t *testing.T) {
		// Encode single byte
		encoder := NewEncoder().FromBytes([]byte{0x41}).ByBase45()
		assert.Nil(t, encoder.Error)

		// Decode it
		decoder := NewDecoder().FromBytes(encoder.dst).ByBase45()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, []byte{0x41}, decoder.dst)
	})

	t.Run("decode two bytes encoded", func(t *testing.T) {
		// Encode two bytes
		encoder := NewEncoder().FromBytes([]byte{0x41, 0x42}).ByBase45()
		assert.Nil(t, encoder.Error)

		// Decode it
		decoder := NewDecoder().FromBytes(encoder.dst).ByBase45()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, []byte{0x41, 0x42}, decoder.dst)
	})

	t.Run("decode three bytes encoded", func(t *testing.T) {
		// Encode three bytes
		encoder := NewEncoder().FromBytes([]byte{0x41, 0x42, 0x43}).ByBase45()
		assert.Nil(t, encoder.Error)

		// Decode it
		decoder := NewDecoder().FromBytes(encoder.dst).ByBase45()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, []byte{0x41, 0x42, 0x43}, decoder.dst)
	})

	t.Run("decode zero bytes encoded", func(t *testing.T) {
		// Encode zero bytes
		encoder := NewEncoder().FromBytes([]byte{0x00, 0x00, 0x00, 0x00}).ByBase45()
		assert.Nil(t, encoder.Error)

		// Decode it
		decoder := NewDecoder().FromBytes(encoder.dst).ByBase45()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, []byte{0x00, 0x00, 0x00, 0x00}, decoder.dst)
	})

	t.Run("decode max bytes encoded", func(t *testing.T) {
		// Encode max bytes
		encoder := NewEncoder().FromBytes([]byte{0x41, 0x42, 0x43, 0x44, 0x45}).ByBase45()
		assert.Nil(t, encoder.Error)

		// Decode it
		decoder := NewDecoder().FromBytes(encoder.dst).ByBase45()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, []byte{0x41, 0x42, 0x43, 0x44, 0x45}, decoder.dst)
	})
}

func TestError_ByBase45(t *testing.T) {
	t.Run("encoder error propagation", func(t *testing.T) {
		encoder := NewEncoder()
		encoder.Error = errors.New("test error")

		result := encoder.ByBase45()
		assert.Equal(t, encoder, result)
		assert.Equal(t, "test error", result.Error.Error())
	})

	t.Run("decoder error propagation", func(t *testing.T) {
		decoder := NewDecoder()
		decoder.Error = errors.New("test error")

		result := decoder.ByBase45()
		assert.Equal(t, decoder, result)
		assert.Equal(t, "test error", result.Error.Error())
	})

	t.Run("decoder invalid character", func(t *testing.T) {
		// Create data with invalid base45 characters
		invalidData := []byte("invalid!") // '!' is not a valid base45 character
		decoder := NewDecoder().FromBytes(invalidData).ByBase45()
		assert.Error(t, decoder.Error)
		assert.Contains(t, decoder.Error.Error(), "invalid character")
	})

	t.Run("decoder corrupt data", func(t *testing.T) {
		// Create corrupt base45 data
		corruptData := []byte(":::") // Valid length but values too large
		decoder := NewDecoder().FromBytes(corruptData).ByBase45()
		assert.Error(t, decoder.Error)
		assert.Contains(t, decoder.Error.Error(), "illegal data")
	})

	t.Run("decoder invalid length", func(t *testing.T) {
		// Create data with invalid length (not 0 or 2 mod 3)
		invalidLength := []byte("A") // Length 1 is invalid
		decoder := NewDecoder().FromBytes(invalidLength).ByBase45()
		assert.Error(t, decoder.Error)
		assert.Contains(t, decoder.Error.Error(), "invalid length")
	})

	t.Run("decoder with error file", func(t *testing.T) {
		errorFile := mock.NewErrorFile(errors.New("read error"))
		decoder := NewDecoder().FromFile(errorFile).ByBase45()
		assert.Error(t, decoder.Error)
		assert.Contains(t, decoder.Error.Error(), "read error")
	})

	t.Run("encoder with error file", func(t *testing.T) {
		errorFile := mock.NewErrorFile(errors.New("read error"))
		encoder := NewEncoder().FromFile(errorFile).ByBase45()
		assert.Error(t, encoder.Error)
		assert.Contains(t, encoder.Error.Error(), "read error")
	})
}
