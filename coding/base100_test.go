package coding

import (
	"errors"
	"strings"
	"testing"

	"github.com/dromara/dongle/mock"
	"github.com/stretchr/testify/assert"
)

func TestEncoder_ByBase100(t *testing.T) {
	t.Run("encode string", func(t *testing.T) {
		encoder := NewEncoder().FromString("hello world").ByBase100()
		assert.Nil(t, encoder.Error)
		// Base100 encoding of "hello world" = []byte{0xf0, 0x9f, 0x91, 0x9f, 0xf0, 0x9f, 0x91, 0x9c, 0xf0, 0x9f, 0x91, 0xa3, 0xf0, 0x9f, 0x91, 0xa3, 0xf0, 0x9f, 0x91, 0xa6, 0xf0, 0x9f, 0x90, 0x97, 0xf0, 0x9f, 0x91, 0xae, 0xf0, 0x9f, 0x91, 0xa6, 0xf0, 0x9f, 0x91, 0xa9, 0xf0, 0x9f, 0x91, 0xa3, 0xf0, 0x9f, 0x91, 0x9b}
		assert.Equal(t, []byte{0xf0, 0x9f, 0x91, 0x9f, 0xf0, 0x9f, 0x91, 0x9c, 0xf0, 0x9f, 0x91, 0xa3, 0xf0, 0x9f, 0x91, 0xa3, 0xf0, 0x9f, 0x91, 0xa6, 0xf0, 0x9f, 0x90, 0x97, 0xf0, 0x9f, 0x91, 0xae, 0xf0, 0x9f, 0x91, 0xa6, 0xf0, 0x9f, 0x91, 0xa9, 0xf0, 0x9f, 0x91, 0xa3, 0xf0, 0x9f, 0x91, 0x9b}, encoder.dst)
	})

	t.Run("encode empty string", func(t *testing.T) {
		encoder := NewEncoder().FromString("").ByBase100()
		assert.Nil(t, encoder.Error)
		assert.Nil(t, encoder.dst)
	})

	t.Run("encode bytes", func(t *testing.T) {
		encoder := NewEncoder().FromBytes([]byte{0x00, 0x01, 0x02, 0x03}).ByBase100()
		assert.Nil(t, encoder.Error)
		// Base100 encoding of [0x00, 0x01, 0x02, 0x03] = []byte{0xf0, 0x9f, 0x8f, 0xb7, 0xf0, 0x9f, 0x8f, 0xb8, 0xf0, 0x9f, 0x8f, 0xb9, 0xf0, 0x9f, 0x8f, 0xba}
		assert.Equal(t, []byte{0xf0, 0x9f, 0x8f, 0xb7, 0xf0, 0x9f, 0x8f, 0xb8, 0xf0, 0x9f, 0x8f, 0xb9, 0xf0, 0x9f, 0x8f, 0xba}, encoder.dst)
	})

	t.Run("encode empty bytes", func(t *testing.T) {
		encoder := NewEncoder().FromBytes([]byte{}).ByBase100()
		assert.Nil(t, encoder.Error)
		assert.Nil(t, encoder.dst)
	})

	t.Run("encode nil bytes", func(t *testing.T) {
		encoder := NewEncoder().FromBytes(nil).ByBase100()
		assert.Nil(t, encoder.Error)
		assert.Nil(t, encoder.dst)
	})

	t.Run("encode with file", func(t *testing.T) {
		file := mock.NewFile([]byte("hello world"), "test.txt")
		encoder := NewEncoder().FromFile(file).ByBase100()
		assert.Nil(t, encoder.Error)
		// Base100 encoding of "hello world" = []byte{0xf0, 0x9f, 0x91, 0x9f, 0xf0, 0x9f, 0x91, 0x9c, 0xf0, 0x9f, 0x91, 0xa3, 0xf0, 0x9f, 0x91, 0xa3, 0xf0, 0x9f, 0x91, 0xa6, 0xf0, 0x9f, 0x90, 0x97, 0xf0, 0x9f, 0x91, 0xae, 0xf0, 0x9f, 0x91, 0xa6, 0xf0, 0x9f, 0x91, 0xa9, 0xf0, 0x9f, 0x91, 0xa3, 0xf0, 0x9f, 0x91, 0x9b}
		assert.Equal(t, []byte{0xf0, 0x9f, 0x91, 0x9f, 0xf0, 0x9f, 0x91, 0x9c, 0xf0, 0x9f, 0x91, 0xa3, 0xf0, 0x9f, 0x91, 0xa3, 0xf0, 0x9f, 0x91, 0xa6, 0xf0, 0x9f, 0x90, 0x97, 0xf0, 0x9f, 0x91, 0xae, 0xf0, 0x9f, 0x91, 0xa6, 0xf0, 0x9f, 0x91, 0xa9, 0xf0, 0x9f, 0x91, 0xa3, 0xf0, 0x9f, 0x91, 0x9b}, encoder.dst)
	})

	t.Run("encode with empty file", func(t *testing.T) {
		file := mock.NewFile([]byte{}, "empty.txt")
		encoder := NewEncoder().FromFile(file).ByBase100()
		assert.Nil(t, encoder.Error)
		assert.Equal(t, []byte{}, encoder.dst)
	})

	t.Run("encode with error file", func(t *testing.T) {
		errorFile := mock.NewErrorFile(errors.New("read error"))
		encoder := NewEncoder().FromFile(errorFile).ByBase100()
		assert.Error(t, encoder.Error)
		assert.Contains(t, encoder.Error.Error(), "read error")
	})

	t.Run("encode with existing error", func(t *testing.T) {
		encoder := NewEncoder()
		encoder.Error = errors.New("existing error")
		result := encoder.FromString("hello world").ByBase100()
		assert.Equal(t, encoder, result)
		assert.Equal(t, "existing error", result.Error.Error())
	})

	t.Run("encode unicode string", func(t *testing.T) {
		encoder := NewEncoder().FromString("你好世界").ByBase100()
		assert.Nil(t, encoder.Error)
		// Base100 encoding of "你好世界" = []byte{0xf0, 0x9f, 0x93, 0x9b, 0xf0, 0x9f, 0x92, 0xb4, 0xf0, 0x9f, 0x92, 0x97, 0xf0, 0x9f, 0x93, 0x9c, 0xf0, 0x9f, 0x92, 0x9c, 0xf0, 0x9f, 0x92, 0xb4, 0xf0, 0x9f, 0x93, 0x9b, 0xf0, 0x9f, 0x92, 0xaf, 0xf0, 0x9f, 0x92, 0x8d, 0xf0, 0x9f, 0x93, 0x9e, 0xf0, 0x9f, 0x92, 0x8c, 0xf0, 0x9f, 0x92, 0x83}
		assert.Equal(t, []byte{0xf0, 0x9f, 0x93, 0x9b, 0xf0, 0x9f, 0x92, 0xb4, 0xf0, 0x9f, 0x92, 0x97, 0xf0, 0x9f, 0x93, 0x9c, 0xf0, 0x9f, 0x92, 0x9c, 0xf0, 0x9f, 0x92, 0xb4, 0xf0, 0x9f, 0x93, 0x9b, 0xf0, 0x9f, 0x92, 0xaf, 0xf0, 0x9f, 0x92, 0x8d, 0xf0, 0x9f, 0x93, 0x9e, 0xf0, 0x9f, 0x92, 0x8c, 0xf0, 0x9f, 0x92, 0x83}, encoder.dst)
	})

	t.Run("encode large data", func(t *testing.T) {
		largeData := strings.Repeat("Hello, World! ", 100)
		encoder := NewEncoder().FromString(largeData).ByBase100()
		assert.Nil(t, encoder.Error)
		// For large data, test round-trip instead of exact value
		decoder := NewDecoder().FromBytes(encoder.dst).ByBase100()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, []byte(largeData), decoder.dst)
	})

	t.Run("encode single byte", func(t *testing.T) {
		encoder := NewEncoder().FromBytes([]byte{0x41}).ByBase100()
		assert.Nil(t, encoder.Error)
		// Base100 encoding of byte 0x41 = []byte{0xf0, 0x9f, 0x90, 0xb8}
		assert.Equal(t, []byte{0xf0, 0x9f, 0x90, 0xb8}, encoder.dst)
	})

	t.Run("encode two bytes", func(t *testing.T) {
		encoder := NewEncoder().FromBytes([]byte{0x41, 0x42}).ByBase100()
		assert.Nil(t, encoder.Error)
		// Base100 encoding of bytes [0x41, 0x42] = []byte{0xf0, 0x9f, 0x90, 0xb8, 0xf0, 0x9f, 0x90, 0xb9}
		assert.Equal(t, []byte{0xf0, 0x9f, 0x90, 0xb8, 0xf0, 0x9f, 0x90, 0xb9}, encoder.dst)
	})

	t.Run("encode three bytes", func(t *testing.T) {
		encoder := NewEncoder().FromBytes([]byte{0x41, 0x42, 0x43}).ByBase100()
		assert.Nil(t, encoder.Error)
		// Base100 encoding of bytes [0x41, 0x42, 0x43] = []byte{0xf0, 0x9f, 0x90, 0xb8, 0xf0, 0x9f, 0x90, 0xb9, 0xf0, 0x9f, 0x90, 0xba}
		assert.Equal(t, []byte{0xf0, 0x9f, 0x90, 0xb8, 0xf0, 0x9f, 0x90, 0xb9, 0xf0, 0x9f, 0x90, 0xba}, encoder.dst)
	})

	t.Run("encode zero bytes", func(t *testing.T) {
		encoder := NewEncoder().FromBytes([]byte{0x00, 0x00, 0x00, 0x00}).ByBase100()
		assert.Nil(t, encoder.Error)
		// Base100 encoding of zero bytes = []byte{0xf0, 0x9f, 0x8f, 0xb7, 0xf0, 0x9f, 0x8f, 0xb7, 0xf0, 0x9f, 0x8f, 0xb7, 0xf0, 0x9f, 0x8f, 0xb7}
		assert.Equal(t, []byte{0xf0, 0x9f, 0x8f, 0xb7, 0xf0, 0x9f, 0x8f, 0xb7, 0xf0, 0x9f, 0x8f, 0xb7, 0xf0, 0x9f, 0x8f, 0xb7}, encoder.dst)
	})

	t.Run("encode max bytes", func(t *testing.T) {
		encoder := NewEncoder().FromBytes([]byte{0xFF, 0xFF, 0xFF, 0xFF}).ByBase100()
		assert.Nil(t, encoder.Error)
		// Base100 encoding of max bytes = []byte{0xf0, 0x9f, 0x93, 0xb6, 0xf0, 0x9f, 0x93, 0xb6, 0xf0, 0x9f, 0x93, 0xb6, 0xf0, 0x9f, 0x93, 0xb6}
		assert.Equal(t, []byte{0xf0, 0x9f, 0x93, 0xb6, 0xf0, 0x9f, 0x93, 0xb6, 0xf0, 0x9f, 0x93, 0xb6, 0xf0, 0x9f, 0x93, 0xb6}, encoder.dst)
	})
}

func TestDecoder_ByBase100(t *testing.T) {
	t.Run("decode string", func(t *testing.T) {
		// First encode some data
		encoder := NewEncoder().FromString("hello world").ByBase100()
		assert.Nil(t, encoder.Error)

		// Then decode it
		decoder := NewDecoder().FromBytes(encoder.dst).ByBase100()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, []byte("hello world"), decoder.dst)
	})

	t.Run("decode empty string", func(t *testing.T) {
		decoder := NewDecoder().FromString("").ByBase100()
		assert.Nil(t, decoder.Error)
		assert.Nil(t, decoder.dst)
	})

	t.Run("decode bytes", func(t *testing.T) {
		// First encode some data
		encoder := NewEncoder().FromBytes([]byte{0x00, 0x01, 0x02, 0x03}).ByBase100()
		assert.Nil(t, encoder.Error)

		// Then decode it
		decoder := NewDecoder().FromBytes(encoder.dst).ByBase100()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, []byte{0x00, 0x01, 0x02, 0x03}, decoder.dst)
	})

	t.Run("decode empty bytes", func(t *testing.T) {
		decoder := NewDecoder().FromBytes([]byte{}).ByBase100()
		assert.Nil(t, decoder.Error)
		assert.Nil(t, decoder.dst)
	})

	t.Run("decode nil bytes", func(t *testing.T) {
		decoder := NewDecoder().FromBytes(nil).ByBase100()
		assert.Nil(t, decoder.Error)
		assert.Nil(t, decoder.dst)
	})

	t.Run("decode with file", func(t *testing.T) {
		// First encode some data
		encoder := NewEncoder().FromString("hello world").ByBase100()
		assert.Nil(t, encoder.Error)

		// Then decode with file
		file := mock.NewFile(encoder.dst, "test.txt")
		decoder := NewDecoder().FromFile(file).ByBase100()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, []byte("hello world"), decoder.dst)
	})

	t.Run("decode with empty file", func(t *testing.T) {
		file := mock.NewFile([]byte{}, "empty.txt")
		decoder := NewDecoder().FromFile(file).ByBase100()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, []byte{}, decoder.dst)
	})

	t.Run("decode with error file", func(t *testing.T) {
		errorFile := mock.NewErrorFile(errors.New("read error"))
		decoder := NewDecoder().FromFile(errorFile).ByBase100()
		assert.Error(t, decoder.Error)
		assert.Contains(t, decoder.Error.Error(), "read error")
	})

	t.Run("decode with existing error", func(t *testing.T) {
		decoder := NewDecoder()
		decoder.Error = errors.New("existing error")
		result := decoder.FromString("test").ByBase100()
		assert.Equal(t, decoder, result)
		assert.Equal(t, "existing error", result.Error.Error())
	})

	t.Run("decode invalid base100", func(t *testing.T) {
		// Create invalid base100 data (not divisible by 4)
		invalidData := []byte{0xf0, 0x9f, 0x90, 0xb8, 0xf0} // 5 bytes, not divisible by 4
		decoder := NewDecoder().FromBytes(invalidData).ByBase100()
		assert.Error(t, decoder.Error)
	})

	t.Run("decode unicode string", func(t *testing.T) {
		// First encode unicode data
		encoder := NewEncoder().FromString("你好世界").ByBase100()
		assert.Nil(t, encoder.Error)

		// Then decode it
		decoder := NewDecoder().FromBytes(encoder.dst).ByBase100()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, []byte("你好世界"), decoder.dst)
	})

	t.Run("decode single byte encoded", func(t *testing.T) {
		// Encode single byte
		encoder := NewEncoder().FromBytes([]byte{0x41}).ByBase100()
		assert.Nil(t, encoder.Error)

		// Decode it
		decoder := NewDecoder().FromBytes(encoder.dst).ByBase100()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, []byte{0x41}, decoder.dst)
	})

	t.Run("decode two bytes encoded", func(t *testing.T) {
		// Encode two bytes
		encoder := NewEncoder().FromBytes([]byte{0x41, 0x42}).ByBase100()
		assert.Nil(t, encoder.Error)

		// Decode it
		decoder := NewDecoder().FromBytes(encoder.dst).ByBase100()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, []byte{0x41, 0x42}, decoder.dst)
	})

	t.Run("decode three bytes encoded", func(t *testing.T) {
		// Encode three bytes
		encoder := NewEncoder().FromBytes([]byte{0x41, 0x42, 0x43}).ByBase100()
		assert.Nil(t, encoder.Error)

		// Decode it
		decoder := NewDecoder().FromBytes(encoder.dst).ByBase100()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, []byte{0x41, 0x42, 0x43}, decoder.dst)
	})

	t.Run("decode zero bytes encoded", func(t *testing.T) {
		// Encode zero bytes
		encoder := NewEncoder().FromBytes([]byte{0x00, 0x00, 0x00, 0x00}).ByBase100()
		assert.Nil(t, encoder.Error)

		// Decode it
		decoder := NewDecoder().FromBytes(encoder.dst).ByBase100()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, []byte{0x00, 0x00, 0x00, 0x00}, decoder.dst)
	})

	t.Run("decode max bytes encoded", func(t *testing.T) {
		// Encode max bytes
		encoder := NewEncoder().FromBytes([]byte{0xFF, 0xFF, 0xFF, 0xFF}).ByBase100()
		assert.Nil(t, encoder.Error)

		// Decode it
		decoder := NewDecoder().FromBytes(encoder.dst).ByBase100()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, []byte{0xFF, 0xFF, 0xFF, 0xFF}, decoder.dst)
	})
}

func TestError_ByBase100(t *testing.T) {
	t.Run("encoder error propagation", func(t *testing.T) {
		encoder := NewEncoder()
		encoder.Error = errors.New("test error")

		result := encoder.ByBase100()
		assert.Equal(t, encoder, result)
		assert.Equal(t, "test error", result.Error.Error())
	})

	t.Run("decoder error propagation", func(t *testing.T) {
		decoder := NewDecoder()
		decoder.Error = errors.New("test error")

		result := decoder.ByBase100()
		assert.Equal(t, decoder, result)
		assert.Equal(t, "test error", result.Error.Error())
	})

	t.Run("decoder with error file", func(t *testing.T) {
		errorFile := mock.NewErrorFile(errors.New("read error"))
		decoder := NewDecoder().FromFile(errorFile).ByBase100()
		assert.Error(t, decoder.Error)
		assert.Contains(t, decoder.Error.Error(), "read error")
	})

	t.Run("encoder with error file", func(t *testing.T) {
		errorFile := mock.NewErrorFile(errors.New("read error"))
		encoder := NewEncoder().FromFile(errorFile).ByBase100()
		assert.Error(t, encoder.Error)
		assert.Contains(t, encoder.Error.Error(), "read error")
	})

	t.Run("decoder invalid length", func(t *testing.T) {
		// Create data with invalid length (not divisible by 4)
		invalidData := []byte{0xf0, 0x9f, 0x90, 0xb8, 0xf0} // 5 bytes, not divisible by 4
		decoder := NewDecoder().FromBytes(invalidData).ByBase100()
		assert.Error(t, decoder.Error)
	})

	t.Run("decoder corrupt data", func(t *testing.T) {
		// Create corrupt base100 data with wrong first two bytes
		corruptData := []byte{0xf1, 0x9f, 0x90, 0xb8} // Wrong first byte
		decoder := NewDecoder().FromBytes(corruptData).ByBase100()
		assert.Error(t, decoder.Error)
	})

	t.Run("decoder invalid second byte", func(t *testing.T) {
		// Create invalid data with wrong second byte
		invalidData := []byte{0xf0, 0x9e, 0x90, 0xb8} // Wrong second byte
		decoder := NewDecoder().FromBytes(invalidData).ByBase100()
		assert.Error(t, decoder.Error)
	})

	t.Run("base100 emoji verification", func(t *testing.T) {
		// Test that base100 encoding produces emoji sequences
		testData := []byte{0x41, 0x42, 0x43} // 'ABC'
		encoder := NewEncoder().FromBytes(testData).ByBase100()
		assert.Nil(t, encoder.Error)

		// Base100 should produce 4-byte sequences starting with 0xf0, 0x9f
		result := encoder.dst
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
		assert.Equal(t, len(testData)*4, len(encoder.dst))
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
		assert.Equal(t, expected, encoder.dst)
	})
}
