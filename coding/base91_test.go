package coding

import (
	"errors"
	"strings"
	"testing"

	"github.com/dromara/dongle/mock"
	"github.com/stretchr/testify/assert"
)

func TestEncoder_ByBase91(t *testing.T) {
	t.Run("encode string", func(t *testing.T) {
		encoder := NewEncoder().FromString("hello world").ByBase91()
		assert.Nil(t, encoder.Error)
		// Base91 encoding of "hello world" = "TPwJh>Io2Tv!lE"
		assert.Equal(t, []byte("TPwJh>Io2Tv!lE"), encoder.dst)
	})

	t.Run("encode empty string", func(t *testing.T) {
		encoder := NewEncoder().FromString("").ByBase91()
		assert.Nil(t, encoder.Error)
		assert.Nil(t, encoder.dst)
	})

	t.Run("encode bytes", func(t *testing.T) {
		encoder := NewEncoder().FromBytes([]byte{0x00, 0x01, 0x02, 0x03}).ByBase91()
		assert.Nil(t, encoder.Error)
		// Base91 encoding of [0x00, 0x01, 0x02, 0x03] = ":C#(A"
		assert.Equal(t, []byte(":C#(A"), encoder.dst)
	})

	t.Run("encode empty bytes", func(t *testing.T) {
		encoder := NewEncoder().FromBytes([]byte{}).ByBase91()
		assert.Nil(t, encoder.Error)
		assert.Nil(t, encoder.dst)
	})

	t.Run("encode nil bytes", func(t *testing.T) {
		encoder := NewEncoder().FromBytes(nil).ByBase91()
		assert.Nil(t, encoder.Error)
		assert.Nil(t, encoder.dst)
	})

	t.Run("encode with file", func(t *testing.T) {
		file := mock.NewFile([]byte("hello world"), "test.txt")
		encoder := NewEncoder().FromFile(file).ByBase91()
		assert.Nil(t, encoder.Error)
		// Base91 encoding of "hello world" = "TPwJh>Io2Tv!lE"
		assert.Equal(t, []byte("TPwJh>Io2Tv!lE"), encoder.dst)
	})

	t.Run("encode with empty file", func(t *testing.T) {
		file := mock.NewFile([]byte{}, "empty.txt")
		encoder := NewEncoder().FromFile(file).ByBase91()
		assert.Nil(t, encoder.Error)
		assert.Equal(t, []byte{}, encoder.dst)
	})

	t.Run("encode with error file", func(t *testing.T) {
		errorFile := mock.NewErrorFile(errors.New("read error"))
		encoder := NewEncoder().FromFile(errorFile).ByBase91()
		assert.Error(t, encoder.Error)
		assert.Contains(t, encoder.Error.Error(), "read error")
	})

	t.Run("encode with existing error", func(t *testing.T) {
		encoder := NewEncoder()
		encoder.Error = errors.New("existing error")
		result := encoder.FromString("hello world").ByBase91()
		assert.Equal(t, encoder, result)
		assert.Equal(t, "existing error", result.Error.Error())
	})

	t.Run("encode unicode string", func(t *testing.T) {
		encoder := NewEncoder().FromString("你好世界").ByBase91()
		assert.Nil(t, encoder.Error)
		// Base91 encoding of "你好世界" = "I_5k7a9aug!32zR"
		assert.Equal(t, []byte("I_5k7a9aug!32zR"), encoder.dst)
	})

	t.Run("encode large data", func(t *testing.T) {
		largeData := strings.Repeat("Hello, World! ", 100)
		encoder := NewEncoder().FromString(largeData).ByBase91()
		assert.Nil(t, encoder.Error)
		// For large data, test round-trip instead of exact value
		decoder := NewDecoder().FromBytes(encoder.dst).ByBase91()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, []byte(largeData), decoder.dst)
	})

	t.Run("encode single byte", func(t *testing.T) {
		encoder := NewEncoder().FromBytes([]byte{0x41}).ByBase91()
		assert.Nil(t, encoder.Error)
		// Base91 encoding of byte 0x41 = "%A"
		assert.Equal(t, []byte("%A"), encoder.dst)
	})

	t.Run("encode two bytes", func(t *testing.T) {
		encoder := NewEncoder().FromBytes([]byte{0x41, 0x42}).ByBase91()
		assert.Nil(t, encoder.Error)
		// Base91 encoding of bytes [0x41, 0x42] = "fGC"
		assert.Equal(t, []byte("fGC"), encoder.dst)
	})

	t.Run("encode three bytes", func(t *testing.T) {
		encoder := NewEncoder().FromBytes([]byte{0x41, 0x42, 0x43}).ByBase91()
		assert.Nil(t, encoder.Error)
		// Base91 encoding of bytes [0x41, 0x42, 0x43] = "fG^F"
		assert.Equal(t, []byte("fG^F"), encoder.dst)
	})

	t.Run("encode zero bytes", func(t *testing.T) {
		encoder := NewEncoder().FromBytes([]byte{0x00, 0x00, 0x00, 0x00}).ByBase91()
		assert.Nil(t, encoder.Error)
		// Base91 encoding of zero bytes = "AAAAA"
		assert.Equal(t, []byte("AAAAA"), encoder.dst)
	})

	t.Run("encode max bytes", func(t *testing.T) {
		encoder := NewEncoder().FromBytes([]byte{0xFF, 0xFF, 0xFF, 0xFF}).ByBase91()
		assert.Nil(t, encoder.Error)
		// Base91 encoding of max bytes = "B\"B\"#"
		assert.Equal(t, []byte("B\"B\"#"), encoder.dst)
	})
}

func TestDecoder_ByBase91(t *testing.T) {
	t.Run("decode string", func(t *testing.T) {
		// First encode some data
		encoder := NewEncoder().FromString("hello world").ByBase91()
		assert.Nil(t, encoder.Error)

		// Then decode it
		decoder := NewDecoder().FromBytes(encoder.dst).ByBase91()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, []byte("hello world"), decoder.dst)
	})

	t.Run("decode empty string", func(t *testing.T) {
		decoder := NewDecoder().FromString("").ByBase91()
		assert.Nil(t, decoder.Error)
		assert.Nil(t, decoder.dst)
	})

	t.Run("decode bytes", func(t *testing.T) {
		// First encode some data
		encoder := NewEncoder().FromBytes([]byte{0x00, 0x01, 0x02, 0x03}).ByBase91()
		assert.Nil(t, encoder.Error)

		// Then decode it
		decoder := NewDecoder().FromBytes(encoder.dst).ByBase91()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, []byte{0x00, 0x01, 0x02, 0x03}, decoder.dst)
	})

	t.Run("decode empty bytes", func(t *testing.T) {
		decoder := NewDecoder().FromBytes([]byte{}).ByBase91()
		assert.Nil(t, decoder.Error)
		assert.Nil(t, decoder.dst)
	})

	t.Run("decode nil bytes", func(t *testing.T) {
		decoder := NewDecoder().FromBytes(nil).ByBase91()
		assert.Nil(t, decoder.Error)
		assert.Nil(t, decoder.dst)
	})

	t.Run("decode with file", func(t *testing.T) {
		// First encode some data
		encoder := NewEncoder().FromString("hello world").ByBase91()
		assert.Nil(t, encoder.Error)

		// Then decode with file
		file := mock.NewFile(encoder.dst, "test.txt")
		decoder := NewDecoder().FromFile(file).ByBase91()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, []byte("hello world"), decoder.dst)
	})

	t.Run("decode with empty file", func(t *testing.T) {
		file := mock.NewFile([]byte{}, "empty.txt")
		decoder := NewDecoder().FromFile(file).ByBase91()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, []byte{}, decoder.dst)
	})

	t.Run("decode with error file", func(t *testing.T) {
		errorFile := mock.NewErrorFile(errors.New("read error"))
		decoder := NewDecoder().FromFile(errorFile).ByBase91()
		assert.Error(t, decoder.Error)
		assert.Contains(t, decoder.Error.Error(), "read error")
	})

	t.Run("decode with existing error", func(t *testing.T) {
		decoder := NewDecoder()
		decoder.Error = errors.New("existing error")
		result := decoder.FromString("TPwJh>Io2Tv!lE").ByBase91()
		assert.Equal(t, decoder, result)
		assert.Equal(t, "existing error", result.Error.Error())
	})

	t.Run("decode invalid base91", func(t *testing.T) {
		decoder := NewDecoder().FromString("invalid!").ByBase91()
		// Base91 decoder returns decoded result for invalid characters, not error
		assert.Nil(t, decoder.Error)
		assert.NotNil(t, decoder.dst)
		// Verify it returns some decoded bytes
		assert.Equal(t, []byte{255, 173, 45, 237, 176, 19}, decoder.dst)
	})

	t.Run("decode unicode string", func(t *testing.T) {
		// First encode unicode data
		encoder := NewEncoder().FromString("你好世界").ByBase91()
		assert.Nil(t, encoder.Error)

		// Then decode it
		decoder := NewDecoder().FromBytes(encoder.dst).ByBase91()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, []byte("你好世界"), decoder.dst)
	})

	t.Run("decode single byte encoded", func(t *testing.T) {
		// Encode single byte
		encoder := NewEncoder().FromBytes([]byte{0x41}).ByBase91()
		assert.Nil(t, encoder.Error)

		// Decode it
		decoder := NewDecoder().FromBytes(encoder.dst).ByBase91()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, []byte{0x41}, decoder.dst)
	})

	t.Run("decode two bytes encoded", func(t *testing.T) {
		// Encode two bytes
		encoder := NewEncoder().FromBytes([]byte{0x41, 0x42}).ByBase91()
		assert.Nil(t, encoder.Error)

		// Decode it
		decoder := NewDecoder().FromBytes(encoder.dst).ByBase91()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, []byte{0x41, 0x42}, decoder.dst)
	})

	t.Run("decode three bytes encoded", func(t *testing.T) {
		// Encode three bytes
		encoder := NewEncoder().FromBytes([]byte{0x41, 0x42, 0x43}).ByBase91()
		assert.Nil(t, encoder.Error)

		// Decode it
		decoder := NewDecoder().FromBytes(encoder.dst).ByBase91()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, []byte{0x41, 0x42, 0x43}, decoder.dst)
	})

	t.Run("decode zero bytes encoded", func(t *testing.T) {
		// Encode zero bytes
		encoder := NewEncoder().FromBytes([]byte{0x00, 0x00, 0x00, 0x00}).ByBase91()
		assert.Nil(t, encoder.Error)

		// Decode it
		decoder := NewDecoder().FromBytes(encoder.dst).ByBase91()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, []byte{0x00, 0x00, 0x00, 0x00}, decoder.dst)
	})

	t.Run("decode max bytes encoded", func(t *testing.T) {
		// Encode max bytes
		encoder := NewEncoder().FromBytes([]byte{0xFF, 0xFF, 0xFF, 0xFF}).ByBase91()
		assert.Nil(t, encoder.Error)

		// Decode it
		decoder := NewDecoder().FromBytes(encoder.dst).ByBase91()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, []byte{0xFF, 0xFF, 0xFF, 0xFF}, decoder.dst)
	})
}

func TestError_ByBase91(t *testing.T) {
	t.Run("encoder error propagation", func(t *testing.T) {
		encoder := NewEncoder()
		encoder.Error = errors.New("test error")

		result := encoder.ByBase91()
		assert.Equal(t, encoder, result)
		assert.Equal(t, "test error", result.Error.Error())
	})

	t.Run("decoder error propagation", func(t *testing.T) {
		decoder := NewDecoder()
		decoder.Error = errors.New("test error")

		result := decoder.ByBase91()
		assert.Equal(t, decoder, result)
		assert.Equal(t, "test error", result.Error.Error())
	})

	t.Run("decoder with error file", func(t *testing.T) {
		errorFile := mock.NewErrorFile(errors.New("read error"))
		decoder := NewDecoder().FromFile(errorFile).ByBase91()
		assert.Error(t, decoder.Error)
		assert.Contains(t, decoder.Error.Error(), "read error")
	})

	t.Run("encoder with error file", func(t *testing.T) {
		errorFile := mock.NewErrorFile(errors.New("read error"))
		encoder := NewEncoder().FromFile(errorFile).ByBase91()
		assert.Error(t, encoder.Error)
		assert.Contains(t, encoder.Error.Error(), "read error")
	})

	t.Run("decoder with invalid data handling", func(t *testing.T) {
		// Base91 decoder processes all input and doesn't throw errors for invalid characters
		// It tries to decode whatever it can
		invalidData := []byte("invalid!")
		decoder := NewDecoder().FromBytes(invalidData).ByBase91()
		assert.Nil(t, decoder.Error)
		assert.NotNil(t, decoder.dst)
		// Base91 decodes the input and produces output
		assert.Equal(t, []byte{255, 173, 45, 237, 176, 19}, decoder.dst)
	})

	t.Run("decoder alphabet verification", func(t *testing.T) {
		// Test that base91 encoding uses the correct alphabet
		testData := []byte{0x00, 0x01, 0x02}
		encoder := NewEncoder().FromBytes(testData).ByBase91()
		assert.Nil(t, encoder.Error)

		// Base91 alphabet verification
		resultStr := string(encoder.dst)
		base91Alphabet := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!#$%&()*+,./:;<=>?@[]^_`{|}~\""
		for _, char := range resultStr {
			assert.Contains(t, base91Alphabet, string(char))
		}
	})
}
