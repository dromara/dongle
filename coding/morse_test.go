package coding

import (
	"errors"
	"strings"
	"testing"

	"github.com/dromara/dongle/mock"
	"github.com/stretchr/testify/assert"
)

func TestEncoder_ByMorse(t *testing.T) {
	t.Run("encode string", func(t *testing.T) {
		encoder := NewEncoder().FromString("hello").ByMorse()
		assert.Nil(t, encoder.Error)
		// Morse encoding of "hello" = ".... . .-.. .-.. ---"
		assert.Equal(t, []byte(".... . .-.. .-.. ---"), encoder.dst)
	})

	t.Run("encode empty string", func(t *testing.T) {
		encoder := NewEncoder().FromString("").ByMorse()
		assert.Nil(t, encoder.Error)
		assert.Nil(t, encoder.dst)
	})

	t.Run("encode bytes", func(t *testing.T) {
		encoder := NewEncoder().FromBytes([]byte("abc")).ByMorse()
		assert.Nil(t, encoder.Error)
		// Morse encoding of "abc" = ".- -... -.-."
		assert.Equal(t, []byte(".- -... -.-."), encoder.dst)
	})

	t.Run("encode empty bytes", func(t *testing.T) {
		encoder := NewEncoder().FromBytes([]byte{}).ByMorse()
		assert.Nil(t, encoder.Error)
		assert.Nil(t, encoder.dst)
	})

	t.Run("encode nil bytes", func(t *testing.T) {
		encoder := NewEncoder().FromBytes(nil).ByMorse()
		assert.Nil(t, encoder.Error)
		assert.Nil(t, encoder.dst)
	})

	t.Run("encode with file", func(t *testing.T) {
		file := mock.NewFile([]byte("hello"), "test.txt")
		encoder := NewEncoder().FromFile(file).ByMorse()
		assert.Nil(t, encoder.Error)
		// Morse encoding of "hello" = ".... . .-.. .-.. ---"
		assert.Equal(t, []byte(".... . .-.. .-.. ---"), encoder.dst)
	})

	t.Run("encode with empty file", func(t *testing.T) {
		file := mock.NewFile([]byte{}, "empty.txt")
		encoder := NewEncoder().FromFile(file).ByMorse()
		assert.Nil(t, encoder.Error)
		assert.Equal(t, []byte{}, encoder.dst)
	})

	t.Run("encode with error file", func(t *testing.T) {
		errorFile := mock.NewErrorFile(errors.New("read error"))
		encoder := NewEncoder().FromFile(errorFile).ByMorse()
		assert.Error(t, encoder.Error)
		assert.Contains(t, encoder.Error.Error(), "read error")
	})

	t.Run("encode with existing error", func(t *testing.T) {
		encoder := NewEncoder()
		encoder.Error = errors.New("existing error")
		result := encoder.FromString("hello").ByMorse()
		assert.Equal(t, encoder, result)
		assert.Equal(t, errors.New("existing error"), result.Error)
	})

	t.Run("encode numbers", func(t *testing.T) {
		encoder := NewEncoder().FromString("123").ByMorse()
		assert.Nil(t, encoder.Error)
		// Morse encoding of "123" = ".---- ..--- ...--"
		assert.Equal(t, []byte(".---- ..--- ...--"), encoder.dst)
	})

	t.Run("encode punctuation", func(t *testing.T) {
		encoder := NewEncoder().FromString("!?").ByMorse()
		assert.Nil(t, encoder.Error)
		// Morse encoding of "!?" = "-.-.-- ..--.."
		assert.Equal(t, []byte("-.-.-- ..--.."), encoder.dst)
	})

	t.Run("encode mixed characters", func(t *testing.T) {
		encoder := NewEncoder().FromString("a1!").ByMorse()
		assert.Nil(t, encoder.Error)
		// Morse encoding of "a1!" = ".- .---- -.-.--"
		assert.Equal(t, []byte(".- .---- -.-.--"), encoder.dst)
	})

	t.Run("encode large data", func(t *testing.T) {
		largeData := strings.Repeat("hello", 100)
		encoder := NewEncoder().FromString(largeData).ByMorse()
		assert.Nil(t, encoder.Error)
		// For large data, test round-trip instead of exact value
		decoder := NewDecoder().FromBytes(encoder.dst).ByMorse()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, []byte(largeData), decoder.dst)
	})

	t.Run("encode all letters", func(t *testing.T) {
		encoder := NewEncoder().FromString("abcdefghijklmnopqrstuvwxyz").ByMorse()
		assert.Nil(t, encoder.Error)
		expected := ".- -... -.-. -.. . ..-. --. .... .. .--- -.- .-.. -- -. --- .--. --.- .-. ... - ..- ...- .-- -..- -.-- --.."
		assert.Equal(t, []byte(expected), encoder.dst)
	})

	t.Run("encode all numbers", func(t *testing.T) {
		encoder := NewEncoder().FromString("0123456789").ByMorse()
		assert.Nil(t, encoder.Error)
		expected := "----- .---- ..--- ...-- ....- ..... -.... --... ---.. ----."
		assert.Equal(t, []byte(expected), encoder.dst)
	})

}

func TestDecoder_ByMorse(t *testing.T) {
	t.Run("decode string", func(t *testing.T) {
		// First encode some data
		encoder := NewEncoder().FromString("hello").ByMorse()
		assert.Nil(t, encoder.Error)

		// Then decode it
		decoder := NewDecoder().FromBytes(encoder.dst).ByMorse()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, []byte("hello"), decoder.dst)
	})

	t.Run("decode empty string", func(t *testing.T) {
		decoder := NewDecoder().FromString("").ByMorse()
		assert.Nil(t, decoder.Error)
		assert.Nil(t, decoder.dst)
	})

	t.Run("decode bytes", func(t *testing.T) {
		// First encode some data
		encoder := NewEncoder().FromBytes([]byte("abc")).ByMorse()
		assert.Nil(t, encoder.Error)

		// Then decode it
		decoder := NewDecoder().FromBytes(encoder.dst).ByMorse()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, []byte("abc"), decoder.dst)
	})

	t.Run("decode empty bytes", func(t *testing.T) {
		decoder := NewDecoder().FromBytes([]byte{}).ByMorse()
		assert.Nil(t, decoder.Error)
		assert.Nil(t, decoder.dst)
	})

	t.Run("decode nil bytes", func(t *testing.T) {
		decoder := NewDecoder().FromBytes(nil).ByMorse()
		assert.Nil(t, decoder.Error)
		assert.Nil(t, decoder.dst)
	})

	t.Run("decode with file", func(t *testing.T) {
		// First encode some data
		encoder := NewEncoder().FromString("hello").ByMorse()
		assert.Nil(t, encoder.Error)

		// Then decode with file
		file := mock.NewFile(encoder.dst, "test.txt")
		decoder := NewDecoder().FromFile(file).ByMorse()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, []byte("hello"), decoder.dst)
	})

	t.Run("decode with empty file", func(t *testing.T) {
		file := mock.NewFile([]byte{}, "empty.txt")
		decoder := NewDecoder().FromFile(file).ByMorse()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, []byte{}, decoder.dst)
	})

	t.Run("decode with error file", func(t *testing.T) {
		errorFile := mock.NewErrorFile(errors.New("read error"))
		decoder := NewDecoder().FromFile(errorFile).ByMorse()
		assert.Error(t, decoder.Error)
		assert.Contains(t, decoder.Error.Error(), "read error")
	})

	t.Run("decode with existing error", func(t *testing.T) {
		decoder := NewDecoder()
		decoder.Error = errors.New("existing error")
		result := decoder.FromString("test").ByMorse()
		assert.Equal(t, decoder, result)
		assert.Equal(t, errors.New("existing error"), result.Error)
	})

	t.Run("decode invalid morse", func(t *testing.T) {
		decoder := NewDecoder().FromString("invalid morse").ByMorse()
		assert.Error(t, decoder.Error)
		assert.Contains(t, decoder.Error.Error(), "unsupported character")
	})

	t.Run("decode numbers", func(t *testing.T) {
		// First encode numbers
		encoder := NewEncoder().FromString("123").ByMorse()
		assert.Nil(t, encoder.Error)

		// Then decode it
		decoder := NewDecoder().FromBytes(encoder.dst).ByMorse()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, []byte("123"), decoder.dst)
	})

	t.Run("decode punctuation", func(t *testing.T) {
		// First encode punctuation
		encoder := NewEncoder().FromString("!?").ByMorse()
		assert.Nil(t, encoder.Error)

		// Then decode it
		decoder := NewDecoder().FromBytes(encoder.dst).ByMorse()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, []byte("!?"), decoder.dst)
	})

	t.Run("decode mixed characters", func(t *testing.T) {
		// First encode mixed characters
		encoder := NewEncoder().FromString("a1!").ByMorse()
		assert.Nil(t, encoder.Error)

		// Then decode it
		decoder := NewDecoder().FromBytes(encoder.dst).ByMorse()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, []byte("a1!"), decoder.dst)
	})

	t.Run("decode all letters", func(t *testing.T) {
		// First encode all letters
		encoder := NewEncoder().FromString("abcdefghijklmnopqrstuvwxyz").ByMorse()
		assert.Nil(t, encoder.Error)

		// Then decode it
		decoder := NewDecoder().FromBytes(encoder.dst).ByMorse()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, []byte("abcdefghijklmnopqrstuvwxyz"), decoder.dst)
	})

	t.Run("decode all numbers", func(t *testing.T) {
		// First encode all numbers
		encoder := NewEncoder().FromString("0123456789").ByMorse()
		assert.Nil(t, encoder.Error)

		// Then decode it
		decoder := NewDecoder().FromBytes(encoder.dst).ByMorse()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, []byte("0123456789"), decoder.dst)
	})

	t.Run("decode with unknown character", func(t *testing.T) {
		decoder := NewDecoder().FromString(".... invalid .-..").ByMorse()
		assert.Error(t, decoder.Error)
		assert.Contains(t, decoder.Error.Error(), "unsupported character")
	})

	t.Run("decode with invalid morse code", func(t *testing.T) {
		decoder := NewDecoder().FromString(".... . .-.. .-.. --- invalid").ByMorse()
		assert.Error(t, decoder.Error)
		assert.Contains(t, decoder.Error.Error(), "unsupported character")
	})

}

func TestError_ByMorse(t *testing.T) {
	t.Run("encoder error propagation", func(t *testing.T) {
		encoder := NewEncoder()
		encoder.Error = errors.New("test error")

		result := encoder.ByMorse()
		assert.Equal(t, encoder, result)
		assert.Equal(t, "test error", result.Error.Error())
	})

	t.Run("decoder error propagation", func(t *testing.T) {
		decoder := NewDecoder()
		decoder.Error = errors.New("test error")

		result := decoder.ByMorse()
		assert.Equal(t, decoder, result)
		assert.Equal(t, "test error", result.Error.Error())
	})

	t.Run("encoder space error", func(t *testing.T) {
		encoder := NewEncoder().FromString("hello world").ByMorse()
		assert.Nil(t, encoder.Error)
		// Spaces are now supported in morse encoding, encoded as "/"
		assert.Contains(t, string(encoder.dst), "/")
	})

	t.Run("decoder invalid character", func(t *testing.T) {
		// Create data with invalid morse characters
		invalidData := []byte(".... invalid .-..") // 'invalid' is not a valid morse code
		decoder := NewDecoder().FromBytes(invalidData).ByMorse()
		assert.Error(t, decoder.Error)
		assert.Contains(t, decoder.Error.Error(), "unsupported character")
	})

	t.Run("decoder with error file", func(t *testing.T) {
		errorFile := mock.NewErrorFile(errors.New("read error"))
		decoder := NewDecoder().FromFile(errorFile).ByMorse()
		assert.Error(t, decoder.Error)
		assert.Contains(t, decoder.Error.Error(), "read error")
	})

	t.Run("encoder with error file", func(t *testing.T) {
		errorFile := mock.NewErrorFile(errors.New("read error"))
		encoder := NewEncoder().FromFile(errorFile).ByMorse()
		assert.Error(t, encoder.Error)
		assert.Contains(t, encoder.Error.Error(), "read error")
	})

	t.Run("round trip test", func(t *testing.T) {
		original := "hello world"
		// Remove spaces for morse encoding
		cleanOriginal := strings.ReplaceAll(original, " ", "")

		encoder := NewEncoder().FromString(cleanOriginal).ByMorse()
		assert.Nil(t, encoder.Error)

		decoder := NewDecoder().FromBytes(encoder.dst).ByMorse()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, []byte(cleanOriginal), decoder.dst)
	})

	t.Run("round trip with special characters", func(t *testing.T) {
		original := "hello123!?"

		encoder := NewEncoder().FromString(original).ByMorse()
		assert.Nil(t, encoder.Error)

		decoder := NewDecoder().FromBytes(encoder.dst).ByMorse()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, []byte(original), decoder.dst)
	})

	t.Run("encode with unsupported character", func(t *testing.T) {
		encoder := NewEncoder().FromString("hello\u00FF").ByMorse()
		assert.Error(t, encoder.Error)
		assert.Contains(t, encoder.Error.Error(), "invalid input")
	})

	t.Run("encode with encoder error propagation", func(t *testing.T) {
		encoder := NewEncoder().FromString("hello").ByMorse()
		assert.Nil(t, encoder.Error)

		// Simulate encoder error by encoding unsupported character
		encoder2 := NewEncoder().FromString("hello\u00FF").ByMorse()
		assert.Error(t, encoder2.Error)
		assert.Contains(t, encoder2.Error.Error(), "invalid input")
	})

	t.Run("streaming encoder with valid data", func(t *testing.T) {
		encoder := NewEncoder()
		encoder.reader = strings.NewReader("hello")
		result := encoder.ByMorse()
		assert.Nil(t, result.Error)
		assert.NotNil(t, result.dst)
	})

	t.Run("streaming decoder with valid data", func(t *testing.T) {
		// First encode some data
		encoder := NewEncoder().FromString("hello").ByMorse()
		assert.Nil(t, encoder.Error)

		// Create a reader with encoded data
		reader := strings.NewReader(string(encoder.dst))
		decoder := NewDecoder()
		decoder.reader = reader
		result := decoder.ByMorse()
		assert.Nil(t, result.Error)
		assert.Equal(t, []byte("hello"), result.dst)
	})
}
