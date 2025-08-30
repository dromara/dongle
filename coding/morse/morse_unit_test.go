package morse

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/dromara/dongle/mock"
	"github.com/stretchr/testify/assert"
)

func TestStdEncoder_Encode(t *testing.T) {
	t.Run("encode empty input", func(t *testing.T) {
		encoder := NewStdEncoder()
		result := encoder.Encode([]byte{})
		assert.Nil(t, result)
		assert.Nil(t, encoder.Error)
	})

	t.Run("encode simple string", func(t *testing.T) {
		encoder := NewStdEncoder()
		result := encoder.Encode([]byte("hello"))
		assert.Equal(t, []byte(".... . .-.. .-.. ---"), result)
		assert.Nil(t, encoder.Error)
	})

	t.Run("encode with different character types", func(t *testing.T) {
		encoder := NewStdEncoder()

		// Test letters
		result := encoder.Encode([]byte("abc"))
		assert.Equal(t, []byte(".- -... -.-."), result)
		assert.Nil(t, encoder.Error)

		// Test numbers
		result = encoder.Encode([]byte("123"))
		assert.Equal(t, []byte(".---- ..--- ...--"), result)
		assert.Nil(t, encoder.Error)

		// Test punctuation
		result = encoder.Encode([]byte("!?"))
		assert.Equal(t, []byte("-.-.-- ..--.."), result)
		assert.Nil(t, encoder.Error)

		// Test mixed
		result = encoder.Encode([]byte("a1!"))
		assert.Equal(t, []byte(".- .---- -.-.--"), result)
		assert.Nil(t, encoder.Error)
	})

	t.Run("encode all letters", func(t *testing.T) {
		encoder := NewStdEncoder()
		result := encoder.Encode([]byte("abcdefghijklmnopqrstuvwxyz"))
		expected := ".- -... -.-. -.. . ..-. --. .... .. .--- -.- .-.. -- -. --- .--. --.- .-. ... - ..- ...- .-- -..- -.-- --.."
		assert.Equal(t, []byte(expected), result)
		assert.Nil(t, encoder.Error)
	})

	t.Run("encode all numbers", func(t *testing.T) {
		encoder := NewStdEncoder()
		result := encoder.Encode([]byte("0123456789"))
		expected := "----- .---- ..--- ...-- ....- ..... -.... --... ---.. ----."
		assert.Equal(t, []byte(expected), result)
		assert.Nil(t, encoder.Error)
	})

	t.Run("encode with space error", func(t *testing.T) {
		encoder := NewStdEncoder()
		result := encoder.Encode([]byte("hello world"))
		assert.Nil(t, result)
		assert.NotNil(t, encoder.Error)
		assert.Contains(t, encoder.Error.Error(), "input cannot contain spaces")
	})

	t.Run("encode large data", func(t *testing.T) {
		encoder := NewStdEncoder()
		largeData := strings.Repeat("hello", 100)
		result := encoder.Encode([]byte(largeData))
		assert.NotNil(t, result)
		assert.Nil(t, encoder.Error)
		// Verify round-trip
		decoder := NewStdDecoder()
		decoded, err := decoder.Decode(result)
		assert.Nil(t, err)
		assert.Equal(t, []byte(largeData), decoded)
	})

	t.Run("encode with unknown characters", func(t *testing.T) {
		encoder := NewStdEncoder()
		original := []byte("hello@world")
		encoded := encoder.Encode(original)
		// Should encode known characters and skip unknown ones
		assert.Equal(t, []byte(".... . .-.. .-.. --- .-- --- .-. .-.. -.."), encoded)
		assert.Nil(t, encoder.Error)
	})

	t.Run("encode with all unknown characters", func(t *testing.T) {
		encoder := NewStdEncoder()
		original := []byte("@#$%^&*()")
		encoded := encoder.Encode(original)
		// Should return empty result when all characters are unknown
		assert.Equal(t, []byte{}, encoded)
		assert.Nil(t, encoder.Error)
	})

	t.Run("encode with existing error", func(t *testing.T) {
		encoder := &StdEncoder{Error: errors.New("test error")}
		result := encoder.Encode([]byte("hello"))
		assert.Nil(t, result)
		assert.Equal(t, "test error", encoder.Error.Error())
	})

	t.Run("encode with punctuation marks", func(t *testing.T) {
		encoder := NewStdEncoder()

		// Test all supported punctuation
		result := encoder.Encode([]byte("."))
		assert.Equal(t, []byte(".-.-.-"), result)
		assert.Nil(t, encoder.Error)

		result = encoder.Encode([]byte(","))
		assert.Equal(t, []byte("--..--"), result)
		assert.Nil(t, encoder.Error)

		result = encoder.Encode([]byte("="))
		assert.Equal(t, []byte("-...-"), result)
		assert.Nil(t, encoder.Error)

		result = encoder.Encode([]byte("+"))
		assert.Equal(t, []byte(".-.-."), result)
		assert.Nil(t, encoder.Error)

		result = encoder.Encode([]byte("-"))
		assert.Equal(t, []byte("-....-"), result)
		assert.Nil(t, encoder.Error)

		result = encoder.Encode([]byte("/"))
		assert.Equal(t, []byte("-..-."), result)
		assert.Nil(t, encoder.Error)
	})
}

func TestStdDecoder_Decode(t *testing.T) {
	t.Run("decode empty input", func(t *testing.T) {
		decoder := NewStdDecoder()
		result, err := decoder.Decode([]byte{})
		assert.Nil(t, err)
		assert.Nil(t, result)
	})

	t.Run("decode simple string", func(t *testing.T) {
		decoder := NewStdDecoder()
		encoded := []byte(".... . .-.. .-.. ---")
		decoded, err := decoder.Decode(encoded)
		assert.Nil(t, err)
		assert.Equal(t, []byte("hello"), decoded)
	})

	t.Run("decode with different character types", func(t *testing.T) {
		decoder := NewStdDecoder()

		// Test letters
		encoded := []byte(".- -... -.-.")
		decoded, err := decoder.Decode(encoded)
		assert.Nil(t, err)
		assert.Equal(t, []byte("abc"), decoded)

		// Test numbers
		encoded = []byte(".---- ..--- ...--")
		decoded, err = decoder.Decode(encoded)
		assert.Nil(t, err)
		assert.Equal(t, []byte("123"), decoded)

		// Test punctuation
		encoded = []byte("-.-.-- ..--..")
		decoded, err = decoder.Decode(encoded)
		assert.Nil(t, err)
		assert.Equal(t, []byte("!?"), decoded)

		// Test mixed
		encoded = []byte(".- .---- -.-.--")
		decoded, err = decoder.Decode(encoded)
		assert.Nil(t, err)
		assert.Equal(t, []byte("a1!"), decoded)
	})

	t.Run("decode all letters", func(t *testing.T) {
		decoder := NewStdDecoder()
		encoded := []byte(".- -... -.-. -.. . ..-. --. .... .. .--- -.- .-.. -- -. --- .--. --.- .-. ... - ..- ...- .-- -..- -.-- --..")
		decoded, err := decoder.Decode(encoded)
		assert.Nil(t, err)
		assert.Equal(t, []byte("abcdefghijklmnopqrstuvwxyz"), decoded)
	})

	t.Run("decode all numbers", func(t *testing.T) {
		decoder := NewStdDecoder()
		encoded := []byte("----- .---- ..--- ...-- ....- ..... -.... --... ---.. ----.")
		decoded, err := decoder.Decode(encoded)
		assert.Nil(t, err)
		assert.Equal(t, []byte("0123456789"), decoded)
	})

	t.Run("decode large data", func(t *testing.T) {
		decoder := NewStdDecoder()
		// Create large morse data by encoding then decoding
		encoder := NewStdEncoder()
		largeData := strings.Repeat("hello", 100)
		encoded := encoder.Encode([]byte(largeData))
		decoded, err := decoder.Decode(encoded)
		assert.Nil(t, err)
		assert.Equal(t, []byte(largeData), decoded)
	})

	t.Run("decode with unknown character", func(t *testing.T) {
		decoder := NewStdDecoder()
		encoded := []byte(".... . .-.. .-.. --- INVALID .-- --- .-. .-.. -..")
		decoded, err := decoder.Decode(encoded)
		assert.NotNil(t, err)
		assert.Nil(t, decoded)
		assert.Contains(t, err.Error(), "unknown character")
	})

	t.Run("decode with invalid morse code", func(t *testing.T) {
		decoder := NewStdDecoder()
		encoded := []byte(".... . .-.. .-.. --- .-- --- .-. .-.. -.. INVALID")
		decoded, err := decoder.Decode(encoded)
		assert.NotNil(t, err)
		assert.Nil(t, decoded)
		assert.Contains(t, err.Error(), "unknown character")
	})

	t.Run("decode with existing error", func(t *testing.T) {
		decoder := &StdDecoder{Error: errors.New("test error")}
		result, err := decoder.Decode([]byte(".... . .-.. .-.. ---"))
		assert.NotNil(t, err)
		assert.Nil(t, result)
		assert.Equal(t, "test error", err.Error())
	})

	t.Run("decode punctuation marks", func(t *testing.T) {
		decoder := NewStdDecoder()

		// Test all supported punctuation
		encoded := []byte(".-.-.-")
		decoded, err := decoder.Decode(encoded)
		assert.Nil(t, err)
		assert.Equal(t, []byte("."), decoded)

		encoded = []byte("--..--")
		decoded, err = decoder.Decode(encoded)
		assert.Nil(t, err)
		assert.Equal(t, []byte(","), decoded)

		encoded = []byte("-...-")
		decoded, err = decoder.Decode(encoded)
		assert.Nil(t, err)
		assert.Equal(t, []byte("="), decoded)

		encoded = []byte(".-.-.")
		decoded, err = decoder.Decode(encoded)
		assert.Nil(t, err)
		assert.Equal(t, []byte("+"), decoded)

		encoded = []byte("-....-")
		decoded, err = decoder.Decode(encoded)
		assert.Nil(t, err)
		assert.Equal(t, []byte("-"), decoded)

		encoded = []byte("-..-.")
		decoded, err = decoder.Decode(encoded)
		assert.Nil(t, err)
		assert.Equal(t, []byte("/"), decoded)
	})
}

func TestStreamEncoder_Write(t *testing.T) {
	t.Run("write data", func(t *testing.T) {
		var buf bytes.Buffer
		encoder := NewStreamEncoder(&buf)

		data := []byte("hello")
		n, err := encoder.Write(data)

		assert.Equal(t, 5, n)
		assert.Nil(t, err)
		// Data is processed immediately in Write
		assert.Equal(t, ".... . .-.. .-.. ---", buf.String())
	})

	t.Run("write with error", func(t *testing.T) {
		encoder := &StreamEncoder{Error: errors.New("test error")}
		data := []byte("hello")
		n, err := encoder.Write(data)

		assert.Equal(t, 0, n)
		assert.NotNil(t, err)
		assert.Equal(t, "test error", err.Error())
	})

	t.Run("write empty data", func(t *testing.T) {
		var buf bytes.Buffer
		encoder := NewStreamEncoder(&buf)

		data := []byte{}
		n, err := encoder.Write(data)

		assert.Equal(t, 0, n)
		assert.Nil(t, err)
		assert.Empty(t, buf.String())
	})

	t.Run("write with writer error", func(t *testing.T) {
		errorWriter := mock.NewErrorWriteCloser(errors.New("write error"))
		encoder := NewStreamEncoder(errorWriter)

		n, err := encoder.Write([]byte("hello"))
		assert.Equal(t, 5, n)
		assert.Error(t, err)
		assert.Equal(t, "write error", err.Error())
	})

	t.Run("write with encoding error", func(t *testing.T) {
		var buf bytes.Buffer
		encoder := NewStreamEncoder(&buf)

		// Write data with spaces to trigger encoding error
		data := []byte("hello world") // contains space
		n, err := encoder.Write(data)

		assert.Equal(t, 11, n)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "input cannot contain spaces")
	})

	t.Run("write with encoder error", func(t *testing.T) {
		var buf bytes.Buffer
		encoder := NewStreamEncoder(&buf)

		// Set an error on the underlying encoder to test error handling
		encoder.(*StreamEncoder).encoder.Error = errors.New("encoder error")

		n, err := encoder.Write([]byte("hello"))
		assert.Equal(t, 5, n)
		assert.Error(t, err)
		assert.Equal(t, "encoder error", err.Error())
	})

	t.Run("write with unknown character buffering", func(t *testing.T) {
		var buf bytes.Buffer
		encoder := NewStreamEncoder(&buf)

		// Write data with unknown character to test buffering logic
		n, err := encoder.Write([]byte("ab@"))
		assert.Equal(t, 3, n)
		assert.Nil(t, err)

		// Should encode "ab" and buffer "@"
		assert.Equal(t, ".- -...", buf.String())

		// Check that "@" is buffered
		streamEncoder := encoder.(*StreamEncoder)
		assert.Equal(t, []byte("@"), streamEncoder.buffer)
	})
}

func TestStreamEncoder_Close(t *testing.T) {
	t.Run("close with data", func(t *testing.T) {
		var buf bytes.Buffer
		encoder := NewStreamEncoder(&buf)

		encoder.Write([]byte("hello"))
		err := encoder.Close()

		assert.Nil(t, err)
		// StreamEncoder processes data immediately in Write
		assert.Equal(t, ".... . .-.. .-.. ---", buf.String())
	})

	t.Run("close without data", func(t *testing.T) {
		var buf bytes.Buffer
		encoder := NewStreamEncoder(&buf)

		err := encoder.Close()

		assert.Nil(t, err)
		assert.Empty(t, buf.String())
	})

	t.Run("close with error", func(t *testing.T) {
		encoder := &StreamEncoder{Error: errors.New("test error")}
		err := encoder.Close()

		assert.NotNil(t, err)
		assert.Equal(t, "test error", err.Error())
	})

	t.Run("close with buffered data", func(t *testing.T) {
		var buf bytes.Buffer
		encoder := NewStreamEncoder(&buf)

		// Manually set buffer with some data (simulating incomplete write)
		streamEncoder := encoder.(*StreamEncoder)
		streamEncoder.buffer = []byte("abc")

		err := encoder.Close()
		assert.Nil(t, err)
		assert.Equal(t, ".- -... -.-.", buf.String())
	})

	t.Run("close with buffered data and space error", func(t *testing.T) {
		var buf bytes.Buffer
		encoder := NewStreamEncoder(&buf)

		// Manually set buffer with space character
		streamEncoder := encoder.(*StreamEncoder)
		streamEncoder.buffer = []byte("a b")

		err := encoder.Close()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "input cannot contain spaces")
	})

	t.Run("close with buffered data and write error", func(t *testing.T) {
		errorWriter := mock.NewErrorWriteCloser(errors.New("write error"))
		encoder := NewStreamEncoder(errorWriter)

		// Manually set buffer with some data
		streamEncoder := encoder.(*StreamEncoder)
		streamEncoder.buffer = []byte("abc")

		err := encoder.Close()
		assert.Error(t, err)
		assert.Equal(t, "write error", err.Error())
	})
}

func TestStreamDecoder_Read(t *testing.T) {
	t.Run("read decoded data", func(t *testing.T) {
		// First encode some data
		encoder := NewStdEncoder()
		encoded := encoder.Encode([]byte("hello"))

		// Create reader with encoded data
		reader := bytes.NewReader(encoded)
		decoder := NewStreamDecoder(reader)

		// Read decoded data
		buffer := make([]byte, 10)
		n, err := decoder.Read(buffer)

		assert.Nil(t, err)
		assert.Equal(t, 5, n)
		assert.Equal(t, []byte("hello"), buffer[:n])
	})

	t.Run("read with large buffer", func(t *testing.T) {
		encoder := NewStdEncoder()
		encoded := encoder.Encode([]byte("hello"))

		reader := bytes.NewReader(encoded)
		decoder := NewStreamDecoder(reader)

		buffer := make([]byte, 100)
		n, err := decoder.Read(buffer)

		assert.Nil(t, err)
		assert.Equal(t, 5, n)
		assert.Equal(t, []byte("hello"), buffer[:n])
	})

	t.Run("read with small buffer", func(t *testing.T) {
		encoder := NewStdEncoder()
		encoded := encoder.Encode([]byte("hello"))

		reader := bytes.NewReader(encoded)
		decoder := NewStreamDecoder(reader)

		buffer := make([]byte, 3)
		n, err := decoder.Read(buffer)

		assert.Nil(t, err)
		assert.Equal(t, 3, n)
		assert.Equal(t, []byte("hel"), buffer[:n])

		// Read remaining data
		n, err = decoder.Read(buffer)
		assert.Nil(t, err)
		assert.Equal(t, 2, n)
		assert.Equal(t, []byte("lo"), buffer[:n])
	})

	t.Run("read from buffer", func(t *testing.T) {
		decoder := &StreamDecoder{
			buffer: []byte("hello"),
			pos:    0,
		}

		buffer := make([]byte, 3)
		n, err := decoder.Read(buffer)

		assert.Equal(t, 3, n)
		assert.Nil(t, err)
		assert.Equal(t, []byte("hel"), buffer)
		assert.Equal(t, 3, decoder.pos)
	})

	t.Run("read with error", func(t *testing.T) {
		decoder := &StreamDecoder{Error: errors.New("test error")}
		buffer := make([]byte, 10)
		n, err := decoder.Read(buffer)

		assert.Equal(t, 0, n)
		assert.NotNil(t, err)
		assert.Equal(t, "test error", err.Error())
	})

	t.Run("read with decode error", func(t *testing.T) {
		// Create invalid morse data
		invalidData := []byte("invalid morse code")
		reader := bytes.NewReader(invalidData)
		decoder := NewStreamDecoder(reader)

		buffer := make([]byte, 10)
		n, err := decoder.Read(buffer)

		assert.Equal(t, 0, n)
		assert.NotNil(t, err)
		assert.Contains(t, err.Error(), "unknown character")
	})

	t.Run("read with reader error", func(t *testing.T) {
		errorReader := mock.NewErrorFile(errors.New("read error"))
		decoder := NewStreamDecoder(errorReader)

		buffer := make([]byte, 10)
		n, err := decoder.Read(buffer)

		assert.Equal(t, 0, n)
		assert.NotNil(t, err)
		assert.Equal(t, "read error", err.Error())
	})

	t.Run("read eof", func(t *testing.T) {
		reader := bytes.NewReader([]byte{})
		decoder := NewStreamDecoder(reader)

		buffer := make([]byte, 10)
		n, err := decoder.Read(buffer)

		assert.Equal(t, 0, n)
		assert.Equal(t, io.EOF, err)
	})
}

func TestStdError(t *testing.T) {
	t.Run("decode invalid character", func(t *testing.T) {
		decoder := NewStdDecoder()
		encoded := []byte(".... . .-.. .-.. --- INVALID")
		decoded, err := decoder.Decode(encoded)
		assert.NotNil(t, err)
		assert.Nil(t, decoded)
		assert.Contains(t, err.Error(), "unknown character INVALID")
	})

	t.Run("encoder with space error", func(t *testing.T) {
		encoder := NewStdEncoder()
		result := encoder.Encode([]byte("hello world"))
		assert.Nil(t, result)
		assert.NotNil(t, encoder.Error)
		assert.Contains(t, encoder.Error.Error(), "input cannot contain spaces")
	})

	t.Run("invalid character error message", func(t *testing.T) {
		err := InvalidCharacterError{Char: "INVALID"}
		assert.Equal(t, "coding/morse: unknown character INVALID", err.Error())
	})

	t.Run("invalid input error message", func(t *testing.T) {
		err := InvalidInputError{}
		assert.Equal(t, "coding/morse: input cannot contain spaces", err.Error())
	})
}

func TestStreamError(t *testing.T) {
	t.Run("stream encoder with writer error", func(t *testing.T) {
		errorWriter := mock.NewErrorWriteCloser(errors.New("write error"))
		encoder := NewStreamEncoder(errorWriter)

		// Error occurs during Write, not Close
		n, err := encoder.Write([]byte("hello"))
		assert.Equal(t, 5, n)
		assert.Error(t, err)
		assert.Equal(t, "write error", err.Error())

		// Close should not return an error
		closeErr := encoder.Close()
		assert.Nil(t, closeErr)
	})

	t.Run("stream decoder with reader error", func(t *testing.T) {
		errorReader := mock.NewErrorFile(errors.New("read error"))
		decoder := NewStreamDecoder(errorReader)

		buffer := make([]byte, 10)
		n, err := decoder.Read(buffer)

		assert.Equal(t, 0, n)
		assert.NotNil(t, err)
		assert.Equal(t, "read error", err.Error())
	})

	t.Run("stream decoder with decode error", func(t *testing.T) {
		invalidData := []byte("invalid morse code")
		reader := bytes.NewReader(invalidData)
		decoder := NewStreamDecoder(reader)

		buffer := make([]byte, 10)
		n, err := decoder.Read(buffer)

		assert.Equal(t, 0, n)
		assert.NotNil(t, err)
		assert.Contains(t, err.Error(), "unknown character")
	})

	t.Run("stream encoder with existing error", func(t *testing.T) {
		encoder := &StreamEncoder{Error: errors.New("existing error")}
		data := []byte("hello")
		n, err := encoder.Write(data)

		assert.Equal(t, 0, n)
		assert.NotNil(t, err)
		assert.Equal(t, "existing error", err.Error())
	})

	t.Run("stream encoder close with existing error", func(t *testing.T) {
		encoder := &StreamEncoder{Error: errors.New("existing error")}
		err := encoder.Close()

		assert.NotNil(t, err)
		assert.Equal(t, "existing error", err.Error())
	})

	t.Run("stream decoder with existing error", func(t *testing.T) {
		decoder := &StreamDecoder{Error: errors.New("existing error")}
		buffer := make([]byte, 10)
		n, err := decoder.Read(buffer)

		assert.Equal(t, 0, n)
		assert.NotNil(t, err)
		assert.Equal(t, "existing error", err.Error())
	})
}
