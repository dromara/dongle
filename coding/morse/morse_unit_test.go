package morse

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"

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

	t.Run("write multiple times", func(t *testing.T) {
		var buf bytes.Buffer
		encoder := NewStreamEncoder(&buf)

		data1 := []byte("hello")
		data2 := []byte("world")

		n1, err1 := encoder.Write(data1)
		n2, err2 := encoder.Write(data2)

		assert.Equal(t, 5, n1)
		assert.Nil(t, err1)
		assert.Equal(t, 5, n2)
		assert.Nil(t, err2)

		err := encoder.Close()
		assert.Nil(t, err)
		assert.Equal(t, ".... . .-.. .-.. --- .-- --- .-. .-.. -..", buf.String())
	})

	t.Run("close with data success", func(t *testing.T) {
		var buf bytes.Buffer
		encoder := NewStreamEncoder(&buf)

		encoder.Write([]byte("test"))
		err := encoder.Close()

		assert.Nil(t, err)
		assert.Equal(t, "- . ... -", buf.String())
	})

	t.Run("close with single character", func(t *testing.T) {
		var buf bytes.Buffer
		encoder := NewStreamEncoder(&buf)

		encoder.Write([]byte("a"))
		err := encoder.Close()

		assert.Nil(t, err)
		assert.Equal(t, ".-", buf.String())
	})

	t.Run("close with data", func(t *testing.T) {
		var buf bytes.Buffer
		encoder := NewStreamEncoder(&buf)

		encoder.Write([]byte("hello"))
		err := encoder.Close()

		assert.Nil(t, err)
		assert.Equal(t, ".... . .-.. .-.. ---", buf.String())
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
}

func TestStreamEncoder_Write(t *testing.T) {
	t.Run("write data", func(t *testing.T) {
		var buf bytes.Buffer
		encoder := NewStreamEncoder(&buf)

		data := []byte("hello")
		n, err := encoder.Write(data)

		assert.Equal(t, 5, n)
		assert.Nil(t, err)
	})

	t.Run("write multiple times", func(t *testing.T) {
		var buf bytes.Buffer
		encoder := NewStreamEncoder(&buf)

		data1 := []byte("hello")
		data2 := []byte("world")

		n1, err1 := encoder.Write(data1)
		n2, err2 := encoder.Write(data2)

		assert.Equal(t, 5, n1)
		assert.Nil(t, err1)
		assert.Equal(t, 5, n2)
		assert.Nil(t, err2)
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
	})
}

func TestStreamEncoder_Close(t *testing.T) {
	t.Run("close with data", func(t *testing.T) {
		var buf bytes.Buffer
		encoder := NewStreamEncoder(&buf)

		encoder.Write([]byte("hello"))
		err := encoder.Close()

		assert.Nil(t, err)
		assert.Equal(t, ".... . .-.. .-.. ---", buf.String())
	})

	t.Run("close without data", func(t *testing.T) {
		var buf bytes.Buffer
		encoder := NewStreamEncoder(&buf)

		err := encoder.Close()

		assert.Nil(t, err)
		assert.Equal(t, "", buf.String())
	})

	t.Run("close with error", func(t *testing.T) {
		encoder := &StreamEncoder{Error: errors.New("test error")}
		err := encoder.Close()

		assert.NotNil(t, err)
		assert.Equal(t, "test error", err.Error())
	})

	t.Run("close with write error", func(t *testing.T) {
		// Create a simple error writer
		errorWriter := &errorWriter{err: errors.New("write error")}
		encoder := NewStreamEncoder(errorWriter)

		encoder.Write([]byte("hello"))
		err := encoder.Close()

		assert.NotNil(t, err)
		assert.Equal(t, "write error", err.Error())
	})

	t.Run("close with encoding error", func(t *testing.T) {
		var buf bytes.Buffer
		encoder := NewStreamEncoder(&buf)

		// Write data with spaces to trigger encoding error
		encoder.Write([]byte("hello world"))
		err := encoder.Close()

		assert.NotNil(t, err)
		assert.Contains(t, err.Error(), "input cannot contain spaces")
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
		encoder := NewStdEncoder()
		encoded := encoder.Encode([]byte("hello"))

		reader := bytes.NewReader(encoded)
		decoder := NewStreamDecoder(reader)

		// Read first part
		buffer1 := make([]byte, 3)
		n1, err1 := decoder.Read(buffer1)
		assert.Nil(t, err1)
		assert.Equal(t, 3, n1)

		// Read second part
		buffer2 := make([]byte, 3)
		n2, err2 := decoder.Read(buffer2)
		assert.Nil(t, err2)
		assert.Equal(t, 2, n2)

		// Verify complete data
		complete := append(buffer1[:n1], buffer2[:n2]...)
		assert.Equal(t, []byte("hello"), complete)
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
		errorReader := &errorReader{err: errors.New("read error")}
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

	t.Run("decoder with error", func(t *testing.T) {
		decoder := &StdDecoder{Error: errors.New("test error")}
		result, err := decoder.Decode([]byte(".... . .-.. .-.. ---"))
		assert.NotNil(t, err)
		assert.Nil(t, result)
		assert.Equal(t, "test error", err.Error())
	})

	t.Run("encoder with error", func(t *testing.T) {
		encoder := &StdEncoder{Error: errors.New("test error")}
		result := encoder.Encode([]byte("hello"))
		assert.Nil(t, result)
		assert.Equal(t, "test error", encoder.Error.Error())
	})

	t.Run("invalid character error message", func(t *testing.T) {
		err := InvalidCharacterError{Char: "INVALID"}
		assert.Equal(t, "coding/morse: unknown character INVALID", err.Error())
	})
}

func TestStreamError(t *testing.T) {
	t.Run("stream encoder close with writer error", func(t *testing.T) {
		errorWriter := &errorWriter{err: errors.New("write error")}
		encoder := NewStreamEncoder(errorWriter)

		encoder.Write([]byte("hello"))
		err := encoder.Close()

		assert.NotNil(t, err)
		assert.Equal(t, "write error", err.Error())
	})

	t.Run("stream decoder with reader error", func(t *testing.T) {
		errorReader := &errorReader{err: errors.New("read error")}
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

	t.Run("stream decoder with mock error reader", func(t *testing.T) {
		errorReader := &errorReader{err: errors.New("mock error")}
		decoder := NewStreamDecoder(errorReader)

		buffer := make([]byte, 10)
		n, err := decoder.Read(buffer)

		assert.Equal(t, 0, n)
		assert.NotNil(t, err)
		assert.Equal(t, "mock error", err.Error())
	})

	t.Run("read with invalid data", func(t *testing.T) {
		invalidData := []byte(".... . .-.. .-.. --- INVALID")
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

// errorWriter is a simple mock writer that always returns an error
type errorWriter struct {
	err error
}

func (w *errorWriter) Write(p []byte) (n int, err error) {
	return 0, w.err
}

// errorReader is a simple mock reader that always returns an error
type errorReader struct {
	err error
}

func (r *errorReader) Read(p []byte) (n int, err error) {
	return 0, r.err
}
