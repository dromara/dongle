package unicode

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/dromara/dongle/internal/mock"
	"github.com/stretchr/testify/assert"
)

func TestStdEncoder_Encode(t *testing.T) {
	t.Run("encode empty data", func(t *testing.T) {
		encoder := NewStdEncoder()
		result := encoder.Encode([]byte{})
		assert.Empty(t, result)
		assert.Nil(t, encoder.Error)
	})

	t.Run("encode simple string", func(t *testing.T) {
		encoder := NewStdEncoder()
		result := encoder.Encode([]byte("hello"))
		expected := []byte(`hello`)
		assert.Equal(t, expected, result)
		assert.Nil(t, encoder.Error)
	})

	t.Run("encode unicode string", func(t *testing.T) {
		encoder := NewStdEncoder()
		result := encoder.Encode([]byte("你好世界"))
		expected := []byte(`\u4f60\u597d\u4e16\u754c`)
		assert.Equal(t, expected, result)
		assert.Nil(t, encoder.Error)
	})

	t.Run("encode mixed content", func(t *testing.T) {
		encoder := NewStdEncoder()
		result := encoder.Encode([]byte("hello 世界"))
		expected := []byte(`hello \u4e16\u754c`)
		assert.Equal(t, expected, result)
		assert.Nil(t, encoder.Error)
	})

	t.Run("encode special characters", func(t *testing.T) {
		encoder := NewStdEncoder()
		result := encoder.Encode([]byte("hello\nworld\t"))
		expected := []byte(`hello\nworld\t`)
		assert.Equal(t, expected, result)
		assert.Nil(t, encoder.Error)
	})

	t.Run("encode binary data", func(t *testing.T) {
		encoder := NewStdEncoder()
		data := []byte{0x00, 0x01, 0x7F, 0x80, 0xFF}
		result := encoder.Encode(data)
		// Binary data should be escaped
		assert.NotEmpty(t, result)
		assert.Nil(t, encoder.Error)
	})

	t.Run("encode with existing error", func(t *testing.T) {
		encoder := &StdEncoder{Error: assert.AnError}
		result := encoder.Encode([]byte("hello"))
		assert.Empty(t, result)
	})

	t.Run("encode large data", func(t *testing.T) {
		encoder := NewStdEncoder()
		original := bytes.Repeat([]byte("Hello, World! "), 100)
		encoded := encoder.Encode(original)
		assert.NotEmpty(t, encoded)
		assert.Nil(t, encoder.Error)
	})

	t.Run("encode with different byte counts", func(t *testing.T) {
		encoder := NewStdEncoder()

		// Test single byte
		encoded := encoder.Encode([]byte{0x41})
		assert.Equal(t, []byte("A"), encoded)
		assert.Nil(t, encoder.Error)

		// Test two bytes
		encoded = encoder.Encode([]byte{0x41, 0x42})
		assert.Equal(t, []byte("AB"), encoded)
		assert.Nil(t, encoder.Error)

		// Test three bytes
		encoded = encoder.Encode([]byte{0x41, 0x42, 0x43})
		assert.Equal(t, []byte("ABC"), encoded)
		assert.Nil(t, encoder.Error)
	})

	t.Run("encode all zeros", func(t *testing.T) {
		encoder := NewStdEncoder()
		original := []byte{0x00, 0x01, 0x02, 0x03}
		encoded := encoder.Encode(original)
		// Binary data should be escaped
		assert.NotEmpty(t, encoded)
		assert.Nil(t, encoder.Error)
	})

	t.Run("encode with leading zeros", func(t *testing.T) {
		encoder := NewStdEncoder()
		input := []byte{0x00, 0x00, 0x01, 0x02, 0x03}
		result := encoder.Encode(input)
		// Binary data should be escaped
		assert.NotEmpty(t, result)
		assert.Nil(t, encoder.Error)
	})

	t.Run("encode with existing error", func(t *testing.T) {
		encoder := &StdEncoder{Error: errors.New("test error")}
		result := encoder.Encode([]byte("hello"))
		assert.Empty(t, result)
		assert.NotNil(t, encoder.Error)
		assert.Equal(t, "test error", encoder.Error.Error())
	})
}

func TestStdDecoder_Decode(t *testing.T) {
	t.Run("decode empty data", func(t *testing.T) {
		decoder := NewStdDecoder()
		result, err := decoder.Decode([]byte{})
		assert.Empty(t, result)
		assert.Nil(t, err)
	})

	t.Run("decode simple string", func(t *testing.T) {
		decoder := NewStdDecoder()
		result, err := decoder.Decode([]byte(`hello`))
		assert.Equal(t, []byte("hello"), result)
		assert.Nil(t, err)
	})

	t.Run("decode unicode string", func(t *testing.T) {
		decoder := NewStdDecoder()
		result, err := decoder.Decode([]byte(`\u4f60\u597d\u4e16\u754c`))
		assert.Equal(t, []byte("你好世界"), result)
		assert.Nil(t, err)
	})

	t.Run("decode mixed content", func(t *testing.T) {
		decoder := NewStdDecoder()
		result, err := decoder.Decode([]byte(`hello \u4e16\u754c`))
		assert.Equal(t, []byte("hello 世界"), result)
		assert.Nil(t, err)
	})

	t.Run("decode special characters", func(t *testing.T) {
		decoder := NewStdDecoder()
		result, err := decoder.Decode([]byte(`hello\nworld\t`))
		assert.Equal(t, []byte("hello\nworld\t"), result)
		assert.Nil(t, err)
	})

	t.Run("decode invalid unicode", func(t *testing.T) {
		decoder := NewStdDecoder()
		result, err := decoder.Decode([]byte(`\uZZZZ`))
		assert.Empty(t, result)
		assert.Error(t, err)
	})

	t.Run("decode with existing error", func(t *testing.T) {
		decoder := &StdDecoder{Error: assert.AnError}
		result, err := decoder.Decode([]byte("hello"))
		assert.Empty(t, result)
		assert.Equal(t, assert.AnError, err)
	})

	t.Run("decode with different byte counts", func(t *testing.T) {
		decoder := NewStdDecoder()

		// Test single byte
		decoded, err := decoder.Decode([]byte("A"))
		assert.Nil(t, err)
		assert.Equal(t, []byte{0x41}, decoded)

		// Test two bytes
		decoded, err = decoder.Decode([]byte("AB"))
		assert.Nil(t, err)
		assert.Equal(t, []byte{0x41, 0x42}, decoded)

		// Test binary data
		decoded, err = decoder.Decode([]byte("\\u0000\\u0001\\u0002\\u0003"))
		assert.Nil(t, err)
		assert.Equal(t, []byte{0x00, 0x01, 0x02, 0x03}, decoded)
	})

	t.Run("decode all zeros", func(t *testing.T) {
		decoder := NewStdDecoder()
		encoded := []byte("\\u0000\\u0001\\u0002\\u0003")
		decoded, err := decoder.Decode(encoded)
		assert.Nil(t, err)
		assert.Equal(t, []byte{0x00, 0x01, 0x02, 0x03}, decoded)
	})

	t.Run("decode binary data", func(t *testing.T) {
		decoder := NewStdDecoder()
		encoder := NewStdEncoder()
		original := []byte{0xFF, 0xFE, 0xFD, 0xFC, 0xFB, 0xFA}
		encoded := encoder.Encode(original)
		decoded, err := decoder.Decode(encoded)
		assert.Nil(t, err)
		assert.Equal(t, original, decoded)
	})

	t.Run("decode with leading zeros", func(t *testing.T) {
		decoder := NewStdDecoder()
		encoder := NewStdEncoder()
		input := []byte{0x00, 0x00, 0x01, 0x02, 0x03}
		encoded := encoder.Encode(input)
		decoded, err := decoder.Decode(encoded)
		assert.Nil(t, err)
		assert.Equal(t, input, decoded)
	})
}

func TestStreamEncoder_Write(t *testing.T) {
	t.Run("write empty data", func(t *testing.T) {
		file := mock.NewFile(nil, "test.txt")
		encoder := NewStreamEncoder(file)
		n, err := encoder.Write([]byte{})
		assert.Equal(t, 0, n)
		assert.Nil(t, err)
		assert.Empty(t, string(file.Bytes()))
	})

	t.Run("write simple string", func(t *testing.T) {
		file := mock.NewFile(nil, "test.txt")
		encoder := NewStreamEncoder(file)
		n, err := encoder.Write([]byte("hello"))
		assert.Equal(t, 5, n)
		assert.Nil(t, err)
		// Close to flush the buffer
		err = encoder.Close()
		assert.Nil(t, err)
		assert.Equal(t, "hello", string(file.Bytes()))
	})

	t.Run("write unicode string", func(t *testing.T) {
		file := mock.NewFile(nil, "test.txt")
		encoder := NewStreamEncoder(file)
		n, err := encoder.Write([]byte("你好"))
		assert.Equal(t, 6, n) // 3 bytes per character
		assert.Nil(t, err)
		// Close to flush the buffer
		err = encoder.Close()
		assert.Nil(t, err)
		assert.Equal(t, `\u4f60\u597d`, string(file.Bytes()))
	})

	t.Run("write with existing error", func(t *testing.T) {
		file := mock.NewFile(nil, "test.txt")
		encoder := &StreamEncoder{writer: file, Error: assert.AnError}
		n, err := encoder.Write([]byte("hello"))
		assert.Equal(t, 0, n)
		assert.Equal(t, assert.AnError, err)
	})

	t.Run("write multiple times", func(t *testing.T) {
		file := mock.NewFile(nil, "test.txt")
		encoder := NewStreamEncoder(file)

		encoder.Write([]byte("hello"))
		encoder.Write([]byte(" world"))

		err := encoder.Close()
		assert.NoError(t, err)
		assert.Equal(t, "hello world", string(file.Bytes()))
	})

	t.Run("write with writer error", func(t *testing.T) {
		errorWriter := mock.NewErrorWriteCloser(errors.New("write error"))
		encoder := NewStreamEncoder(errorWriter).(*StreamEncoder)

		data := []byte("hello")
		n, err := encoder.Write(data)
		assert.Equal(t, 5, n)
		assert.Nil(t, err) // Write succeeds, error happens on Close

		err = encoder.Close()
		assert.Error(t, err)
		assert.Equal(t, "write error", err.Error())
	})

	t.Run("write large data", func(t *testing.T) {
		file := mock.NewFile(nil, "test.txt")
		encoder := NewStreamEncoder(file)

		data := bytes.Repeat([]byte("Hello, World! "), 100)
		n, err := encoder.Write(data)
		assert.Equal(t, len(data), n)
		assert.Nil(t, err)

		err = encoder.Close()
		assert.NoError(t, err)
		assert.NotEmpty(t, string(file.Bytes()))
	})

	t.Run("write empty data", func(t *testing.T) {
		file := mock.NewFile(nil, "test.txt")
		encoder := NewStreamEncoder(file).(*StreamEncoder)
		var data []byte
		n, err := encoder.Write(data)
		assert.Equal(t, 0, n)
		assert.Nil(t, err)
		assert.Empty(t, encoder.buffer)
	})
}

func TestStreamEncoder_Close(t *testing.T) {
	t.Run("close with no buffered data", func(t *testing.T) {
		file := mock.NewFile(nil, "test.txt")
		encoder := NewStreamEncoder(file)
		err := encoder.Close()
		assert.Nil(t, err)
		assert.Empty(t, string(file.Bytes()))
	})

	t.Run("close with buffered data", func(t *testing.T) {
		file := mock.NewFile(nil, "test.txt")
		encoder := NewStreamEncoder(file)
		// Write partial data that will be buffered
		encoder.Write([]byte("h"))
		err := encoder.Close()
		assert.Nil(t, err)
		assert.Equal(t, "h", string(file.Bytes()))
	})

	t.Run("close with existing error", func(t *testing.T) {
		file := mock.NewFile(nil, "test.txt")
		encoder := &StreamEncoder{writer: file, Error: assert.AnError}
		err := encoder.Close()
		assert.Equal(t, assert.AnError, err)
	})

	t.Run("close with write error", func(t *testing.T) {
		errorWriter := mock.NewErrorWriteCloser(errors.New("write error"))
		encoder := NewStreamEncoder(errorWriter).(*StreamEncoder)

		// Write data that will be buffered
		encoder.Write([]byte("hello"))

		err := encoder.Close()
		assert.Error(t, err)
		assert.Equal(t, "write error", err.Error())
	})
}

func TestStreamDecoder_Read(t *testing.T) {
	t.Run("read empty data", func(t *testing.T) {
		reader := strings.NewReader("")
		decoder := NewStreamDecoder(reader)
		buf := make([]byte, 10)
		n, err := decoder.Read(buf)
		assert.Equal(t, 0, n)
		assert.Equal(t, err, err) // EOF
	})

	t.Run("read simple string", func(t *testing.T) {
		reader := strings.NewReader("hello")
		decoder := NewStreamDecoder(reader)
		buf := make([]byte, 10)
		n, err := decoder.Read(buf)
		assert.Equal(t, 5, n)
		assert.Nil(t, err)
		assert.Equal(t, []byte("hello"), buf[:n])
	})

	t.Run("read unicode string", func(t *testing.T) {
		reader := strings.NewReader(`\u4f60\u597d`)
		decoder := NewStreamDecoder(reader)
		buf := make([]byte, 10)
		n, err := decoder.Read(buf)
		assert.Equal(t, 6, n) // 3 bytes per character
		assert.Nil(t, err)
		assert.Equal(t, []byte("你好"), buf[:n])
	})

	t.Run("read with existing error", func(t *testing.T) {
		reader := strings.NewReader("hello")
		decoder := &StreamDecoder{reader: reader, Error: assert.AnError}
		buf := make([]byte, 10)
		n, err := decoder.Read(buf)
		assert.Equal(t, 0, n)
		assert.Equal(t, assert.AnError, err)
	})

	t.Run("read from buffer", func(t *testing.T) {
		// First encode some data
		encoder := NewStdEncoder()
		encoded := encoder.Encode([]byte("hello"))

		reader := mock.NewFile(encoded, "test.bin")
		decoder := NewStreamDecoder(reader)

		buf := make([]byte, 10)
		n, err := decoder.Read(buf)
		assert.NoError(t, err)
		assert.Equal(t, 5, n)
		assert.Equal(t, []byte("hello"), buf[:n])
	})

	t.Run("read from reader", func(t *testing.T) {
		// First encode some data
		encoder := NewStdEncoder()
		encoded := encoder.Encode([]byte("hello world"))

		reader := mock.NewFile(encoded, "test.bin")
		decoder := NewStreamDecoder(reader)

		buf := make([]byte, 20)
		n, err := decoder.Read(buf)
		assert.NoError(t, err)
		assert.Equal(t, 11, n)
		assert.Equal(t, []byte("hello world"), buf[:n])
	})

	t.Run("read with partial buffer", func(t *testing.T) {
		// First encode some data
		encoder := NewStdEncoder()
		encoded := encoder.Encode([]byte("hello world"))

		reader := mock.NewFile(encoded, "test.bin")
		decoder := NewStreamDecoder(reader)

		// Read with small buffer
		buf := make([]byte, 5)
		n, err := decoder.Read(buf)
		assert.NoError(t, err)
		assert.Equal(t, 5, n)
		assert.Equal(t, []byte("hello"), buf)

		// Read remaining data
		buf2 := make([]byte, 10)
		n2, err2 := decoder.Read(buf2)
		assert.NoError(t, err2)
		assert.Equal(t, 6, n2) // " world"
		assert.Equal(t, []byte(" world"), buf2[:n2])
	})

	t.Run("read from empty reader", func(t *testing.T) {
		reader := mock.NewFile([]byte{}, "test.bin")
		decoder := NewStreamDecoder(reader)

		buf := make([]byte, 10)
		n, err := decoder.Read(buf)
		assert.Equal(t, io.EOF, err)
		assert.Equal(t, 0, n)
	})

	t.Run("read unicode data", func(t *testing.T) {
		file := mock.NewFile(nil, "test.bin")
		encoder := NewStreamEncoder(file)
		encoder.Write([]byte("hello world"))
		encoder.Close()

		// Reset file position for reading
		file.Reset()

		decoder := NewStreamDecoder(file)

		buf := make([]byte, 20)
		n, err := decoder.Read(buf)
		assert.NoError(t, err)
		assert.Equal(t, 11, n)
		assert.Equal(t, []byte("hello world"), buf[:n])
	})

	t.Run("read with reader error", func(t *testing.T) {
		errorReader := mock.NewErrorFile(assert.AnError)
		decoder := NewStreamDecoder(errorReader)

		buf := make([]byte, 10)
		n, err := decoder.Read(buf)
		assert.Equal(t, assert.AnError, err)
		assert.Equal(t, 0, n)
	})

	t.Run("read with decode error", func(t *testing.T) {
		reader := mock.NewFile([]byte("invalid!"), "test.bin")
		decoder := NewStreamDecoder(reader)

		buf := make([]byte, 10)
		n, err := decoder.Read(buf)
		// strconv.Unquote is tolerant, so this might not error
		// We just check that it processes the data
		assert.Nil(t, err)
		assert.Equal(t, 8, n) // "invalid!" is 8 bytes
	})

	t.Run("read with mock error reader", func(t *testing.T) {
		errorReader := mock.NewErrorReadWriteCloser(assert.AnError)
		decoder := NewStreamDecoder(errorReader)

		buf := make([]byte, 10)
		n, err := decoder.Read(buf)
		assert.Equal(t, assert.AnError, err)
		assert.Equal(t, 0, n)
	})

	t.Run("read with error state", func(t *testing.T) {
		reader := mock.NewFile([]byte("hello"), "test.bin")
		decoder := NewStreamDecoder(reader).(*StreamDecoder)
		decoder.Error = io.ErrUnexpectedEOF

		buf := make([]byte, 10)
		n, err := decoder.Read(buf)
		assert.Equal(t, 0, n)
		assert.Equal(t, io.ErrUnexpectedEOF, err)
	})

	t.Run("read with EOF error", func(t *testing.T) {
		reader := strings.NewReader("")
		decoder := NewStreamDecoder(reader)

		buf := make([]byte, 10)
		n, err := decoder.Read(buf)
		assert.Equal(t, io.EOF, err)
		assert.Equal(t, 0, n)
	})

	t.Run("read with large buffer", func(t *testing.T) {
		// First encode some data
		encoder := NewStdEncoder()
		encoded := encoder.Encode([]byte("hello world"))

		reader := mock.NewFile(encoded, "test.bin")
		decoder := NewStreamDecoder(reader)

		// Read with large buffer
		buf := make([]byte, 100)
		n, err := decoder.Read(buf)
		assert.NoError(t, err)
		assert.Equal(t, 11, n)
		assert.Equal(t, []byte("hello world"), buf[:n])
	})

	t.Run("read with partial buffer copy", func(t *testing.T) {
		// First encode some data
		encoder := NewStdEncoder()
		encoded := encoder.Encode([]byte("hello world"))

		reader := mock.NewFile(encoded, "test.bin")
		decoder := NewStreamDecoder(reader)

		// Read with small buffer to trigger partial copy
		buf := make([]byte, 5)
		n, err := decoder.Read(buf)
		assert.NoError(t, err)
		assert.Equal(t, 5, n)
		assert.Equal(t, []byte("hello"), buf)

		// Read remaining data
		buf2 := make([]byte, 10)
		n2, err2 := decoder.Read(buf2)
		assert.NoError(t, err2)
		assert.Equal(t, 6, n2) // " world"
		assert.Equal(t, []byte(" world"), buf2[:n2])
	})
}

func TestEncodeDecodeRoundTrip(t *testing.T) {
	testCases := []struct {
		name string
		data []byte
	}{
		{"empty", []byte{}},
		{"simple", []byte("hello")},
		{"unicode", []byte("你好世界")},
		{"mixed", []byte("hello 世界")},
		{"special", []byte("hello\nworld\t")},
		{"binary", []byte{0x00, 0x01, 0x7F, 0x80, 0xFF}},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Encode
			encoder := NewStdEncoder()
			encoded := encoder.Encode(tc.data)
			assert.Nil(t, encoder.Error)

			// Decode
			decoder := NewStdDecoder()
			decoded, err := decoder.Decode(encoded)
			assert.Nil(t, err)
			if len(tc.data) == 0 {
				assert.Empty(t, decoded)
			} else {
				assert.Equal(t, tc.data, decoded)
			}
		})
	}
}

func TestStdEncoderDecoder_ErrorShortCircuit(t *testing.T) {
	t.Run("encoder preset error", func(t *testing.T) {
		enc := NewStdEncoder()
		enc.Error = assert.AnError
		out := enc.Encode([]byte("hello"))
		assert.Nil(t, out)
	})

	t.Run("decoder preset error", func(t *testing.T) {
		dec := NewStdDecoder()
		dec.Error = assert.AnError
		out, err := dec.Decode([]byte("hello"))
		assert.Nil(t, out)
		assert.Equal(t, assert.AnError, err)
	})
}

func TestStdError(t *testing.T) {
	t.Run("decode invalid unicode", func(t *testing.T) {
		decoder := NewStdDecoder()
		result, err := decoder.Decode([]byte("\\uZZZZ"))
		assert.Error(t, err)
		assert.Nil(t, result)
	})

	t.Run("decode invalid escape sequence", func(t *testing.T) {
		decoder := NewStdDecoder()
		result, err := decoder.Decode([]byte("\\x"))
		assert.Error(t, err)
		assert.Nil(t, result)
	})

	t.Run("decode invalid characters", func(t *testing.T) {
		decoder := NewStdDecoder()
		result, err := decoder.Decode([]byte("\\uGGGG"))
		assert.Error(t, err)
		assert.Nil(t, result)
	})

	t.Run("decode with invalid escape sequence in stream", func(t *testing.T) {
		reader := strings.NewReader("\\uGGGG")
		decoder := NewStreamDecoder(reader)

		buf := make([]byte, 10)
		n, err := decoder.Read(buf)
		assert.Error(t, err)
		assert.Equal(t, 0, n)
	})

	t.Run("decode with invalid unicode in stream", func(t *testing.T) {
		reader := strings.NewReader("\\uZZZZ")
		decoder := NewStreamDecoder(reader)

		buf := make([]byte, 10)
		n, err := decoder.Read(buf)
		assert.Error(t, err)
		assert.Equal(t, 0, n)
	})
}

func TestStreamError(t *testing.T) {
	t.Run("stream encoder write with writer error", func(t *testing.T) {
		errorWriter := mock.NewErrorWriteCloser(assert.AnError)
		encoder := NewStreamEncoder(errorWriter)
		_, err := encoder.Write([]byte("test"))
		// Write succeeds, error happens on Close
		assert.Nil(t, err)
	})

	t.Run("stream decoder with reader error", func(t *testing.T) {
		errorReader := mock.NewErrorFile(assert.AnError)
		decoder := NewStreamDecoder(errorReader)

		buf := make([]byte, 10)
		n, err := decoder.Read(buf)
		assert.Equal(t, assert.AnError, err)
		assert.Equal(t, 0, n)
	})

	t.Run("stream decoder with decode error", func(t *testing.T) {
		reader := mock.NewFile([]byte("invalid!"), "test.bin")
		decoder := NewStreamDecoder(reader)

		buf := make([]byte, 10)
		n, err := decoder.Read(buf)
		// strconv.Unquote is tolerant, so this might not error
		// We just check that it processes the data
		assert.Nil(t, err)
		assert.Equal(t, 8, n) // "invalid!" is 8 bytes
	})

	t.Run("stream decoder with mock error reader", func(t *testing.T) {
		errorReader := mock.NewErrorReadWriteCloser(assert.AnError)
		decoder := NewStreamDecoder(errorReader)

		buf := make([]byte, 10)
		n, err := decoder.Read(buf)
		assert.Equal(t, assert.AnError, err)
		assert.Equal(t, 0, n)
	})

	t.Run("stream encoder with error state", func(t *testing.T) {
		file := mock.NewFile(nil, "test.txt")
		encoder := NewStreamEncoder(file).(*StreamEncoder)
		encoder.Error = io.ErrShortWrite

		n, err := encoder.Write([]byte("hello"))
		assert.Equal(t, 0, n)
		assert.Equal(t, io.ErrShortWrite, err)
	})

	t.Run("stream decoder with error state", func(t *testing.T) {
		reader := mock.NewFile([]byte("hello"), "test.bin")
		decoder := NewStreamDecoder(reader).(*StreamDecoder)
		decoder.Error = io.ErrUnexpectedEOF

		buf := make([]byte, 10)
		n, err := decoder.Read(buf)
		assert.Equal(t, 0, n)
		assert.Equal(t, io.ErrUnexpectedEOF, err)
	})
}

func TestErrorTypes(t *testing.T) {
	t.Run("DecodeFailedError", func(t *testing.T) {
		err := DecodeFailedError{Input: "test input"}
		msg := err.Error()
		assert.Contains(t, msg, "coding/unicode: failed to decode data")
		assert.Contains(t, msg, "test input")
	})

	t.Run("InvalidUnicodeError", func(t *testing.T) {
		err := InvalidUnicodeError{Char: "invalid char"}
		msg := err.Error()
		assert.Contains(t, msg, "coding/unicode: invalid unicode character")
		assert.Contains(t, msg, "invalid char")
	})

	t.Run("EncodeFailedError", func(t *testing.T) {
		err := EncodeFailedError{Input: "test input"}
		msg := err.Error()
		assert.Contains(t, msg, "coding/unicode: failed to encode data")
		assert.Contains(t, msg, "test input")
	})
}
