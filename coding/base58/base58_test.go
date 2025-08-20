package base58

import (
	"bytes"
	"errors"
	"io"
	"testing"

	"gitee.com/golang-package/dongle/mock"
	"github.com/stretchr/testify/assert"
)

func TestStdEncoder_Encode(t *testing.T) {
	tests := []struct {
		name     string
		input    []byte
		expected string
	}{
		{
			name:     "empty input",
			input:    []byte{},
			expected: "",
		},
		{
			name:     "hello world",
			input:    []byte("hello world"),
			expected: "StV1DL6CwTryKyV",
		},
		{
			name:     "single character",
			input:    []byte("A"),
			expected: "28",
		},
		{
			name:     "two characters",
			input:    []byte("AB"),
			expected: "5y3",
		},
		{
			name:     "three characters",
			input:    []byte("ABC"),
			expected: "NvLz",
		},
		{
			name:     "leading zeros",
			input:    []byte{0, 0, 1, 2, 3},
			expected: "11Ldp",
		},
		{
			name:     "all zeros",
			input:    []byte{0, 0, 0, 0},
			expected: "1111",
		},
		{
			name:     "single zero",
			input:    []byte{0},
			expected: "1",
		},
		{
			name:     "large number",
			input:    []byte{255, 255, 255, 255},
			expected: "7YXq9G",
		},
		{
			name:     "unicode string",
			input:    []byte("你好世界"),
			expected: "5KMpie3K6ztGQYmij",
		},
		{
			name:     "binary data",
			input:    []byte{0x00, 0x01, 0x02, 0x03, 0xFF, 0xFE, 0xFD},
			expected: "1W7N56s6",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encoder := NewStdEncoder()
			result := encoder.Encode(tt.input)
			assert.Equal(t, tt.expected, string(result))
		})
	}
}

func TestStdDecoder_Decode(t *testing.T) {
	tests := []struct {
		name        string
		input       []byte
		expected    []byte
		expectError bool
	}{
		{
			name:        "empty input",
			input:       []byte{},
			expected:    nil,
			expectError: false,
		},
		{
			name:        "hello world",
			input:       []byte("StV1DL6CwTryKyV"),
			expected:    []byte("hello world"),
			expectError: false,
		},
		{
			name:        "single character",
			input:       []byte("28"),
			expected:    []byte("A"),
			expectError: false,
		},
		{
			name:        "two characters",
			input:       []byte("5y3"),
			expected:    []byte("AB"),
			expectError: false,
		},
		{
			name:        "three characters",
			input:       []byte("NvLz"),
			expected:    []byte("ABC"),
			expectError: false,
		},
		{
			name:        "leading ones",
			input:       []byte("11Ldp"),
			expected:    []byte{0, 0, 1, 2, 3},
			expectError: false,
		},
		{
			name:        "all ones",
			input:       []byte("1111"),
			expected:    []byte{0, 0, 0, 0},
			expectError: false,
		},
		{
			name:        "single one",
			input:       []byte("1"),
			expected:    []byte{0},
			expectError: false,
		},
		{
			name:        "large number",
			input:       []byte("7YXq9G"),
			expected:    []byte{255, 255, 255, 255},
			expectError: false,
		},
		{
			name:        "unicode string",
			input:       []byte("5KMpie3K6ztGQYmij"),
			expected:    []byte("你好世界"),
			expectError: false,
		},
		{
			name:        "binary data",
			input:       []byte("1W7N56s6"),
			expected:    []byte{0x00, 0x01, 0x02, 0x03, 0xFF, 0xFE, 0xFD},
			expectError: false,
		},
		{
			name:        "invalid character",
			input:       []byte("ABC!DEF"),
			expected:    nil,
			expectError: true,
		},
		{
			name:        "invalid character at start",
			input:       []byte("!ABCDEF"),
			expected:    nil,
			expectError: true,
		},
		{
			name:        "invalid character at end",
			input:       []byte("ABCDEF!"),
			expected:    nil,
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			decoder := NewStdDecoder()
			result, err := decoder.Decode(tt.input)

			if tt.expectError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), "base58: illegal data at input byte")
			} else {
				assert.Nil(t, err)
				assert.Equal(t, tt.expected, result)
			}
		})
	}
}

func TestStreamEncoder_Write(t *testing.T) {
	t.Run("write data", func(t *testing.T) {
		var buf bytes.Buffer
		encoder := NewStreamEncoder(&buf)
		data := []byte("hello world")
		n, err := encoder.Write(data)
		assert.NoError(t, err)
		assert.Equal(t, len(data), n)
	})

	t.Run("write multiple times", func(t *testing.T) {
		var buf bytes.Buffer
		encoder := NewStreamEncoder(&buf)

		encoder.Write([]byte("hello"))
		encoder.Write([]byte(" world"))

		err := encoder.Close()
		assert.NoError(t, err)
		assert.NotEmpty(t, buf.String())
	})

	t.Run("close without write", func(t *testing.T) {
		var buf bytes.Buffer
		encoder := NewStreamEncoder(&buf)
		err := encoder.Close()
		assert.NoError(t, err)
		assert.Empty(t, buf.String())
	})

	t.Run("close with data and write error", func(t *testing.T) {
		errorWriter := mock.NewErrorWriteCloser(assert.AnError)
		encoder := NewStreamEncoder(errorWriter)
		encoder.Write([]byte("test"))
		err := encoder.Close()
		assert.Equal(t, assert.AnError, err)
	})

	t.Run("close with data success", func(t *testing.T) {
		var buf bytes.Buffer
		encoder := NewStreamEncoder(&buf)
		encoder.Write([]byte("test"))
		err := encoder.Close()
		assert.NoError(t, err)
		assert.NotEmpty(t, buf.String())
	})

	t.Run("close with single byte", func(t *testing.T) {
		var buf bytes.Buffer
		encoder := NewStreamEncoder(&buf)
		encoder.Write([]byte("a"))
		err := encoder.Close()
		assert.NoError(t, err)
		assert.NotEmpty(t, buf.String())
	})

	t.Run("close with two bytes", func(t *testing.T) {
		var buf bytes.Buffer
		encoder := NewStreamEncoder(&buf)
		encoder.Write([]byte("ab"))
		err := encoder.Close()
		assert.NoError(t, err)
		assert.NotEmpty(t, buf.String())
	})
}

func TestStreamEncoder_Close(t *testing.T) {
	t.Run("close with data", func(t *testing.T) {
		var buf bytes.Buffer
		encoder := NewStreamEncoder(&buf)
		encoder.Write([]byte("hello world"))

		err := encoder.Close()
		assert.NoError(t, err)
		assert.NotEmpty(t, buf.String())
	})

	t.Run("close without data", func(t *testing.T) {
		var buf bytes.Buffer
		encoder := NewStreamEncoder(&buf)

		err := encoder.Close()
		assert.NoError(t, err)
		assert.Empty(t, buf.String())
	})
}

func TestStreamDecoder_Read(t *testing.T) {
	t.Run("read from buffer", func(t *testing.T) {
		// First encode some data
		encoder := NewStdEncoder()
		encoded := encoder.Encode([]byte("hello"))

		reader := bytes.NewReader(encoded)
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

		reader := bytes.NewReader(encoded)
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

		reader := bytes.NewReader(encoded)
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
		reader := bytes.NewReader([]byte{})
		decoder := NewStreamDecoder(reader)

		buf := make([]byte, 10)
		n, err := decoder.Read(buf)
		assert.Equal(t, io.EOF, err)
		assert.Equal(t, 0, n)
	})

	t.Run("read with decode error", func(t *testing.T) {
		reader := bytes.NewReader([]byte("invalid!"))
		decoder := NewStreamDecoder(reader)

		buf := make([]byte, 10)
		n, err := decoder.Read(buf)
		assert.Error(t, err)
		assert.Equal(t, 0, n)
	})
}

func TestStdError(t *testing.T) {
	t.Run("error_fields", func(t *testing.T) {
		encoder := NewStdEncoder()
		decoder := NewStdDecoder()
		assert.Nil(t, encoder.Error)
		assert.Nil(t, decoder.Error)

		testError := errors.New("test error")
		encoder.Error = testError
		decoder.Error = testError
		assert.Equal(t, testError, encoder.Error)
		assert.Equal(t, testError, decoder.Error)
	})

	t.Run("error_types", func(t *testing.T) {
		err1 := AlphabetSizeError(50)
		assert.Equal(t, "coding/base58: invalid alphabet, the alphabet length must be 58, got 50", err1.Error())

		err2 := CorruptInputError(5)
		assert.Equal(t, "coding/base58: illegal data at input byte 5", err2.Error())

		err3 := CorruptInputError(0)
		assert.Equal(t, "coding/base58: illegal data at input byte 0", err3.Error())
	})

	t.Run("decode invalid character", func(t *testing.T) {
		decoder := NewStdDecoder()
		result, err := decoder.Decode([]byte("invalid!"))
		assert.Error(t, err)
		assert.Nil(t, result)
	})

	t.Run("encoder with error", func(t *testing.T) {
		encoder := NewStdEncoder()
		encoder.Error = assert.AnError
		result := encoder.Encode([]byte("hello"))
		assert.Nil(t, result)
	})

	t.Run("decoder with error", func(t *testing.T) {
		decoder := NewStdDecoder()
		decoder.Error = assert.AnError
		result, err := decoder.Decode([]byte("StV1DL6CwTryKyV"))
		assert.Equal(t, assert.AnError, err)
		assert.Nil(t, result)
	})

	t.Run("legacy encode function", func(t *testing.T) {
		// Test legacy encode function
		original := []byte("hello world")
		encoded := Encode(original)
		assert.NotEmpty(t, encoded)
		assert.NotEqual(t, original, encoded)
	})

	t.Run("legacy decode with invalid input", func(t *testing.T) {
		// Test legacy decode function with invalid input
		invalidData := []byte("invalid!")
		result := Decode(invalidData)
		// Legacy Decode function ignores errors, so we just check the result
		assert.Nil(t, result)
	})
}

func TestStreamError(t *testing.T) {
	t.Run("stream encoder with error in close", func(t *testing.T) {
		encoder := NewStreamEncoder(mock.NewErrorFile(assert.AnError))
		data := []byte("hello")
		_, err := encoder.Write(data)
		assert.NoError(t, err)
		err = encoder.Close()
		assert.Equal(t, assert.AnError, err)
	})

	t.Run("stream encoder with existing error", func(t *testing.T) {
		// Base58 uses custom implementation, so we can set custom errors
		encoder := NewStreamEncoder(&bytes.Buffer{})
		streamEncoder, ok := encoder.(*StreamEncoder)
		assert.True(t, ok)
		streamEncoder.Error = assert.AnError
		_, err := encoder.Write([]byte("test"))
		assert.Equal(t, assert.AnError, err)
	})

	t.Run("stream encoder close with existing error", func(t *testing.T) {
		encoder := NewStreamEncoder(&bytes.Buffer{})
		streamEncoder, ok := encoder.(*StreamEncoder)
		assert.True(t, ok)
		streamEncoder.Error = assert.AnError
		err := encoder.Close()
		assert.Equal(t, assert.AnError, err)
	})

	t.Run("stream encoder close with writer error", func(t *testing.T) {
		errorWriter := mock.NewErrorWriteCloser(assert.AnError)
		encoder := NewStreamEncoder(errorWriter)
		_, err := encoder.Write([]byte("test"))
		assert.NoError(t, err)

		err = encoder.Close()
		assert.Equal(t, assert.AnError, err)
	})

	t.Run("stream decoder with error", func(t *testing.T) {
		// Base58 uses custom implementation, so we can set custom errors
		reader := bytes.NewReader([]byte("test"))
		decoder := NewStreamDecoder(reader)
		streamDecoder, ok := decoder.(*StreamDecoder)
		assert.True(t, ok)
		streamDecoder.Error = assert.AnError
		buf := make([]byte, 10)
		n, err := decoder.Read(buf)
		assert.Equal(t, assert.AnError, err)
		assert.Equal(t, 0, n)
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
		reader := bytes.NewReader([]byte("invalid!"))
		decoder := NewStreamDecoder(reader)

		buf := make([]byte, 10)
		n, err := decoder.Read(buf)
		assert.Error(t, err)
		assert.Equal(t, 0, n)
	})

	t.Run("stream decoder with mock error reader", func(t *testing.T) {
		errorReader := mock.NewErrorReadWriteCloser(assert.AnError)
		decoder := NewStreamDecoder(errorReader)

		buf := make([]byte, 10)
		n, err := decoder.Read(buf)
		assert.Equal(t, assert.AnError, err)
		assert.Equal(t, 0, n)
	})
}
