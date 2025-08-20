package base85

import (
	"bytes"
	"io"
	"testing"

	"gitee.com/golang-package/dongle/mock"
	"github.com/stretchr/testify/assert"
)

// TestStdEncoder_Encode tests standard base85 encoding scenarios.
func TestStdEncoder_Encode(t *testing.T) {
	t.Run("encode empty input", func(t *testing.T) {
		encoder := NewStdEncoder()
		result := encoder.Encode([]byte{})
		assert.Nil(t, result)
		assert.Nil(t, encoder.Error)
	})

	t.Run("encode simple string", func(t *testing.T) {
		encoder := NewStdEncoder()
		original := []byte("hello")
		encoded := encoder.Encode(original)
		assert.Equal(t, []byte("BOu!rDZ"), encoded)
		assert.Nil(t, encoder.Error)
	})

	t.Run("encode with different byte counts", func(t *testing.T) {
		encoder := NewStdEncoder()

		// Test single byte
		encoded := encoder.Encode([]byte{42})
		assert.Equal(t, []byte(".K"), encoded)
		assert.Nil(t, encoder.Error)

		// Test two bytes
		encoded = encoder.Encode([]byte{42, 43})
		assert.Equal(t, []byte(".Ot"), encoded)
		assert.Nil(t, encoder.Error)

		// Test three bytes
		encoded = encoder.Encode([]byte{42, 43, 44})
		assert.Equal(t, []byte(".P!%"), encoded)
		assert.Nil(t, encoder.Error)

		// Test four bytes
		encoded = encoder.Encode([]byte{42, 43, 44, 45})
		assert.Equal(t, []byte(".P!&%"), encoded)
		assert.Nil(t, encoder.Error)

		// Test five bytes
		encoded = encoder.Encode([]byte{42, 43, 44, 45, 46})
		assert.Equal(t, []byte(".P!&%/c"), encoded)
		assert.Nil(t, encoder.Error)
	})

	t.Run("encode all zeros", func(t *testing.T) {
		encoder := NewStdEncoder()
		original := []byte{0, 0, 0, 0}
		encoded := encoder.Encode(original)
		assert.Equal(t, []byte("z"), encoded)
		assert.Nil(t, encoder.Error)
	})

	t.Run("encode unicode string", func(t *testing.T) {
		encoder := NewStdEncoder()
		original := []byte("Hello, World! 你好世界")
		encoded := encoder.Encode(original)
		assert.NotEmpty(t, encoded)
		assert.Nil(t, encoder.Error)
	})

	t.Run("encode binary data", func(t *testing.T) {
		encoder := NewStdEncoder()
		original := []byte{0xFF, 0xFE, 0xFD, 0xFC, 0xFB, 0xFA}
		encoded := encoder.Encode(original)
		assert.Equal(t, []byte("s8Mupqt^"), encoded)
		assert.Nil(t, encoder.Error)
	})

	t.Run("encode large data", func(t *testing.T) {
		encoder := NewStdEncoder()
		original := bytes.Repeat([]byte("Hello, World! "), 100)
		encoded := encoder.Encode(original)
		assert.Equal(t, []byte("87cURD_*#4DfTZ)+Ws<eCi\"#@+BNK%Ch+\\387cURD_*#4DfTZ)"), encoded[:50])
		assert.Nil(t, encoder.Error)
	})

	t.Run("encode with leading zeros", func(t *testing.T) {
		encoder := NewStdEncoder()
		input := []byte{0x00, 0x00, 0x01, 0x02, 0x03}
		result := encoder.Encode(input)
		assert.Equal(t, []byte("!!!$$!r"), result)
		assert.Nil(t, encoder.Error)
	})
}

// TestStdDecoder_Decode tests standard base85 decoding scenarios.
func TestStdDecoder_Decode(t *testing.T) {
	t.Run("decode empty input", func(t *testing.T) {
		decoder := NewStdDecoder()
		result, err := decoder.Decode([]byte{})
		assert.Nil(t, err)
		assert.Nil(t, result)
	})

	t.Run("decode simple string", func(t *testing.T) {
		decoder := NewStdDecoder()
		encoded := []byte("BOu!rDZ")
		decoded, err := decoder.Decode(encoded)
		assert.Nil(t, err)
		assert.Equal(t, []byte("hello"), decoded)
	})

	t.Run("decode with different byte counts", func(t *testing.T) {
		decoder := NewStdDecoder()

		// Test single byte
		decoded, err := decoder.Decode([]byte(".K"))
		assert.Nil(t, err)
		assert.Equal(t, []byte{42}, decoded)

		// Test two bytes
		decoded, err = decoder.Decode([]byte(".Ot"))
		assert.Nil(t, err)
		assert.Equal(t, []byte{42, 43}, decoded)

		// Test three bytes
		decoded, err = decoder.Decode([]byte(".P!%"))
		assert.Nil(t, err)
		assert.Equal(t, []byte{42, 43, 44}, decoded)

		// Test four bytes
		decoded, err = decoder.Decode([]byte(".P!&%"))
		assert.Nil(t, err)
		assert.Equal(t, []byte{42, 43, 44, 45}, decoded)

		// Test binary data
		decoded, err = decoder.Decode([]byte("!!!$$!r"))
		assert.Nil(t, err)
		assert.Equal(t, []byte{0x00, 0x00, 0x01, 0x02, 0x03}, decoded)
	})

	t.Run("decode all zeros", func(t *testing.T) {
		decoder := NewStdDecoder()
		encoded := []byte("z")
		decoded, err := decoder.Decode(encoded)
		assert.Nil(t, err)
		assert.Equal(t, []byte{0, 0, 0, 0}, decoded)
	})

	t.Run("decode unicode string", func(t *testing.T) {
		decoder := NewStdDecoder()
		encoded := []byte("87cURD_*#4DfTZ)+X#jZT]N#`jLCN=Q&G")
		decoded, err := decoder.Decode(encoded)
		assert.Nil(t, err)
		assert.Equal(t, []byte("Hello, World! 你好世界"), decoded)
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

// TestStreamEncoder_Write tests writing to the stream encoder.
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
		assert.Equal(t, "BOu!rD]j7BEbo7", buf.String())
	})
}

// TestStreamEncoder_Close tests closing the stream encoder.
func TestStreamEncoder_Close(t *testing.T) {
	t.Run("close with data", func(t *testing.T) {
		var buf bytes.Buffer
		encoder := NewStreamEncoder(&buf)
		encoder.Write([]byte("hello world"))

		err := encoder.Close()
		assert.NoError(t, err)
		assert.Equal(t, "BOu!rD]j7BEbo7", buf.String())
	})

	t.Run("close without data", func(t *testing.T) {
		var buf bytes.Buffer
		encoder := NewStreamEncoder(&buf)

		err := encoder.Close()
		assert.NoError(t, err)
		assert.Empty(t, buf.String())
	})
}

// TestStreamDecoder_Read tests reading from the stream decoder.
func TestStreamDecoder_Read(t *testing.T) {
	t.Run("read from buffer", func(t *testing.T) {
		// First encode some data
		encoder := NewStdEncoder()
		encoded := encoder.Encode([]byte("hello"))

		file := mock.NewFile(encoded, "test.txt")
		decoder := NewStreamDecoder(file)

		buf := make([]byte, 10)
		n, err := decoder.Read(buf)
		assert.NoError(t, err)
		assert.Equal(t, 4, n)
		assert.Equal(t, []byte("hell"), buf[:n])
	})

	t.Run("read from reader", func(t *testing.T) {
		// First encode some data
		encoder := NewStdEncoder()
		encoded := encoder.Encode([]byte("hello world"))

		file := mock.NewFile(encoded, "test.txt")
		decoder := NewStreamDecoder(file)

		buf := make([]byte, 20)
		n, err := decoder.Read(buf)
		assert.NoError(t, err)
		assert.Equal(t, 8, n)
		assert.Equal(t, []byte("hello wo"), buf[:n])
	})

	t.Run("read with partial buffer", func(t *testing.T) {
		// First encode some data
		encoder := NewStdEncoder()
		encoded := encoder.Encode([]byte("hello world"))

		file := mock.NewFile(encoded, "test.txt")
		decoder := NewStreamDecoder(file)

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
		assert.Equal(t, 3, n2) // " wo"
		assert.Equal(t, []byte(" wo"), buf2[:n2])
	})

	t.Run("read from empty reader", func(t *testing.T) {
		file := mock.NewFile([]byte{}, "test.txt")
		decoder := NewStreamDecoder(file)

		buf := make([]byte, 10)
		n, err := decoder.Read(buf)
		assert.Equal(t, io.EOF, err)
		assert.Equal(t, 0, n)
	})
}

// TestStdError tests standard error scenarios for encoder and decoder.
func TestStdError(t *testing.T) {
	t.Run("decode invalid character", func(t *testing.T) {
		decoder := NewStdDecoder()
		result, err := decoder.Decode([]byte("invalid@"))
		assert.Error(t, err)
		assert.Nil(t, result)
	})

	t.Run("encoder invalid alphabet", func(t *testing.T) {
		encoder := NewStdEncoder()
		assert.Nil(t, encoder.Error)
		result := encoder.Encode([]byte("hello"))
		assert.NotNil(t, result)
	})

	t.Run("decoder invalid alphabet", func(t *testing.T) {
		decoder := NewStdDecoder()
		assert.Nil(t, decoder.Error)
		result, err := decoder.Decode([]byte("BOu!rDZ"))
		assert.Nil(t, err)
		assert.NotNil(t, result)
	})

	t.Run("corrupt input error message", func(t *testing.T) {
		err := CorruptInputError(5)
		expected := "coding/base85: illegal data at input byte 5"
		assert.Equal(t, expected, err.Error())
	})
}

// TestStreamError tests error scenarios for stream encoder and decoder.
func TestStreamError(t *testing.T) {
	t.Run("stream encoder close with writer error", func(t *testing.T) {
		errorWriter := mock.NewErrorWriteCloser(assert.AnError)
		encoder := NewStreamEncoder(errorWriter)
		_, err := encoder.Write([]byte("test"))
		assert.NoError(t, err)

		err = encoder.Close()
		assert.Equal(t, assert.AnError, err)
	})

	t.Run("stream encoder write with existing error", func(t *testing.T) {
		var buf bytes.Buffer
		encoder := NewStreamEncoder(&buf)
		streamEncoder, ok := encoder.(*StreamEncoder)
		assert.True(t, ok)
		streamEncoder.Error = assert.AnError

		n, err := streamEncoder.Write([]byte("test"))
		assert.Equal(t, assert.AnError, err)
		assert.Equal(t, 0, n)
	})

	t.Run("stream encoder close with existing error", func(t *testing.T) {
		var buf bytes.Buffer
		encoder := NewStreamEncoder(&buf)
		streamEncoder, ok := encoder.(*StreamEncoder)
		assert.True(t, ok)
		streamEncoder.Error = assert.AnError

		err := streamEncoder.Close()
		assert.Equal(t, assert.AnError, err)
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
		file := mock.NewFile([]byte("invalid@"), "test.txt")
		decoder := NewStreamDecoder(file)

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

	t.Run("read with invalid data", func(t *testing.T) {
		file := mock.NewFile([]byte("invalid@"), "test.txt")
		decoder := NewStreamDecoder(file)

		buf := make([]byte, 10)
		n, err := decoder.Read(buf)
		assert.Error(t, err)
		assert.Equal(t, 0, n)
	})

	t.Run("read with incomplete group", func(t *testing.T) {
		// Test with incomplete 5-character group
		file := mock.NewFile([]byte("BOu!r"), "test.txt")
		decoder := NewStreamDecoder(file)

		buf := make([]byte, 10)
		n, err := decoder.Read(buf)
		assert.NoError(t, err)
		assert.Equal(t, 4, n) // Actually returns decoded data
	})

	t.Run("read with existing error", func(t *testing.T) {
		file := mock.NewFile([]byte("test"), "test.txt")
		decoder := NewStreamDecoder(file)
		streamDecoder, ok := decoder.(*StreamDecoder)
		assert.True(t, ok)
		streamDecoder.Error = assert.AnError

		buf := make([]byte, 10)
		n, err := streamDecoder.Read(buf)
		assert.Equal(t, assert.AnError, err)
		assert.Equal(t, 0, n)
	})

	t.Run("read with decode error", func(t *testing.T) {
		// Test the case where Decode returns an error
		file := mock.NewFile([]byte("invalid@"), "test.txt")
		decoder := NewStreamDecoder(file)

		buf := make([]byte, 10)
		n, err := decoder.Read(buf)
		assert.Error(t, err)
		assert.Equal(t, 0, n)
	})

	t.Run("read with no complete groups", func(t *testing.T) {
		// Test the case where there are no complete 5-character groups
		file := mock.NewFile([]byte("BOu!"), "test.txt")
		decoder := NewStreamDecoder(file)

		buf := make([]byte, 10)
		n, err := decoder.Read(buf)
		assert.NoError(t, err)
		assert.Equal(t, 0, n) // Should wait for more data
	})

	t.Run("read with EOF and no data", func(t *testing.T) {
		// Test the case where we're at EOF and have no encoded data
		file := mock.NewFile([]byte{}, "test.txt")
		decoder := NewStreamDecoder(file)
		streamDecoder, ok := decoder.(*StreamDecoder)
		assert.True(t, ok)
		streamDecoder.eof = true
		streamDecoder.encodeBuf = nil

		buf := make([]byte, 10)
		n, err := streamDecoder.Read(buf)
		assert.Equal(t, io.EOF, err)
		assert.Equal(t, 0, n)
	})

	t.Run("read with EOF and remaining data", func(t *testing.T) {
		// Test the case where we're at EOF and have remaining encoded data
		file := mock.NewFile([]byte("BOu!rDZ"), "test.txt")
		decoder := NewStreamDecoder(file)
		streamDecoder, ok := decoder.(*StreamDecoder)
		assert.True(t, ok)
		streamDecoder.eof = true

		buf := make([]byte, 10)
		n, err := streamDecoder.Read(buf)
		assert.Equal(t, io.EOF, err)
		assert.Equal(t, 5, n) // Should decode all remaining data
	})

	t.Run("read with buffer position at end", func(t *testing.T) {
		// Test the case where buffer position is at the end and we're at EOF
		file := mock.NewFile([]byte("BOu!rDZ"), "test.txt")
		decoder := NewStreamDecoder(file)
		streamDecoder, ok := decoder.(*StreamDecoder)
		assert.True(t, ok)
		streamDecoder.buffer = []byte("hello")
		streamDecoder.pos = 5 // At the end of buffer
		streamDecoder.eof = true

		buf := make([]byte, 10)
		n, err := streamDecoder.Read(buf)
		assert.Equal(t, io.EOF, err)
		assert.Equal(t, 5, n) // Actually returns the data first, then EOF
	})
}
