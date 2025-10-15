package base85

import (
	"bytes"
	"errors"
	"io"
	"testing"

	"github.com/dromara/dongle/mock"
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

func TestStdEncoderDecoder_ErrorFlags(t *testing.T) {
	t.Run("encoder with existing error", func(t *testing.T) {
		enc := NewStdEncoder()
		enc.Error = assert.AnError
		out := enc.Encode([]byte("hello"))
		assert.Nil(t, out)
	})

	t.Run("decoder with existing error", func(t *testing.T) {
		dec := NewStdDecoder()
		dec.Error = assert.AnError
		out, err := dec.Decode([]byte("BOu!rDZ"))
		assert.Nil(t, out)
		assert.Equal(t, assert.AnError, err)
	})

	t.Run("decoder incomplete group sizing (len%5==1)", func(t *testing.T) {
		dec := NewStdDecoder()
		// One character that's not 'z'; will be padded and decode to 1 byte
		out, err := dec.Decode([]byte("!"))
		assert.NoError(t, err)
		assert.Equal(t, 1, len(out))
	})

	t.Run("decoder incomplete group sizing (len%5==2)", func(t *testing.T) {
		dec := NewStdDecoder()
		out, err := dec.Decode([]byte("!!"))
		assert.NoError(t, err)
		assert.Equal(t, 1, len(out))
	})

	t.Run("decoder incomplete group sizing (len%5==3 => 2 bytes)", func(t *testing.T) {
		dec := NewStdDecoder()
		out, err := dec.Decode([]byte("!!!"))
		assert.NoError(t, err)
		assert.Equal(t, 2, len(out))
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

	t.Run("write with writer error", func(t *testing.T) {
		errorWriter := mock.NewErrorWriteCloser(errors.New("write error"))
		encoder := NewStreamEncoder(errorWriter)

		data := []byte("hello world") // 11 bytes, will trigger chunk processing
		n, err := encoder.Write(data)

		assert.Equal(t, 11, n)
		assert.Error(t, err)
		assert.Equal(t, "write error", err.Error())
	})

	t.Run("write with exact chunk size", func(t *testing.T) {
		var buf bytes.Buffer
		encoder := NewStreamEncoder(&buf)

		data := make([]byte, 4) // Exactly 4 bytes
		for i := range data {
			data[i] = byte(i)
		}

		n, err := encoder.Write(data)
		assert.Equal(t, 4, n)
		assert.Nil(t, err)
	})

	t.Run("write with multiple chunks", func(t *testing.T) {
		var buf bytes.Buffer
		encoder := NewStreamEncoder(&buf)

		data := make([]byte, 8) // Exactly 2 chunks of 4 bytes
		for i := range data {
			data[i] = byte(i)
		}

		n, err := encoder.Write(data)
		assert.Equal(t, 8, n)
		assert.Nil(t, err)
	})

	t.Run("write with remainder", func(t *testing.T) {
		var buf bytes.Buffer
		encoder := NewStreamEncoder(&buf)

		data := make([]byte, 6) // 4 + 2 bytes, will have 2 bytes remainder
		for i := range data {
			data[i] = byte(i)
		}

		n, err := encoder.Write(data)
		assert.Equal(t, 6, n)
		assert.Nil(t, err)
	})

	t.Run("write empty data", func(t *testing.T) {
		var buf bytes.Buffer
		encoder := NewStreamEncoder(&buf)

		var data []byte
		n, err := encoder.Write(data)

		assert.Equal(t, 0, n)
		assert.Nil(t, err)
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
		assert.Equal(t, 5, n) // Now reads all data at once
		assert.Equal(t, []byte("hello"), buf[:n])
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
		assert.Equal(t, 11, n) // Now reads all data at once
		assert.Equal(t, []byte("hello world"), buf[:n])
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
		assert.Equal(t, 6, n2) // " world" (now reads all remaining data)
		assert.Equal(t, []byte(" world"), buf2[:n2])
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

		// Write data that will leave 1-3 bytes in buffer
		encoder.Write([]byte("a")) // 1 byte, will be buffered

		err := encoder.Close()
		assert.Error(t, err)
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
		assert.True(t, n > 0) // Now reads and decodes what it can
	})

	t.Run("read with EOF and no data", func(t *testing.T) {
		// Test the case where we're at EOF and have no encoded data
		file := mock.NewFile([]byte{}, "test.txt")
		decoder := NewStreamDecoder(file)

		buf := make([]byte, 10)
		n, err := decoder.Read(buf)
		assert.Equal(t, io.EOF, err)
		assert.Equal(t, 0, n)
	})

	t.Run("read with EOF and remaining data", func(t *testing.T) {
		// Test the case where we're at EOF and have remaining encoded data
		file := mock.NewFile([]byte("BOu!rDZ"), "test.txt")
		decoder := NewStreamDecoder(file)

		buf := make([]byte, 10)
		n, err := decoder.Read(buf)
		assert.NoError(t, err)
		assert.True(t, n > 0) // Should decode data
	})

	t.Run("read with buffer position at end", func(t *testing.T) {
		// Test the case where buffer position is at the end
		file := mock.NewFile([]byte("BOu!rDZ"), "test.txt")
		decoder := NewStreamDecoder(file)
		streamDecoder, ok := decoder.(*StreamDecoder)
		assert.True(t, ok)
		streamDecoder.buffer = []byte("hello")
		streamDecoder.pos = 5 // At the end of buffer

		buf := make([]byte, 10)
		n, err := streamDecoder.Read(buf)
		assert.NoError(t, err)
		assert.True(t, n > 0) // Now reads new data from file
	})
}
