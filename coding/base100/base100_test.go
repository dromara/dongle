package base100

import (
	"bytes"
	"io"
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
		original := []byte("hello world")
		encoded := encoder.Encode(original)
		// Expected values calculated using Python base100 implementation
		expected := []byte{
			0xf0, 0x9f, 0x91, 0x9f, // h
			0xf0, 0x9f, 0x91, 0x9c, // e
			0xf0, 0x9f, 0x91, 0xa3, // l
			0xf0, 0x9f, 0x91, 0xa3, // l
			0xf0, 0x9f, 0x91, 0xa6, // o
			0xf0, 0x9f, 0x90, 0x97, // space
			0xf0, 0x9f, 0x91, 0xae, // w
			0xf0, 0x9f, 0x91, 0xa6, // o
			0xf0, 0x9f, 0x91, 0xa9, // r
			0xf0, 0x9f, 0x91, 0xa3, // l
			0xf0, 0x9f, 0x91, 0x9b, // d
		}
		assert.Equal(t, expected, encoded)
		assert.Nil(t, encoder.Error)
	})

	t.Run("encode with different byte counts", func(t *testing.T) {
		encoder := NewStdEncoder()

		// Test single byte
		encoded := encoder.Encode([]byte{65})
		assert.Equal(t, []byte{0xf0, 0x9f, 0x90, 0xb8}, encoded)
		assert.Nil(t, encoder.Error)

		// Test two bytes
		encoded = encoder.Encode([]byte{65, 66})
		assert.Equal(t, []byte{0xf0, 0x9f, 0x90, 0xb8, 0xf0, 0x9f, 0x90, 0xb9}, encoded)
		assert.Nil(t, encoder.Error)

		// Test three bytes
		encoded = encoder.Encode([]byte{65, 66, 67})
		assert.Equal(t, []byte{0xf0, 0x9f, 0x90, 0xb8, 0xf0, 0x9f, 0x90, 0xb9, 0xf0, 0x9f, 0x90, 0xba}, encoded)
		assert.Nil(t, encoder.Error)

		// Test four bytes
		encoded = encoder.Encode([]byte{65, 66, 67, 68})
		assert.Equal(t, []byte{0xf0, 0x9f, 0x90, 0xb8, 0xf0, 0x9f, 0x90, 0xb9, 0xf0, 0x9f, 0x90, 0xba, 0xf0, 0x9f, 0x90, 0xbb}, encoded)
		assert.Nil(t, encoder.Error)

		// Test five bytes
		encoded = encoder.Encode([]byte{65, 66, 67, 68, 69})
		assert.Equal(t, []byte{0xf0, 0x9f, 0x90, 0xb8, 0xf0, 0x9f, 0x90, 0xb9, 0xf0, 0x9f, 0x90, 0xba, 0xf0, 0x9f, 0x90, 0xbb, 0xf0, 0x9f, 0x90, 0xbc}, encoded)
		assert.Nil(t, encoder.Error)
	})

	t.Run("encode all zeros", func(t *testing.T) {
		encoder := NewStdEncoder()
		original := []byte{0x00, 0x01, 0x02, 0x03}
		encoded := encoder.Encode(original)
		assert.Equal(t, []byte{0xf0, 0x9f, 0x8f, 0xb7, 0xf0, 0x9f, 0x8f, 0xb8, 0xf0, 0x9f, 0x8f, 0xb9, 0xf0, 0x9f, 0x8f, 0xba}, encoded)
		assert.Nil(t, encoder.Error)
	})

	t.Run("encode unicode string", func(t *testing.T) {
		encoder := NewStdEncoder()
		original := []byte("你好世界")
		encoded := encoder.Encode(original)
		// Expected values for UTF-8 bytes of "你好世界"
		expected := []byte{
			0xf0, 0x9f, 0x93, 0x9b, // 0xe4
			0xf0, 0x9f, 0x92, 0xb4, // 0xbd
			0xf0, 0x9f, 0x92, 0x97, // 0xa0
			0xf0, 0x9f, 0x93, 0x9c, // 0xe5
			0xf0, 0x9f, 0x92, 0x9c, // 0xa5
			0xf0, 0x9f, 0x92, 0xb4, // 0xbd
			0xf0, 0x9f, 0x93, 0x9b, // 0xe4
			0xf0, 0x9f, 0x92, 0xaf, // 0xb8
			0xf0, 0x9f, 0x92, 0x8d, // 0x96
			0xf0, 0x9f, 0x93, 0x9e, // 0xe7
			0xf0, 0x9f, 0x92, 0x8c, // 0x95
			0xf0, 0x9f, 0x92, 0x83, // 0x8c
		}
		assert.Equal(t, expected, encoded)
		assert.Nil(t, encoder.Error)
	})

	t.Run("encode binary data", func(t *testing.T) {
		encoder := NewStdEncoder()
		original := []byte{0xFF, 0xFE, 0xFD, 0xFC, 0xFB, 0xFA}
		encoded := encoder.Encode(original)
		assert.Equal(t, []byte{0xf0, 0x9f, 0x93, 0xb6, 0xf0, 0x9f, 0x93, 0xb5, 0xf0, 0x9f, 0x93, 0xb4, 0xf0, 0x9f, 0x93, 0xb3, 0xf0, 0x9f, 0x93, 0xb2, 0xf0, 0x9f, 0x93, 0xb1}, encoded)
		assert.Nil(t, encoder.Error)
	})

	t.Run("encode large data", func(t *testing.T) {
		encoder := NewStdEncoder()
		original := bytes.Repeat([]byte("Hello, World! "), 100)
		encoded := encoder.Encode(original)
		// Check first 4 bytes of "Hello, World! " -> "H"
		assert.Equal(t, []byte{0xf0, 0x9f, 0x90, 0xbf, 0xf0, 0x9f, 0x91, 0x9c, 0xf0, 0x9f, 0x91, 0xa3, 0xf0, 0x9f, 0x91, 0xa3}, encoded[:16])
		assert.Nil(t, encoder.Error)
	})

	t.Run("encode with leading zeros", func(t *testing.T) {
		encoder := NewStdEncoder()
		input := []byte{0x00, 0x00, 0x01, 0x02, 0x03}
		result := encoder.Encode(input)
		assert.Equal(t, []byte{0xf0, 0x9f, 0x8f, 0xb7, 0xf0, 0x9f, 0x8f, 0xb7, 0xf0, 0x9f, 0x8f, 0xb8, 0xf0, 0x9f, 0x8f, 0xb9, 0xf0, 0x9f, 0x8f, 0xba}, result)
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
		encoded := []byte{
			0xf0, 0x9f, 0x91, 0x9f, // h
			0xf0, 0x9f, 0x91, 0x9c, // e
			0xf0, 0x9f, 0x91, 0xa3, // l
			0xf0, 0x9f, 0x91, 0xa3, // l
			0xf0, 0x9f, 0x91, 0xa6, // o
			0xf0, 0x9f, 0x90, 0x97, // space
			0xf0, 0x9f, 0x91, 0xae, // w
			0xf0, 0x9f, 0x91, 0xa6, // o
			0xf0, 0x9f, 0x91, 0xa9, // r
			0xf0, 0x9f, 0x91, 0xa3, // l
			0xf0, 0x9f, 0x91, 0x9b, // d
		}
		decoded, err := decoder.Decode(encoded)
		assert.Nil(t, err)
		assert.Equal(t, []byte("hello world"), decoded)
	})

	t.Run("decode with different byte counts", func(t *testing.T) {
		decoder := NewStdDecoder()

		// Test single byte
		decoded, err := decoder.Decode([]byte{0xf0, 0x9f, 0x90, 0xb8})
		assert.Nil(t, err)
		assert.Equal(t, []byte{65}, decoded)

		// Test two bytes
		decoded, err = decoder.Decode([]byte{0xf0, 0x9f, 0x90, 0xb8, 0xf0, 0x9f, 0x90, 0xb9})
		assert.Nil(t, err)
		assert.Equal(t, []byte{65, 66}, decoded)

		// Test binary data
		decoded, err = decoder.Decode([]byte{0xf0, 0x9f, 0x8f, 0xb7, 0xf0, 0x9f, 0x8f, 0xb8, 0xf0, 0x9f, 0x8f, 0xb9, 0xf0, 0x9f, 0x8f, 0xba})
		assert.Nil(t, err)
		assert.Equal(t, []byte{0x00, 0x01, 0x02, 0x03}, decoded)
	})

	t.Run("decode all zeros", func(t *testing.T) {
		decoder := NewStdDecoder()
		encoded := []byte{0xf0, 0x9f, 0x8f, 0xb7, 0xf0, 0x9f, 0x8f, 0xb8, 0xf0, 0x9f, 0x8f, 0xb9, 0xf0, 0x9f, 0x8f, 0xba}
		decoded, err := decoder.Decode(encoded)
		assert.Nil(t, err)
		assert.Equal(t, []byte{0x00, 0x01, 0x02, 0x03}, decoded)
	})

	t.Run("decode unicode string", func(t *testing.T) {
		decoder := NewStdDecoder()
		encoded := []byte{
			0xf0, 0x9f, 0x93, 0x9b, // 0xe4
			0xf0, 0x9f, 0x92, 0xb4, // 0xbd
			0xf0, 0x9f, 0x92, 0x97, // 0xa0
			0xf0, 0x9f, 0x93, 0x9c, // 0xe5
			0xf0, 0x9f, 0x92, 0x9c, // 0xa5
			0xf0, 0x9f, 0x92, 0xb4, // 0xbd
			0xf0, 0x9f, 0x93, 0x9b, // 0xe4
			0xf0, 0x9f, 0x92, 0xaf, // 0xb8
			0xf0, 0x9f, 0x92, 0x8d, // 0x96
			0xf0, 0x9f, 0x93, 0x9e, // 0xe7
			0xf0, 0x9f, 0x92, 0x8c, // 0x95
			0xf0, 0x9f, 0x92, 0x83, // 0x8c
		}
		decoded, err := decoder.Decode(encoded)
		assert.Nil(t, err)
		assert.Equal(t, []byte("你好世界"), decoded)
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
		expected := []byte{
			0xf0, 0x9f, 0x91, 0x9f, // h
			0xf0, 0x9f, 0x91, 0x9c, // e
			0xf0, 0x9f, 0x91, 0xa3, // l
			0xf0, 0x9f, 0x91, 0xa3, // l
			0xf0, 0x9f, 0x91, 0xa6, // o
			0xf0, 0x9f, 0x90, 0x97, // space
			0xf0, 0x9f, 0x91, 0xae, // w
			0xf0, 0x9f, 0x91, 0xa6, // o
			0xf0, 0x9f, 0x91, 0xa9, // r
			0xf0, 0x9f, 0x91, 0xa3, // l
			0xf0, 0x9f, 0x91, 0x9b, // d
		}
		assert.Equal(t, expected, buf.Bytes())
	})

	t.Run("write with existing error", func(t *testing.T) {
		var buf bytes.Buffer
		streamEncoder := NewStreamEncoder(&buf).(*StreamEncoder)
		streamEncoder.Error = assert.AnError

		n, err := streamEncoder.Write([]byte{65})
		assert.Equal(t, 0, n)
		assert.Error(t, err)
		assert.Equal(t, assert.AnError, err)
	})

	t.Run("write empty data", func(t *testing.T) {
		var buf bytes.Buffer
		encoder := NewStreamEncoder(&buf)
		var data []byte
		n, err := encoder.Write(data)
		assert.Equal(t, 0, n)
		assert.Nil(t, err)
		assert.Empty(t, encoder.(*StreamEncoder).buffer)
	})
}

func TestStreamEncoder_Close(t *testing.T) {
	t.Run("close with data", func(t *testing.T) {
		var buf bytes.Buffer
		encoder := NewStreamEncoder(&buf)
		encoder.Write([]byte("hello world"))

		err := encoder.Close()
		assert.NoError(t, err)
		expected := []byte{
			0xf0, 0x9f, 0x91, 0x9f, // h
			0xf0, 0x9f, 0x91, 0x9c, // e
			0xf0, 0x9f, 0x91, 0xa3, // l
			0xf0, 0x9f, 0x91, 0xa3, // l
			0xf0, 0x9f, 0x91, 0xa6, // o
			0xf0, 0x9f, 0x90, 0x97, // space
			0xf0, 0x9f, 0x91, 0xae, // w
			0xf0, 0x9f, 0x91, 0xa6, // o
			0xf0, 0x9f, 0x91, 0xa9, // r
			0xf0, 0x9f, 0x91, 0xa3, // l
			0xf0, 0x9f, 0x91, 0x9b, // d
		}
		assert.Equal(t, expected, buf.Bytes())
	})

	t.Run("close without data", func(t *testing.T) {
		var buf bytes.Buffer
		encoder := NewStreamEncoder(&buf)

		err := encoder.Close()
		assert.NoError(t, err)
		assert.Empty(t, buf.String())
	})

	t.Run("close with existing error", func(t *testing.T) {
		var buf bytes.Buffer
		streamEncoder := NewStreamEncoder(&buf).(*StreamEncoder)
		streamEncoder.Error = assert.AnError

		err := streamEncoder.Close()
		assert.Error(t, err)
		assert.Equal(t, assert.AnError, err)
	})
}

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
		assert.Equal(t, 5, n)
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
		assert.Equal(t, 11, n)
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
		assert.Equal(t, 6, n2) // " world"
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

func TestStdError(t *testing.T) {
	t.Run("decode invalid length", func(t *testing.T) {
		decoder := NewStdDecoder()
		result, err := decoder.Decode([]byte{0xf0, 0x9f, 0x90, 0xb8, 0xf0}) // 5 bytes, not divisible by 4
		assert.Nil(t, result)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid length")
	})

	t.Run("decode invalid first byte", func(t *testing.T) {
		decoder := NewStdDecoder()
		result, err := decoder.Decode([]byte{0xf1, 0x9f, 0x90, 0xb8}) // Wrong first byte
		assert.Nil(t, result)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "illegal data")
	})

	t.Run("decode invalid second byte", func(t *testing.T) {
		decoder := NewStdDecoder()
		result, err := decoder.Decode([]byte{0xf0, 0x9e, 0x90, 0xb8}) // Wrong second byte
		assert.Nil(t, result)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "illegal data")
	})

	t.Run("encoder with error", func(t *testing.T) {
		encoder := NewStdEncoder()
		encoder.Error = assert.AnError
		result := encoder.Encode([]byte{65})
		assert.Nil(t, result)
	})

	t.Run("decoder with error", func(t *testing.T) {
		decoder := NewStdDecoder()
		decoder.Error = assert.AnError
		result, err := decoder.Decode([]byte{0xf0, 0x9f, 0x90, 0xb8})
		assert.Nil(t, result)
		assert.Error(t, err)
		assert.Equal(t, assert.AnError, err)
	})

	t.Run("invalid length error message", func(t *testing.T) {
		err := InvalidLengthError(7)
		expected := "coding/base100: invalid length, data length must be divisible by 4, got 7"
		assert.Equal(t, expected, err.Error())
	})

	t.Run("corrupt input error message", func(t *testing.T) {
		err := CorruptInputError(42)
		expected := "coding/base100: illegal data at input byte 42"
		assert.Equal(t, expected, err.Error())
	})
}

func TestStreamError(t *testing.T) {
	t.Run("stream encoder close with writer error", func(t *testing.T) {
		errorWriter := mock.NewErrorWriteCloser(assert.AnError)
		encoder := NewStreamEncoder(errorWriter)
		_, err := encoder.Write([]byte("test"))
		assert.NoError(t, err)

		err = encoder.Close()
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
		file := mock.NewFile([]byte("invalid!"), "test.txt")
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

	t.Run("read with existing error", func(t *testing.T) {
		file := mock.NewFile([]byte{}, "test.txt")
		streamDecoder := NewStreamDecoder(file).(*StreamDecoder)
		streamDecoder.Error = assert.AnError

		buf := make([]byte, 10)
		n, err := streamDecoder.Read(buf)
		assert.Equal(t, 0, n)
		assert.Error(t, err)
		assert.Equal(t, assert.AnError, err)
	})
}

// Test legacy functions for backward compatibility
func TestLegacyFunctions(t *testing.T) {
	t.Run("legacy encode", func(t *testing.T) {
		original := []byte("hello world")
		encoded := Encode(original)
		expected := []byte{
			0xf0, 0x9f, 0x91, 0x9f, // h
			0xf0, 0x9f, 0x91, 0x9c, // e
			0xf0, 0x9f, 0x91, 0xa3, // l
			0xf0, 0x9f, 0x91, 0xa3, // l
			0xf0, 0x9f, 0x91, 0xa6, // o
			0xf0, 0x9f, 0x90, 0x97, // space
			0xf0, 0x9f, 0x91, 0xae, // w
			0xf0, 0x9f, 0x91, 0xa6, // o
			0xf0, 0x9f, 0x91, 0xa9, // r
			0xf0, 0x9f, 0x91, 0xa3, // l
			0xf0, 0x9f, 0x91, 0x9b, // d
		}
		assert.Equal(t, expected, encoded)
	})

	t.Run("legacy decode", func(t *testing.T) {
		encoded := []byte{
			0xf0, 0x9f, 0x91, 0x9f, // h
			0xf0, 0x9f, 0x91, 0x9c, // e
			0xf0, 0x9f, 0x91, 0xa3, // l
			0xf0, 0x9f, 0x91, 0xa3, // l
			0xf0, 0x9f, 0x91, 0xa6, // o
			0xf0, 0x9f, 0x90, 0x97, // space
			0xf0, 0x9f, 0x91, 0xae, // w
			0xf0, 0x9f, 0x91, 0xa6, // o
			0xf0, 0x9f, 0x91, 0xa9, // r
			0xf0, 0x9f, 0x91, 0xa3, // l
			0xf0, 0x9f, 0x91, 0x9b, // d
		}
		decoded, err := Decode(encoded)
		assert.Nil(t, err)
		assert.Equal(t, []byte("hello world"), decoded)
	})

	t.Run("legacy decode with error", func(t *testing.T) {
		encoded := []byte{0xf0, 0x9f, 0x90, 0xb8, 0xf0} // Invalid length
		decoded, err := Decode(encoded)
		assert.Nil(t, decoded)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid length")
	})
}
