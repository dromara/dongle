package base91

import (
	"bytes"
	"errors"
	"io"
	"testing"

	"gitee.com/golang-package/dongle/mock"
	"github.com/stretchr/testify/assert"
)

// TestStdEncoder_Encode tests standard base91 encoding scenarios.
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
		assert.Equal(t, []byte("TPwJh>Io2Tv!lE"), encoded)
		assert.Nil(t, encoder.Error)
	})

	t.Run("encode with different byte counts", func(t *testing.T) {
		encoder := NewStdEncoder()

		// Test single byte
		encoded := encoder.Encode([]byte{42})
		assert.Equal(t, []byte("qA"), encoded)
		assert.Nil(t, encoder.Error)

		// Test two bytes
		encoded = encoder.Encode([]byte{42, 43})
		assert.Equal(t, []byte("lfB"), encoded)
		assert.Nil(t, encoder.Error)

		// Test three bytes
		encoded = encoder.Encode([]byte{42, 43, 44})
		assert.Equal(t, []byte("lf@D"), encoded)
		assert.Nil(t, encoder.Error)

		// Test four bytes
		encoded = encoder.Encode([]byte{42, 43, 44, 45})
		assert.Equal(t, []byte("lfjaL"), encoded)
		assert.Nil(t, encoder.Error)

		// Test five bytes
		encoded = encoder.Encode([]byte{42, 43, 44, 45, 46})
		assert.Equal(t, []byte("lfjargA"), encoded)
		assert.Nil(t, encoder.Error)
	})

	t.Run("encode all zeros", func(t *testing.T) {
		encoder := NewStdEncoder()
		original := []byte{0x00, 0x01, 0x02, 0x03}
		encoded := encoder.Encode(original)
		assert.Equal(t, []byte(":C#(A"), encoded)
		assert.Nil(t, encoder.Error)
	})

	t.Run("encode unicode string", func(t *testing.T) {
		encoder := NewStdEncoder()
		original := []byte("你好世界")
		encoded := encoder.Encode(original)
		assert.Equal(t, []byte("I_5k7a9aug!32zR"), encoded)
		assert.Nil(t, encoder.Error)
	})

	t.Run("encode binary data", func(t *testing.T) {
		encoder := NewStdEncoder()
		original := []byte{0xFF, 0xFE, 0xFD, 0xFC, 0xFB, 0xFA}
		encoded := encoder.Encode(original)
		assert.Equal(t, []byte("S|dWS|uF"), encoded)
		assert.Nil(t, encoder.Error)
	})

	t.Run("encode large data", func(t *testing.T) {
		encoder := NewStdEncoder()
		original := bytes.Repeat([]byte("Hello, World! "), 100)
		encoded := encoder.Encode(original)
		assert.Equal(t, []byte(">OwJh>}AQ;r@@Y?F"), encoded[:16])
		assert.Nil(t, encoder.Error)
	})

	t.Run("encode with leading zeros", func(t *testing.T) {
		encoder := NewStdEncoder()
		input := []byte{0x00, 0x00, 0x01, 0x02, 0x03}
		result := encoder.Encode(input)
		assert.Equal(t, []byte("AAyWFB"), result)
		assert.Nil(t, encoder.Error)
	})
}

// TestStdDecoder_Decode tests standard base91 decoding scenarios.
func TestStdDecoder_Decode(t *testing.T) {
	t.Run("decode empty input", func(t *testing.T) {
		decoder := NewStdDecoder()
		result, err := decoder.Decode([]byte{})
		assert.Nil(t, result)
		assert.Nil(t, err)
	})

	t.Run("decode simple string", func(t *testing.T) {
		decoder := NewStdDecoder()
		encoded := []byte("TPwJh>Io2Tv!lE")
		decoded, err := decoder.Decode(encoded)
		assert.Nil(t, err)
		assert.Equal(t, []byte("hello world"), decoded)
	})

	t.Run("decode with different byte counts", func(t *testing.T) {
		decoder := NewStdDecoder()

		// Test single byte
		decoded, err := decoder.Decode([]byte("qA"))
		assert.Nil(t, err)
		assert.Equal(t, []byte{42}, decoded)

		// Test two bytes
		decoded, err = decoder.Decode([]byte("lfB"))
		assert.Nil(t, err)
		assert.Equal(t, []byte{42, 43}, decoded)

		// Test three bytes
		decoded, err = decoder.Decode([]byte("lf@D"))
		assert.Nil(t, err)
		assert.Equal(t, []byte{42, 43, 44}, decoded)

		// Test four bytes
		decoded, err = decoder.Decode([]byte("lfjaL"))
		assert.Nil(t, err)
		assert.Equal(t, []byte{42, 43, 44, 45}, decoded)

		// Test five bytes
		decoded, err = decoder.Decode([]byte("lfjargA"))
		assert.Nil(t, err)
		assert.Equal(t, []byte{42, 43, 44, 45, 46}, decoded)
	})

	t.Run("decode all zeros", func(t *testing.T) {
		decoder := NewStdDecoder()
		encoded := []byte(":C#(A")
		decoded, err := decoder.Decode(encoded)
		assert.Nil(t, err)
		assert.Equal(t, []byte{0x00, 0x01, 0x02, 0x03}, decoded)
	})

	t.Run("decode unicode string", func(t *testing.T) {
		decoder := NewStdDecoder()
		encoded := []byte("I_5k7a9aug!32zR")
		decoded, err := decoder.Decode(encoded)
		assert.Nil(t, err)
		assert.Equal(t, []byte("你好世界"), decoded)
	})

	t.Run("decode binary data", func(t *testing.T) {
		decoder := NewStdDecoder()
		encoded := []byte("S|dWS|uF")
		decoded, err := decoder.Decode(encoded)
		assert.Nil(t, err)
		assert.Equal(t, []byte{0xFF, 0xFE, 0xFD, 0xFC, 0xFB, 0xFA}, decoded)
	})

	t.Run("decode with leading zeros", func(t *testing.T) {
		decoder := NewStdDecoder()
		encoded := []byte("AAyWFB")
		decoded, err := decoder.Decode(encoded)
		assert.Nil(t, err)
		assert.Equal(t, []byte{0x00, 0x00, 0x01, 0x02, 0x03}, decoded)
	})
}

// TestStreamEncoder_Write tests writing to the stream encoder.
func TestStreamEncoder_Write(t *testing.T) {
	t.Run("write data", func(t *testing.T) {
		var buf bytes.Buffer
		encoder := NewStreamEncoder(&buf).(*StreamEncoder)

		data := []byte("hello")
		n, err := encoder.Write(data)

		assert.Equal(t, 5, n)
		assert.Nil(t, err)
		assert.Equal(t, data, encoder.buffer)
	})

	t.Run("write multiple times", func(t *testing.T) {
		var buf bytes.Buffer
		encoder := NewStreamEncoder(&buf).(*StreamEncoder)

		data1 := []byte("hello")
		data2 := []byte(" world")

		n1, err1 := encoder.Write(data1)
		n2, err2 := encoder.Write(data2)

		assert.Equal(t, 5, n1)
		assert.Nil(t, err1)
		assert.Equal(t, 6, n2)
		assert.Nil(t, err2)
		assert.Equal(t, []byte("hello world"), encoder.buffer)
	})

	t.Run("write with existing error", func(t *testing.T) {
		encoder := &StreamEncoder{Error: errors.New("test error")}
		data := []byte("hello")
		n, err := encoder.Write(data)
		assert.Equal(t, 0, n)
		assert.Error(t, err)
		assert.Equal(t, "test error", err.Error())
	})

	t.Run("write empty data", func(t *testing.T) {
		var buf bytes.Buffer
		encoder := NewStreamEncoder(&buf).(*StreamEncoder)
		var data []byte
		n, err := encoder.Write(data)
		assert.Equal(t, 0, n)
		assert.Nil(t, err)
		assert.Empty(t, encoder.buffer)
	})
}

// TestStreamEncoder_Close tests closing the stream encoder.
func TestStreamEncoder_Close(t *testing.T) {
	t.Run("close with data", func(t *testing.T) {
		var buf bytes.Buffer
		encoder := NewStreamEncoder(&buf).(*StreamEncoder)

		// Write some data
		encoder.Write([]byte("hello"))

		// Close should encode and write the data
		err := encoder.Close()
		assert.Nil(t, err)

		// Check that data was encoded and written
		expected := "TPwJh>A" // "hello" encoded with base91
		assert.Equal(t, expected, buf.String())
	})

	t.Run("close without data", func(t *testing.T) {
		var buf bytes.Buffer
		encoder := NewStreamEncoder(&buf).(*StreamEncoder)

		err := encoder.Close()
		assert.Nil(t, err)
		assert.Empty(t, buf.String())
	})

	t.Run("close with existing error", func(t *testing.T) {
		encoder := &StreamEncoder{Error: errors.New("test error")}
		err := encoder.Close()
		assert.Error(t, err)
		assert.Equal(t, "test error", err.Error())
	})

	t.Run("close with write error", func(t *testing.T) {
		errorWriter := mock.NewErrorWriteCloser(errors.New("write error"))
		encoder := NewStreamEncoder(errorWriter).(*StreamEncoder)
		encoder.Write([]byte("hello"))
		err := encoder.Close()
		assert.Error(t, err)
		assert.Equal(t, "write error", err.Error())
	})
}

// TestStreamDecoder_Read tests reading from the stream decoder.
func TestStreamDecoder_Read(t *testing.T) {
	t.Run("read from buffer", func(t *testing.T) {
		decoder := &StreamDecoder{
			buffer: []byte("hello"),
			pos:    0,
		}

		buf := make([]byte, 3)
		n, err := decoder.Read(buf)

		assert.Equal(t, 3, n)
		assert.Nil(t, err)
		assert.Equal(t, []byte("hel"), buf)
		assert.Equal(t, 3, decoder.pos)
	})

	t.Run("read from reader", func(t *testing.T) {
		// Create encoded data
		encoded := "TPwJh>A" // "hello" encoded
		file := mock.NewFile([]byte(encoded), "test.txt")
		decoder := NewStreamDecoder(file).(*StreamDecoder)

		buf := make([]byte, 10)
		n, err := decoder.Read(buf)

		assert.Equal(t, 5, n)
		assert.Nil(t, err)
		assert.Equal(t, []byte("hello"), buf[:n])
	})

	t.Run("read with partial buffer", func(t *testing.T) {
		encoded := "TPwJh>A"
		file := mock.NewFile([]byte(encoded), "test.txt")
		decoder := NewStreamDecoder(file).(*StreamDecoder)

		buf := make([]byte, 3)
		n, err := decoder.Read(buf)

		assert.Equal(t, 3, n)
		assert.Nil(t, err)
		assert.Equal(t, []byte("hel"), buf)

		// Read remaining data
		n2, err2 := decoder.Read(buf)
		assert.Equal(t, 2, n2)
		assert.Nil(t, err2)
		assert.Equal(t, []byte("lo"), buf[:n2])
	})

	t.Run("read from empty reader", func(t *testing.T) {
		file := mock.NewFile([]byte{}, "test.txt")
		decoder := NewStreamDecoder(file).(*StreamDecoder)

		buf := make([]byte, 10)
		n, err := decoder.Read(buf)

		assert.Equal(t, 0, n)
		assert.Equal(t, io.EOF, err)
	})

	t.Run("read with existing error", func(t *testing.T) {
		decoder := &StreamDecoder{Error: errors.New("test error")}
		buf := make([]byte, 10)
		n, err := decoder.Read(buf)
		assert.Equal(t, 0, n)
		assert.Error(t, err)
		assert.Equal(t, "test error", err.Error())
	})

	t.Run("read with no complete groups", func(t *testing.T) {
		file := mock.NewFile([]byte("AB"), "test.txt")
		decoder := NewStreamDecoder(file).(*StreamDecoder)
		buf := make([]byte, 10)
		n, err := decoder.Read(buf)
		assert.Equal(t, 1, n) // base91 decoder processes what it can
		assert.Nil(t, err)
	})

	t.Run("read with EOF and no data", func(t *testing.T) {
		file := mock.NewFile([]byte{}, "test.txt")
		decoder := NewStreamDecoder(file).(*StreamDecoder)

		buf := make([]byte, 10)
		n, err := decoder.Read(buf)
		assert.Equal(t, io.EOF, err)
		assert.Equal(t, 0, n)
	})

	t.Run("read with EOF and remaining data", func(t *testing.T) {
		file := mock.NewFile([]byte("TPwJh>Io2Tv!lE"), "test.txt")
		decoder := NewStreamDecoder(file).(*StreamDecoder)

		buf := make([]byte, 10)
		n, err := decoder.Read(buf)
		assert.Equal(t, 10, n) // Buffer size limits the read
		assert.Nil(t, err)
	})

	t.Run("read with buffer position at end", func(t *testing.T) {
		file := mock.NewFile([]byte("TPwJh>Io2Tv!lE"), "test.txt")
		decoder := NewStreamDecoder(file).(*StreamDecoder)
		decoder.buffer = []byte("hello world")
		decoder.pos = 11 // At the end of buffer

		buf := make([]byte, 10)
		n, err := decoder.Read(buf)
		assert.Equal(t, 10, n) // Actually reads from reader since buffer is empty
		assert.Nil(t, err)
	})
}

// TestStdError tests standard base91 error scenarios.
func TestStdError(t *testing.T) {
	t.Run("decode invalid character", func(t *testing.T) {
		decoder := NewStdDecoder()
		result, err := decoder.Decode([]byte("ABC DEF"))
		assert.Nil(t, result)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "base91: illegal data at input byte")
	})

	t.Run("encoder invalid alphabet", func(t *testing.T) {
		encoder := &StdEncoder{alphabet: "invalid"}
		result := encoder.Encode([]byte("hello"))
		assert.NotNil(t, result) // base91 encoder doesn't validate alphabet length
		assert.Nil(t, encoder.Error)
	})

	t.Run("decoder invalid alphabet", func(t *testing.T) {
		decoder := &StdDecoder{alphabet: "invalid"}
		result, err := decoder.Decode([]byte("ABC"))
		assert.NotNil(t, result) // base91 decoder doesn't validate alphabet length
		assert.Nil(t, err)
	})

	t.Run("corrupt input error message", func(t *testing.T) {
		err := CorruptInputError(5)
		expected := "coding/base91: illegal data at input byte 5"
		assert.Equal(t, expected, err.Error())
	})

	t.Run("alphabet size error message", func(t *testing.T) {
		err := AlphabetSizeError(50)
		expected := "coding/base91: invalid alphabet, the alphabet length must be 91, got 50"
		assert.Equal(t, expected, err.Error())
	})
}

// TestStreamError tests stream base91 error scenarios.
func TestStreamError(t *testing.T) {
	t.Run("stream encoder close with writer error", func(t *testing.T) {
		errorWriter := mock.NewErrorWriteCloser(errors.New("write error"))
		encoder := NewStreamEncoder(errorWriter).(*StreamEncoder)

		encoder.Write([]byte("hello"))
		err := encoder.Close()
		assert.Error(t, err)
		assert.Equal(t, "write error", err.Error())
	})

	t.Run("stream decoder with reader error", func(t *testing.T) {
		errorReader := mock.NewErrorFile(errors.New("read error"))
		decoder := NewStreamDecoder(errorReader).(*StreamDecoder)

		buf := make([]byte, 10)
		n, err := decoder.Read(buf)
		assert.Equal(t, 0, n)
		assert.Error(t, err)
		assert.Equal(t, "read error", err.Error())
	})

	t.Run("stream decoder with decode error", func(t *testing.T) {
		file := mock.NewFile([]byte("ABC DEF"), "test.txt")
		decoder := NewStreamDecoder(file).(*StreamDecoder)

		buf := make([]byte, 10)
		n, err := decoder.Read(buf)
		assert.Equal(t, 0, n)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "base91: illegal data at input byte")
	})

	t.Run("stream decoder with mock error reader", func(t *testing.T) {
		errorReader := mock.NewErrorFile(errors.New("mock error"))
		decoder := NewStreamDecoder(errorReader).(*StreamDecoder)

		buf := make([]byte, 10)
		n, err := decoder.Read(buf)
		assert.Equal(t, 0, n)
		assert.Error(t, err)
		assert.Equal(t, "mock error", err.Error())
	})

	t.Run("read with invalid data", func(t *testing.T) {
		file := mock.NewFile([]byte("invalid@"), "test.txt")
		decoder := NewStreamDecoder(file).(*StreamDecoder)

		buf := make([]byte, 10)
		n, err := decoder.Read(buf)
		assert.Equal(t, 6, n) // base91 decoder processes valid characters
		assert.Nil(t, err)
	})
}
