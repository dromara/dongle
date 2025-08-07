package hex

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
		// Python: "hello world".encode().hex() = "68656c6c6f20776f726c64"
		assert.Equal(t, []byte("68656c6c6f20776f726c64"), encoded)
		assert.Nil(t, encoder.Error)
	})

	t.Run("encode with different byte counts", func(t *testing.T) {
		encoder := NewStdEncoder()

		// Test single byte
		encoded := encoder.Encode([]byte{0x41})
		// Python: bytes([0x41]).hex() = "41"
		assert.Equal(t, []byte("41"), encoded)
		assert.Nil(t, encoder.Error)

		// Test two bytes
		encoded = encoder.Encode([]byte{0x41, 0x42})
		// Python: bytes([0x41, 0x42]).hex() = "4142"
		assert.Equal(t, []byte("4142"), encoded)
		assert.Nil(t, encoder.Error)

		// Test three bytes
		encoded = encoder.Encode([]byte{0x41, 0x42, 0x43})
		// Python: bytes([0x41, 0x42, 0x43]).hex() = "414243"
		assert.Equal(t, []byte("414243"), encoded)
		assert.Nil(t, encoder.Error)

		// Test four bytes
		encoded = encoder.Encode([]byte{0x41, 0x42, 0x43, 0x44})
		// Python: bytes([0x41, 0x42, 0x43, 0x44]).hex() = "41424344"
		assert.Equal(t, []byte("41424344"), encoded)
		assert.Nil(t, encoder.Error)

		// Test five bytes
		encoded = encoder.Encode([]byte{0x41, 0x42, 0x43, 0x44, 0x45})
		// Python: bytes([0x41, 0x42, 0x43, 0x44, 0x45]).hex() = "4142434445"
		assert.Equal(t, []byte("4142434445"), encoded)
		assert.Nil(t, encoder.Error)
	})

	t.Run("encode all zeros", func(t *testing.T) {
		encoder := NewStdEncoder()
		original := []byte{0x00, 0x01, 0x02, 0x03}
		encoded := encoder.Encode(original)
		// Python: bytes([0x00, 0x01, 0x02, 0x03]).hex() = "00010203"
		assert.Equal(t, []byte("00010203"), encoded)
		assert.Nil(t, encoder.Error)
	})

	t.Run("encode unicode string", func(t *testing.T) {
		encoder := NewStdEncoder()
		original := []byte("你好世界")
		encoded := encoder.Encode(original)
		// Python: "你好世界".encode('utf-8').hex() = "e4bda0e5a5bde4b896e7958c"
		assert.Equal(t, []byte("e4bda0e5a5bde4b896e7958c"), encoded)
		assert.Nil(t, encoder.Error)
	})

	t.Run("encode binary data", func(t *testing.T) {
		encoder := NewStdEncoder()
		original := []byte{0xFF, 0xFE, 0xFD, 0xFC, 0xFB, 0xFA}
		encoded := encoder.Encode(original)
		// Python: bytes([0xFF, 0xFE, 0xFD, 0xFC, 0xFB, 0xFA]).hex() = "fffefdfcfbfa"
		assert.Equal(t, []byte("fffefdfcfbfa"), encoded)
		assert.Nil(t, encoder.Error)
	})

	t.Run("encode large data", func(t *testing.T) {
		encoder := NewStdEncoder()
		original := bytes.Repeat([]byte("Hello, World! "), 100)
		encoded := encoder.Encode(original)
		// Python: (b"Hello, World! " * 100).hex()
		expected := bytes.Repeat([]byte("48656c6c6f2c20576f726c642120"), 100)
		assert.Equal(t, expected, encoded)
		assert.Nil(t, encoder.Error)
	})

	t.Run("encode with leading zeros", func(t *testing.T) {
		encoder := NewStdEncoder()
		input := []byte{0x00, 0x00, 0x01, 0x02, 0x03}
		result := encoder.Encode(input)
		// Python: bytes([0x00, 0x00, 0x01, 0x02, 0x03]).hex() = "0000010203"
		assert.Equal(t, []byte("0000010203"), result)
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
		encoded := []byte("68656c6c6f20776f726c64")
		decoded, err := decoder.Decode(encoded)
		assert.Nil(t, err)
		assert.Equal(t, []byte("hello world"), decoded)
	})

	t.Run("decode with different byte counts", func(t *testing.T) {
		decoder := NewStdDecoder()

		// Test single byte
		decoded, err := decoder.Decode([]byte("41"))
		assert.Nil(t, err)
		assert.Equal(t, []byte{0x41}, decoded)

		// Test two bytes
		decoded, err = decoder.Decode([]byte("4142"))
		assert.Nil(t, err)
		assert.Equal(t, []byte{0x41, 0x42}, decoded)

		// Test binary data
		decoded, err = decoder.Decode([]byte("00010203"))
		assert.Nil(t, err)
		assert.Equal(t, []byte{0x00, 0x01, 0x02, 0x03}, decoded)
	})

	t.Run("decode all zeros", func(t *testing.T) {
		decoder := NewStdDecoder()
		encoded := []byte("00010203")
		decoded, err := decoder.Decode(encoded)
		assert.Nil(t, err)
		assert.Equal(t, []byte{0x00, 0x01, 0x02, 0x03}, decoded)
	})

	t.Run("decode unicode string", func(t *testing.T) {
		decoder := NewStdDecoder()
		encoded := []byte("e4bda0e5a5bde4b896e7958c")
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

	t.Run("decode with uppercase", func(t *testing.T) {
		decoder := NewStdDecoder()
		encoded := []byte("48656C6C6F")
		decoded, err := decoder.Decode(encoded)
		assert.Nil(t, err)
		assert.Equal(t, []byte("Hello"), decoded)
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
		assert.Equal(t, "68656c6c6f20776f726c64", buf.String())
	})
}

func TestStreamEncoder_Close(t *testing.T) {
	t.Run("close with data", func(t *testing.T) {
		var buf bytes.Buffer
		encoder := NewStreamEncoder(&buf)
		encoder.Write([]byte("hello world"))

		err := encoder.Close()
		assert.NoError(t, err)
		assert.Equal(t, "68656c6c6f20776f726c64", buf.String())
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

	t.Run("read hex data", func(t *testing.T) {
		var encodeBuf bytes.Buffer
		encoder := NewStreamEncoder(&encodeBuf)
		encoder.Write([]byte("hello world"))
		encoder.Close()

		reader := bytes.NewReader(encodeBuf.Bytes())
		decoder := NewStreamDecoder(reader)

		buf := make([]byte, 20)
		n, err := decoder.Read(buf)
		assert.NoError(t, err)
		assert.Equal(t, 11, n)
		assert.Equal(t, []byte("hello world"), buf[:n])
	})
}

func TestStdError(t *testing.T) {
	t.Run("decode invalid character", func(t *testing.T) {
		decoder := NewStdDecoder()
		result, err := decoder.Decode([]byte("invalid!"))
		assert.Error(t, err)
		assert.Nil(t, result)
		assert.Contains(t, err.Error(), "invalid byte")
	})

	t.Run("decode odd length", func(t *testing.T) {
		decoder := NewStdDecoder()
		result, err := decoder.Decode([]byte("123"))
		assert.Error(t, err)
		assert.Nil(t, result)
		assert.Contains(t, err.Error(), "odd length hex string")
	})

	t.Run("decode invalid hex characters", func(t *testing.T) {
		decoder := NewStdDecoder()
		result, err := decoder.Decode([]byte("gg"))
		assert.Error(t, err)
		assert.Nil(t, result)
	})

	t.Run("corrupt input error message", func(t *testing.T) {
		err := CorruptInputError(5)
		expected := "coding/hex: illegal data at input byte 5"
		assert.Equal(t, expected, err.Error())
	})

	t.Run("alphabet size error message", func(t *testing.T) {
		err := AlphabetSizeError(10)
		expected := "coding/hex: invalid alphabet, the alphabet length must be 16, got 10"
		assert.Equal(t, expected, err.Error())
	})
}

func TestStreamError(t *testing.T) {
	t.Run("stream encoder write with writer error", func(t *testing.T) {
		errorWriter := mock.NewErrorWriteCloser(assert.AnError)
		encoder := NewStreamEncoder(errorWriter)
		_, err := encoder.Write([]byte("test"))
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

	t.Run("stream encoder with error state", func(t *testing.T) {
		var buf bytes.Buffer
		encoder := NewStreamEncoder(&buf).(*StreamEncoder)
		encoder.Error = io.ErrShortWrite

		n, err := encoder.Write([]byte("hello"))
		assert.Equal(t, 0, n)
		assert.Equal(t, io.ErrShortWrite, err)
	})

	t.Run("stream decoder with error state", func(t *testing.T) {
		reader := bytes.NewReader([]byte("68656c6c6f"))
		decoder := NewStreamDecoder(reader).(*StreamDecoder)
		decoder.Error = io.ErrUnexpectedEOF

		buf := make([]byte, 10)
		n, err := decoder.Read(buf)
		assert.Equal(t, 0, n)
		assert.Equal(t, io.ErrUnexpectedEOF, err)
	})
}
