package base62

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"

	"gitee.com/golang-package/dongle/mock"
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
		original := []byte("hello")
		encoded := encoder.Encode(original)
		assert.Equal(t, []byte("7tQLFHz"), encoded)
		assert.Nil(t, encoder.Error)
	})

	t.Run("encode with different byte counts", func(t *testing.T) {
		encoder := NewStdEncoder()

		// Test single byte
		encoded := encoder.Encode([]byte{42})
		assert.Equal(t, []byte("g"), encoded)
		assert.Nil(t, encoder.Error)

		// Test two bytes
		encoded = encoder.Encode([]byte{42, 43})
		assert.Equal(t, []byte("2o7"), encoded)
		assert.Nil(t, encoder.Error)

		// Test three bytes
		encoded = encoder.Encode([]byte{42, 43, 44})
		assert.Equal(t, []byte("Bavc"), encoded)
		assert.Nil(t, encoder.Error)

		// Test four bytes
		encoded = encoder.Encode([]byte{42, 43, 44, 45})
		assert.Equal(t, []byte("lsTtd"), encoded)
		assert.Nil(t, encoder.Error)

		// Test five bytes
		encoded = encoder.Encode([]byte{42, 43, 44, 45, 46})
		assert.Equal(t, []byte("3BgxRhm"), encoded)
		assert.Nil(t, encoder.Error)
	})

	t.Run("encode all zeros", func(t *testing.T) {
		encoder := NewStdEncoder()
		original := []byte{0, 0, 0, 0}
		encoded := encoder.Encode(original)
		assert.Equal(t, []byte("04"), encoded)
		assert.Nil(t, encoder.Error)
	})

	t.Run("encode unicode string", func(t *testing.T) {
		encoder := NewStdEncoder()
		original := []byte("Hello, World! 你好世界")
		encoded := encoder.Encode(original)
		assert.Equal(t, []byte("DJdU1U1C8QwwO2iB68s67XuSfeVG1WDn5au"), encoded)
		assert.Nil(t, encoder.Error)
	})

	t.Run("encode binary data", func(t *testing.T) {
		encoder := NewStdEncoder()
		original := []byte{0xFF, 0xFE, 0xFD, 0xFC, 0xFB, 0xFA}
		encoded := encoder.Encode(original)
		assert.Equal(t, []byte("1HvRoQIvq"), encoded)
		assert.Nil(t, encoder.Error)
	})

	t.Run("encode large data", func(t *testing.T) {
		encoder := NewStdEncoder()
		original := bytes.Repeat([]byte("Hello, World! "), 100)
		encoded := encoder.Encode(original)
		assert.NotEmpty(t, encoded)
		assert.Nil(t, encoder.Error)
	})

	t.Run("encode with leading zeros", func(t *testing.T) {
		encoder := NewStdEncoder()
		input := []byte{0x00, 0x00, 0x01, 0x02, 0x03}
		result := encoder.Encode(input)
		assert.Equal(t, []byte("02HBL"), result)
		assert.Nil(t, encoder.Error)
	})

	t.Run("write multiple times", func(t *testing.T) {
		var buf bytes.Buffer
		encoder := NewStreamEncoder(&buf)

		data1 := []byte("hello")
		data2 := []byte(" world")

		n1, err1 := encoder.Write(data1)
		n2, err2 := encoder.Write(data2)

		assert.Equal(t, 5, n1)
		assert.Nil(t, err1)
		assert.Equal(t, 6, n2)
		assert.Nil(t, err2)

		err := encoder.Close()
		assert.Nil(t, err)
		assert.Equal(t, "AAwf93rvy4aWQVw", buf.String())
	})

	t.Run("close with data success", func(t *testing.T) {
		var buf bytes.Buffer
		encoder := NewStreamEncoder(&buf)

		encoder.Write([]byte("test"))
		err := encoder.Close()

		assert.Nil(t, err)
		assert.Equal(t, "289lyu", buf.String())
	})

	t.Run("close with single byte", func(t *testing.T) {
		var buf bytes.Buffer
		encoder := NewStreamEncoder(&buf)

		encoder.Write([]byte("a"))
		err := encoder.Close()

		assert.Nil(t, err)
		assert.Equal(t, "1Z", buf.String())
	})

	t.Run("close with two bytes", func(t *testing.T) {
		var buf bytes.Buffer
		encoder := NewStreamEncoder(&buf)

		encoder.Write([]byte("ab"))
		err := encoder.Close()

		assert.Nil(t, err)
		assert.Equal(t, "6U6", buf.String())
	})

	t.Run("close with data", func(t *testing.T) {
		var buf bytes.Buffer
		encoder := NewStreamEncoder(&buf)

		encoder.Write([]byte("hello"))
		err := encoder.Close()

		assert.Nil(t, err)
		assert.Equal(t, "7tQLFHz", buf.String())
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
		encoded := []byte("7tQLFHz")
		decoded, err := decoder.Decode(encoded)
		assert.Nil(t, err)
		assert.Equal(t, []byte("hello"), decoded)
	})

	t.Run("decode with different byte counts", func(t *testing.T) {
		decoder := NewStdDecoder()

		// Test single byte
		encoded := []byte("g")
		decoded, err := decoder.Decode(encoded)
		assert.Nil(t, err)
		assert.Equal(t, []byte{42}, decoded)

		// Test two bytes
		encoded = []byte("2o7")
		decoded, err = decoder.Decode(encoded)
		assert.Nil(t, err)
		assert.Equal(t, []byte{42, 43}, decoded)

		// Test three bytes
		encoded = []byte("Bavc")
		decoded, err = decoder.Decode(encoded)
		assert.Nil(t, err)
		assert.Equal(t, []byte{42, 43, 44}, decoded)

		// Test four bytes
		encoded = []byte("lsTtd")
		decoded, err = decoder.Decode(encoded)
		assert.Nil(t, err)
		assert.Equal(t, []byte{42, 43, 44, 45}, decoded)

		// Test five bytes
		encoded = []byte("3BgxRhm")
		decoded, err = decoder.Decode(encoded)
		assert.Nil(t, err)
		assert.Equal(t, []byte{42, 43, 44, 45, 46}, decoded)
	})

	t.Run("decode all zeros", func(t *testing.T) {
		decoder := NewStdDecoder()
		encoded := []byte("04")
		decoded, err := decoder.Decode(encoded)
		assert.Nil(t, err)
		assert.Equal(t, []byte{0, 0, 0, 0}, decoded)
	})

	t.Run("decode unicode string", func(t *testing.T) {
		decoder := NewStdDecoder()
		encoded := []byte("DJdU1U1C8QwwO2iB68s67XuSfeVG1WDn5au")
		decoded, err := decoder.Decode(encoded)
		assert.Nil(t, err)
		assert.Equal(t, []byte("Hello, World! 你好世界"), decoded)
	})

	t.Run("decode binary data", func(t *testing.T) {
		decoder := NewStdDecoder()
		encoded := []byte("1HvRoQIvq")
		decoded, err := decoder.Decode(encoded)
		assert.Nil(t, err)
		assert.Equal(t, []byte{0xFF, 0xFE, 0xFD, 0xFC, 0xFB, 0xFA}, decoded)
	})

	t.Run("decode large data", func(t *testing.T) {
		decoder := NewStdDecoder()
		original := strings.Repeat("Hello, World! ", 100)
		encoder := NewStdEncoder()
		encoded := encoder.Encode([]byte(original))
		decoded, err := decoder.Decode(encoded)
		assert.Nil(t, err)
		assert.Equal(t, []byte(original), decoded)
	})

	t.Run("decode invalid leading zero character", func(t *testing.T) {
		decoder := NewStdDecoder()
		// Create input with invalid character that would result in val < 0
		result, err := decoder.Decode([]byte("!@#"))
		assert.Nil(t, result)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "illegal data")
	})

	t.Run("decode with leading zero and invalid character", func(t *testing.T) {
		decoder := NewStdDecoder()
		// Test with "0" followed by an invalid character (not in alphabet)
		result, err := decoder.Decode([]byte("0@"))
		assert.Nil(t, result)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "illegal data at input byte 1")
	})

	t.Run("decode with only leading zeros", func(t *testing.T) {
		decoder := NewStdDecoder()
		// Test with only leading zeros pattern
		result, err := decoder.Decode([]byte("0A"))
		assert.Nil(t, err)
		assert.Equal(t, []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, result)
	})

	t.Run("decode with unicode character > 255", func(t *testing.T) {
		decoder := NewStdDecoder()
		// Create input with unicode character > 255
		unicodeInput := []byte("ABC")
		unicodeInput[1] = 0xFF                          // This will be replaced with a unicode character
		unicodeInput = append(unicodeInput, 0xC3, 0xBF) // UTF-8 for ÿ (255)
		result, err := decoder.Decode(unicodeInput)
		assert.Nil(t, result)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "illegal data")
	})

	t.Run("encode with many leading zeros", func(t *testing.T) {
		encoder := NewStdEncoder()
		// Create data with many leading zeros to cover the leading zeros encoding path
		data := make([]byte, 100)
		data[99] = 1 // Only the last byte is non-zero
		result := encoder.Encode(data)
		assert.NotEmpty(t, result)
		assert.Nil(t, encoder.Error)
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
		data2 := []byte(" world")

		n1, err1 := encoder.Write(data1)
		n2, err2 := encoder.Write(data2)

		assert.Equal(t, 5, n1)
		assert.Nil(t, err1)
		assert.Equal(t, 6, n2)
		assert.Nil(t, err2)
	})

	t.Run("write with error", func(t *testing.T) {
		encoder := &StreamEncoder{Error: errors.New("test error")}

		data := []byte("hello")
		n, err := encoder.Write(data)

		assert.Equal(t, 0, n)
		assert.Error(t, err)
		assert.Equal(t, "test error", err.Error())
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

func TestStreamEncoder_Close(t *testing.T) {
	t.Run("close with data", func(t *testing.T) {
		var buf bytes.Buffer
		encoder := NewStreamEncoder(&buf)

		encoder.Write([]byte("hello"))
		err := encoder.Close()

		assert.Nil(t, err)
		assert.Equal(t, "7tQLFHz", buf.String())
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
		assert.Error(t, err)
		assert.Equal(t, "test error", err.Error())
	})

	t.Run("close with write error", func(t *testing.T) {
		errorWriter := mock.NewErrorWriteCloser(errors.New("write error"))
		encoder := NewStreamEncoder(errorWriter)

		encoder.Write([]byte("hello"))
		err := encoder.Close()

		assert.Error(t, err)
		assert.Equal(t, "write error", err.Error())
	})
}

func TestStreamDecoder_Read(t *testing.T) {
	t.Run("read decoded data", func(t *testing.T) {
		encoded := "7tQLFHz"
		reader := strings.NewReader(encoded)
		decoder := NewStreamDecoder(reader)

		buf := make([]byte, 10)
		n, err := decoder.Read(buf)

		assert.Equal(t, 5, n)
		assert.Nil(t, err)
		assert.Equal(t, []byte("hello"), buf[:n])
	})

	t.Run("read with large buffer", func(t *testing.T) {
		encoded := "7tQLFHz"
		reader := strings.NewReader(encoded)
		decoder := NewStreamDecoder(reader)

		buf := make([]byte, 100)
		n, err := decoder.Read(buf)

		assert.Equal(t, 5, n)
		assert.Nil(t, err)
		assert.Equal(t, []byte("hello"), buf[:n])
	})

	t.Run("read with small buffer", func(t *testing.T) {
		encoded := "7tQLFHz"
		reader := strings.NewReader(encoded)
		decoder := NewStreamDecoder(reader)

		buf := make([]byte, 3)
		n, err := decoder.Read(buf)

		assert.Equal(t, 3, n)
		assert.Nil(t, err)
		assert.Equal(t, []byte("hel"), buf)

		n2, err2 := decoder.Read(buf)
		assert.Equal(t, 2, n2)
		assert.Nil(t, err2)
		assert.Equal(t, []byte("lo"), buf[:n2])
	})

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

	t.Run("read with error", func(t *testing.T) {
		decoder := &StreamDecoder{Error: errors.New("test error")}

		buf := make([]byte, 10)
		n, err := decoder.Read(buf)

		assert.Equal(t, 0, n)
		assert.Error(t, err)
		assert.Equal(t, "test error", err.Error())
	})

	t.Run("read with decode error", func(t *testing.T) {
		reader := strings.NewReader("invalid!")
		decoder := NewStreamDecoder(reader)

		buf := make([]byte, 10)
		n, err := decoder.Read(buf)

		assert.Equal(t, 0, n)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "illegal data")
	})

	t.Run("read with reader error", func(t *testing.T) {
		errorReader := mock.NewErrorFile(errors.New("read error"))
		decoder := NewStreamDecoder(errorReader)

		buf := make([]byte, 10)
		n, err := decoder.Read(buf)

		assert.Equal(t, 0, n)
		assert.Error(t, err)
		assert.Equal(t, "read error", err.Error())
	})

	t.Run("read eof", func(t *testing.T) {
		reader := strings.NewReader("")
		decoder := NewStreamDecoder(reader)

		buf := make([]byte, 10)
		n, err := decoder.Read(buf)

		assert.Equal(t, 0, n)
		assert.Equal(t, io.EOF, err)
	})
}

func TestStdError(t *testing.T) {
	t.Run("decode invalid character", func(t *testing.T) {
		decoder := NewStdDecoder()
		result, err := decoder.Decode([]byte("invalid!"))
		assert.Error(t, err)
		assert.Nil(t, result)
	})

	t.Run("decode invalid padding", func(t *testing.T) {
		decoder := NewStdDecoder()
		result, err := decoder.Decode([]byte("aGVsbG8!"))
		assert.Error(t, err)
		assert.Nil(t, result)
	})

	t.Run("encoder invalid alphabet", func(t *testing.T) {
		encoder := NewStdEncoder()
		// Test with invalid alphabet length
		encoder.alphabet = "invalid"
		// The encoder will still work because it uses the encodeMap initialized with StdAlphabet
		result := encoder.Encode([]byte("hello"))
		assert.NotNil(t, result)
		assert.Equal(t, []byte("7tQLFHz"), result)
	})

	t.Run("decoder invalid alphabet", func(t *testing.T) {
		decoder := NewStdDecoder()
		// Test with invalid alphabet length
		decoder.alphabet = "invalid"
		// The decoder will still work because it uses the decodeMap initialized with StdAlphabet
		result, err := decoder.Decode([]byte("7tQLFHz"))
		assert.Nil(t, err)
		assert.Equal(t, []byte("hello"), result)
	})

	t.Run("alphabet size error message", func(t *testing.T) {
		err := AlphabetSizeError(50)
		expected := "coding/base62: invalid alphabet, the alphabet length must be 62, got 50"
		assert.Equal(t, expected, err.Error())
	})

	t.Run("corrupt input error message", func(t *testing.T) {
		err := CorruptInputError(5)
		expected := "coding/base62: illegal data at input byte 5"
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

	t.Run("read with invalid data", func(t *testing.T) {
		reader := bytes.NewReader([]byte("invalid!"))
		decoder := NewStreamDecoder(reader)

		buf := make([]byte, 10)
		n, err := decoder.Read(buf)
		assert.Error(t, err)
		assert.Equal(t, 0, n)
	})

	t.Run("stream encoder with existing error", func(t *testing.T) {
		var buf bytes.Buffer
		encoder := NewStreamEncoder(&buf)
		encoder.(*StreamEncoder).Error = assert.AnError

		n, err := encoder.Write([]byte("test"))
		assert.Error(t, err)
		assert.Equal(t, 0, n)
	})

	t.Run("stream encoder close with existing error", func(t *testing.T) {
		var buf bytes.Buffer
		encoder := NewStreamEncoder(&buf)
		encoder.(*StreamEncoder).Error = assert.AnError

		err := encoder.Close()
		assert.Error(t, err)
	})

	t.Run("stream decoder with existing error", func(t *testing.T) {
		reader := bytes.NewReader([]byte("test"))
		decoder := NewStreamDecoder(reader)
		decoder.(*StreamDecoder).Error = assert.AnError

		buf := make([]byte, 10)
		n, err := decoder.Read(buf)
		assert.Error(t, err)
		assert.Equal(t, 0, n)
	})
}
