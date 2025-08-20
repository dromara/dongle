package base32

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
		encoder := NewStdEncoder(StdAlphabet)
		result := encoder.Encode([]byte{})
		assert.Nil(t, result)
		assert.Nil(t, encoder.Error)
	})

	t.Run("encode simple string", func(t *testing.T) {
		encoder := NewStdEncoder(StdAlphabet)
		original := []byte("hello world")
		encoded := encoder.Encode(original)
		assert.Equal(t, []byte("NBSWY3DPEB3W64TMMQ======"), encoded)
		assert.Nil(t, encoder.Error)
	})

	t.Run("encode unicode string", func(t *testing.T) {
		encoder := NewStdEncoder(StdAlphabet)
		original := []byte("你好世界")
		encoded := encoder.Encode(original)
		assert.Equal(t, []byte("4S62BZNFXXSLRFXHSWGA===="), encoded)
		assert.Nil(t, encoder.Error)
	})

	t.Run("encode binary data", func(t *testing.T) {
		encoder := NewStdEncoder(StdAlphabet)
		original := []byte{0x00, 0x01, 0x02, 0x03}
		encoded := encoder.Encode(original)
		assert.Equal(t, []byte("AAAQEAY="), encoded)
		assert.Nil(t, encoder.Error)
	})

	t.Run("encode single byte", func(t *testing.T) {
		encoder := NewStdEncoder(StdAlphabet)
		original := []byte{0x41}
		encoded := encoder.Encode(original)
		assert.Equal(t, []byte("IE======"), encoded)
		assert.Nil(t, encoder.Error)
	})

	t.Run("encode two bytes", func(t *testing.T) {
		encoder := NewStdEncoder(StdAlphabet)
		original := []byte{0x41, 0x42}
		encoded := encoder.Encode(original)
		assert.Equal(t, []byte("IFBA===="), encoded)
		assert.Nil(t, encoder.Error)
	})

	t.Run("encode with hex alphabet", func(t *testing.T) {
		encoder := NewStdEncoder(HexAlphabet)
		original := []byte("hello world")
		encoded := encoder.Encode(original)
		// Hex encoding should contain only hex characters (excluding padding)
		resultStr := string(encoded)
		for _, char := range resultStr {
			if char != '=' {
				assert.Contains(t, "0123456789ABCDEFGHIJKLMNOPQRSTUV", string(char))
			}
		}
		assert.Nil(t, encoder.Error)
	})

	t.Run("encode large data", func(t *testing.T) {
		encoder := NewStdEncoder(StdAlphabet)
		original := bytes.Repeat([]byte("Hello, World! "), 100)
		encoded := encoder.Encode(original)
		assert.NotEmpty(t, encoded)
		assert.Nil(t, encoder.Error)
	})

	t.Run("encode with leading zeros", func(t *testing.T) {
		encoder := NewStdEncoder(StdAlphabet)
		input := []byte{0x00, 0x00, 0x01, 0x02, 0x03}
		result := encoder.Encode(input)
		assert.Equal(t, []byte("AAAACAQD"), result)
		assert.Nil(t, encoder.Error)
	})

	t.Run("encode with existing error", func(t *testing.T) {
		encoder := NewStdEncoder("invalid")
		result := encoder.Encode([]byte("hello"))
		assert.Nil(t, result)
		assert.NotNil(t, encoder.Error)
	})

	t.Run("write multiple times", func(t *testing.T) {
		var buf bytes.Buffer
		encoder := NewStreamEncoder(&buf, StdAlphabet)

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
		assert.Equal(t, "NBSWY3DPEB3W64TMMQ======", buf.String())
	})

	t.Run("close with data success", func(t *testing.T) {
		var buf bytes.Buffer
		encoder := NewStreamEncoder(&buf, StdAlphabet)

		encoder.Write([]byte("test"))
		err := encoder.Close()

		assert.Nil(t, err)
		assert.Equal(t, "ORSXG5A=", buf.String())
	})

	t.Run("close with single byte", func(t *testing.T) {
		var buf bytes.Buffer
		encoder := NewStreamEncoder(&buf, StdAlphabet)

		encoder.Write([]byte("a"))
		err := encoder.Close()

		assert.Nil(t, err)
		assert.Equal(t, "ME======", buf.String())
	})

	t.Run("close with two bytes", func(t *testing.T) {
		var buf bytes.Buffer
		encoder := NewStreamEncoder(&buf, StdAlphabet)

		encoder.Write([]byte("ab"))
		err := encoder.Close()

		assert.Nil(t, err)
		assert.Equal(t, "MFRA====", buf.String())
	})

	t.Run("close with data", func(t *testing.T) {
		var buf bytes.Buffer
		encoder := NewStreamEncoder(&buf, StdAlphabet)

		encoder.Write([]byte("hello"))
		err := encoder.Close()

		assert.Nil(t, err)
		assert.Equal(t, "NBSWY3DP", buf.String())
	})
}

func TestStdDecoder_Decode(t *testing.T) {
	t.Run("decode empty input", func(t *testing.T) {
		decoder := NewStdDecoder(StdAlphabet)
		result, err := decoder.Decode([]byte{})
		assert.Nil(t, err)
		assert.Nil(t, result)
	})

	t.Run("decode simple string", func(t *testing.T) {
		decoder := NewStdDecoder(StdAlphabet)
		encoded := []byte("NBSWY3DPEB3W64TMMQ======")
		decoded, err := decoder.Decode(encoded)
		assert.Nil(t, err)
		assert.Equal(t, []byte("hello world"), decoded)
	})

	t.Run("decode unicode string", func(t *testing.T) {
		decoder := NewStdDecoder(StdAlphabet)
		encoded := []byte("4S62BZNFXXSLRFXHSWGA====")
		decoded, err := decoder.Decode(encoded)
		assert.Nil(t, err)
		assert.Equal(t, []byte("你好世界"), decoded)
	})

	t.Run("decode binary data", func(t *testing.T) {
		decoder := NewStdDecoder(StdAlphabet)
		encoded := []byte("AAAQEAY=")
		decoded, err := decoder.Decode(encoded)
		assert.Nil(t, err)
		assert.Equal(t, []byte{0x00, 0x01, 0x02, 0x03}, decoded)
	})

	t.Run("decode single character", func(t *testing.T) {
		decoder := NewStdDecoder(StdAlphabet)
		encoded := []byte("IE======")
		decoded, err := decoder.Decode(encoded)
		assert.Nil(t, err)
		assert.Equal(t, []byte{0x41}, decoded)
	})

	t.Run("decode two characters", func(t *testing.T) {
		decoder := NewStdDecoder(StdAlphabet)
		encoded := []byte("IFBA====")
		decoded, err := decoder.Decode(encoded)
		assert.Nil(t, err)
		assert.Equal(t, []byte{0x41, 0x42}, decoded)
	})

	t.Run("decode with hex alphabet", func(t *testing.T) {
		// First encode some data with hex alphabet
		input := []byte("hello world")
		encoder := NewStdEncoder(HexAlphabet)
		encoded := encoder.Encode(input)

		// Then decode it
		decoder := NewStdDecoder(HexAlphabet)
		result, err := decoder.Decode(encoded)

		assert.Nil(t, err)
		assert.Equal(t, input, result)
	})

	t.Run("decode large data", func(t *testing.T) {
		decoder := NewStdDecoder(StdAlphabet)
		original := strings.Repeat("Hello, World! ", 100)
		encoder := NewStdEncoder(StdAlphabet)
		encoded := encoder.Encode([]byte(original))
		decoded, err := decoder.Decode(encoded)
		assert.Nil(t, err)
		assert.Equal(t, []byte(original), decoded)
	})

	t.Run("decode invalid base32", func(t *testing.T) {
		decoder := NewStdDecoder(StdAlphabet)
		result, err := decoder.Decode([]byte("invalid!"))
		assert.Error(t, err)
		assert.Nil(t, result)
		assert.Contains(t, err.Error(), "illegal data")
	})

	t.Run("decode invalid padding", func(t *testing.T) {
		decoder := NewStdDecoder(StdAlphabet)
		result, err := decoder.Decode([]byte("NBSWY3DPEB3W64TMMQ=====!"))
		assert.Error(t, err)
		assert.Nil(t, result)
		assert.Contains(t, err.Error(), "illegal data")
	})

	t.Run("decode with existing error", func(t *testing.T) {
		decoder := NewStdDecoder("invalid")
		result, err := decoder.Decode([]byte("JBSWY3DP"))
		assert.Nil(t, result)
		assert.NotNil(t, err)
		assert.Equal(t, "coding/base32: invalid alphabet, the alphabet length must be 32, got 7", err.Error())
	})
}

func TestStreamEncoder_Write(t *testing.T) {
	t.Run("write data", func(t *testing.T) {
		var buf bytes.Buffer
		encoder := NewStreamEncoder(&buf, StdAlphabet)

		data := []byte("hello")
		n, err := encoder.Write(data)

		assert.Equal(t, 5, n)
		assert.Nil(t, err)
	})

	t.Run("write multiple times", func(t *testing.T) {
		var buf bytes.Buffer
		encoder := NewStreamEncoder(&buf, StdAlphabet)

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
		// Since NewStreamEncoder returns standard library type, we can't test Error field directly
		// This test is removed as it's not applicable to the current implementation
	})

	t.Run("write empty data", func(t *testing.T) {
		var buf bytes.Buffer
		encoder := NewStreamEncoder(&buf, StdAlphabet)

		var data []byte
		n, err := encoder.Write(data)

		assert.Equal(t, 0, n)
		assert.Nil(t, err)
	})

	t.Run("write with hex alphabet", func(t *testing.T) {
		var buf bytes.Buffer
		encoder := NewStreamEncoder(&buf, HexAlphabet)

		data := []byte("hello world")
		n, err := encoder.Write(data)

		assert.Equal(t, 11, n)
		assert.Nil(t, err)
	})
}

func TestStreamEncoder_Close(t *testing.T) {
	t.Run("close with data", func(t *testing.T) {
		var buf bytes.Buffer
		encoder := NewStreamEncoder(&buf, StdAlphabet)

		encoder.Write([]byte("hello"))
		err := encoder.Close()

		assert.Nil(t, err)
		assert.Equal(t, "NBSWY3DP", buf.String())
	})

	t.Run("close without data", func(t *testing.T) {
		var buf bytes.Buffer
		encoder := NewStreamEncoder(&buf, StdAlphabet)

		err := encoder.Close()
		assert.Nil(t, err)
		assert.Empty(t, buf.String())
	})

	t.Run("close with error", func(t *testing.T) {
		// Since NewStreamEncoder returns standard library type, we can't test Error field directly
		// This test is removed as it's not applicable to the current implementation
	})

	t.Run("close with write error", func(t *testing.T) {
		errorWriter := mock.NewErrorWriteCloser(errors.New("write error"))
		encoder := NewStreamEncoder(errorWriter, StdAlphabet)

		encoder.Write([]byte("hello"))
		err := encoder.Close()

		assert.Error(t, err)
		assert.Equal(t, "write error", err.Error())
	})
}

func TestStreamDecoder_Read(t *testing.T) {
	t.Run("read decoded data", func(t *testing.T) {
		encoded := "NBSWY3DP"
		file := mock.NewFile([]byte(encoded), "test.txt")
		decoder := NewStreamDecoder(file, StdAlphabet)

		buf := make([]byte, 20)
		n, err := decoder.Read(buf)

		assert.Equal(t, 5, n)
		assert.Nil(t, err)
		assert.Equal(t, []byte("hello"), buf[:n])
	})

	t.Run("read with large buffer", func(t *testing.T) {
		encoded := "NBSWY3DP"
		file := mock.NewFile([]byte(encoded), "test.txt")
		decoder := NewStreamDecoder(file, StdAlphabet)

		buf := make([]byte, 100)
		n, err := decoder.Read(buf)

		assert.Equal(t, 5, n)
		assert.Nil(t, err)
		assert.Equal(t, []byte("hello"), buf[:n])
	})

	t.Run("read with small buffer", func(t *testing.T) {
		encoded := "NBSWY3DP"
		file := mock.NewFile([]byte(encoded), "test.txt")
		decoder := NewStreamDecoder(file, StdAlphabet)

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

	t.Run("read with error", func(t *testing.T) {
		// Since NewStreamDecoder returns standard library type, we can't test Error field directly
		// This test is removed as it's not applicable to the current implementation
	})

	t.Run("read with decode error", func(t *testing.T) {
		file := mock.NewFile([]byte("invalid!"), "test.txt")
		decoder := NewStreamDecoder(file, StdAlphabet)

		buf := make([]byte, 10)
		n, err := decoder.Read(buf)

		assert.Equal(t, 0, n)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "illegal base32 data")
	})

	t.Run("read with reader error", func(t *testing.T) {
		errorReader := mock.NewErrorFile(errors.New("read error"))
		decoder := NewStreamDecoder(errorReader, StdAlphabet)

		buf := make([]byte, 10)
		n, err := decoder.Read(buf)

		assert.Equal(t, 0, n)
		assert.Error(t, err)
		assert.Equal(t, "read error", err.Error())
	})

	t.Run("read eof", func(t *testing.T) {
		file := mock.NewFile([]byte{}, "test.txt")
		decoder := NewStreamDecoder(file, StdAlphabet)

		buf := make([]byte, 10)
		n, err := decoder.Read(buf)

		assert.Equal(t, 0, n)
		assert.Equal(t, io.EOF, err)
	})

	t.Run("read with hex alphabet", func(t *testing.T) {
		// First encode with hex alphabet
		var encodeBuf bytes.Buffer
		encoder := NewStreamEncoder(&encodeBuf, HexAlphabet)
		_, err := encoder.Write([]byte("hello world"))
		assert.Nil(t, err)
		err = encoder.Close()
		assert.Nil(t, err)

		// Then decode with hex alphabet
		file := mock.NewFile(encodeBuf.Bytes(), "test.txt")
		decoder := NewStreamDecoder(file, HexAlphabet)

		buf := make([]byte, 20)
		n, err := decoder.Read(buf)
		assert.Nil(t, err)
		assert.Equal(t, 11, n)
		assert.Equal(t, []byte("hello world"), buf[:n])
	})
}

func TestStdError(t *testing.T) {
	t.Run("decode invalid character", func(t *testing.T) {
		decoder := NewStdDecoder(StdAlphabet)
		result, err := decoder.Decode([]byte("invalid!"))
		assert.Error(t, err)
		assert.Nil(t, result)
	})

	t.Run("decode invalid padding", func(t *testing.T) {
		decoder := NewStdDecoder(StdAlphabet)
		result, err := decoder.Decode([]byte("NBSWY3DPEB3W64TMMQ=====!"))
		assert.Error(t, err)
		assert.Nil(t, result)
	})

	t.Run("encoder invalid alphabet", func(t *testing.T) {
		encoder := NewStdEncoder("invalid")
		assert.NotNil(t, encoder.Error)
		assert.Equal(t, "coding/base32: invalid alphabet, the alphabet length must be 32, got 7", encoder.Error.Error())
	})

	t.Run("decoder invalid alphabet", func(t *testing.T) {
		decoder := NewStdDecoder("invalid")
		assert.NotNil(t, decoder.Error)
		assert.Equal(t, "coding/base32: invalid alphabet, the alphabet length must be 32, got 7", decoder.Error.Error())
	})

	t.Run("invalid alphabet error message", func(t *testing.T) {
		err := AlphabetSizeError(30)
		expected := "coding/base32: invalid alphabet, the alphabet length must be 32, got 30"
		assert.Equal(t, expected, err.Error())
	})

	t.Run("corrupt input error message", func(t *testing.T) {
		err := CorruptInputError(5)
		expected := "coding/base32: illegal data at input byte 5"
		assert.Equal(t, expected, err.Error())
	})

	t.Run("corrupt input error with zero", func(t *testing.T) {
		err := CorruptInputError(0)
		expected := "coding/base32: illegal data at input byte 0"
		assert.Equal(t, expected, err.Error())
	})
}

func TestStreamError(t *testing.T) {
	t.Run("stream encoder close with writer error", func(t *testing.T) {
		errorWriter := mock.NewErrorWriteCloser(assert.AnError)
		encoder := NewStreamEncoder(errorWriter, StdAlphabet)
		_, err := encoder.Write([]byte("test"))
		assert.NoError(t, err)

		err = encoder.Close()
		assert.Equal(t, assert.AnError, err)
	})

	t.Run("stream decoder with reader error", func(t *testing.T) {
		errorReader := mock.NewErrorFile(assert.AnError)
		decoder := NewStreamDecoder(errorReader, StdAlphabet)

		buf := make([]byte, 10)
		n, err := decoder.Read(buf)
		assert.Equal(t, assert.AnError, err)
		assert.Equal(t, 0, n)
	})

	t.Run("stream decoder with decode error", func(t *testing.T) {
		file := mock.NewFile([]byte("invalid!"), "test.txt")
		decoder := NewStreamDecoder(file, StdAlphabet)

		buf := make([]byte, 10)
		n, err := decoder.Read(buf)
		assert.Error(t, err)
		assert.Equal(t, 0, n)
	})

	t.Run("stream decoder with mock error reader", func(t *testing.T) {
		errorReader := mock.NewErrorReadWriteCloser(assert.AnError)
		decoder := NewStreamDecoder(errorReader, StdAlphabet)

		buf := make([]byte, 10)
		n, err := decoder.Read(buf)
		assert.Equal(t, assert.AnError, err)
		assert.Equal(t, 0, n)
	})

	t.Run("read with invalid data", func(t *testing.T) {
		file := mock.NewFile([]byte("invalid!"), "test.txt")
		decoder := NewStreamDecoder(file, StdAlphabet)

		buf := make([]byte, 10)
		n, err := decoder.Read(buf)
		assert.Error(t, err)
		assert.Equal(t, 0, n)
	})

	t.Run("stream encoder with existing error", func(t *testing.T) {
		// Since NewStreamEncoder returns standard library type, we can't test Error field directly
		// This test is removed as it's not applicable to the current implementation
	})

	t.Run("stream encoder close with existing error", func(t *testing.T) {
		// Since NewStreamEncoder returns standard library type, we can't test Error field directly
		// This test is removed as it's not applicable to the current implementation
	})

	t.Run("stream decoder with existing error", func(t *testing.T) {
		// Since NewStreamDecoder returns standard library type, we can't test Error field directly
		// This test is removed as it's not applicable to the current implementation
	})
}

func TestCustomAlphabets(t *testing.T) {
	t.Run("verify custom alphabets", func(t *testing.T) {
		// Test that they produce different results
		testData := []byte("hello world")

		stdEncoder := NewStdEncoder(StdAlphabet)
		assert.Nil(t, stdEncoder.Error)
		stdResult := stdEncoder.Encode(testData)

		hexEncoder := NewStdEncoder(HexAlphabet)
		assert.Nil(t, hexEncoder.Error)
		hexResult := hexEncoder.Encode(testData)

		// Results should be different
		assert.NotEqual(t, string(stdResult), string(hexResult))
	})

	t.Run("alphabet length verification", func(t *testing.T) {
		assert.Equal(t, 32, len(StdAlphabet))
		assert.Equal(t, 32, len(HexAlphabet))
	})

	t.Run("alphabet character uniqueness", func(t *testing.T) {
		// Check StdAlphabet uniqueness
		seen := make(map[rune]bool)
		for _, char := range StdAlphabet {
			assert.False(t, seen[char], "Duplicate character in StdAlphabet: %c", char)
			seen[char] = true
		}

		// Check HexAlphabet uniqueness
		seen = make(map[rune]bool)
		for _, char := range HexAlphabet {
			assert.False(t, seen[char], "Duplicate character in HexAlphabet: %c", char)
			seen[char] = true
		}
	})
}

func TestRoundTrip(t *testing.T) {
	t.Run("std encoder decoder round trip", func(t *testing.T) {
		testData := []byte("Hello, World! 你好世界")

		encoder := NewStdEncoder(StdAlphabet)
		assert.Nil(t, encoder.Error)
		encoded := encoder.Encode(testData)

		decoder := NewStdDecoder(StdAlphabet)
		assert.Nil(t, decoder.Error)
		decoded, err := decoder.Decode(encoded)

		assert.NoError(t, err)
		assert.Equal(t, testData, decoded)
	})

	t.Run("hex encoder decoder round trip", func(t *testing.T) {
		testData := []byte("Hello, World! 你好世界")

		encoder := NewStdEncoder(HexAlphabet)
		assert.Nil(t, encoder.Error)
		encoded := encoder.Encode(testData)

		decoder := NewStdDecoder(HexAlphabet)
		assert.Nil(t, decoder.Error)
		decoded, err := decoder.Decode(encoded)

		assert.NoError(t, err)
		assert.Equal(t, testData, decoded)
	})

	t.Run("stream encoder decoder round trip", func(t *testing.T) {
		testData := []byte("Hello, World! 你好世界")

		// Encode
		var encodeBuf bytes.Buffer
		encoder := NewStreamEncoder(&encodeBuf, StdAlphabet)
		_, err := encoder.Write(testData)
		assert.NoError(t, err)
		err = encoder.Close()
		assert.NoError(t, err)

		// Decode
		file := mock.NewFile(encodeBuf.Bytes(), "test.txt")
		decoder := NewStreamDecoder(file, StdAlphabet)

		buf := make([]byte, 1024)
		n, err := decoder.Read(buf)
		assert.NoError(t, err)

		assert.Equal(t, testData, buf[:n])
	})
}

func TestEdgeCases(t *testing.T) {
	t.Run("very large data", func(t *testing.T) {
		// Create large test data
		largeData := bytes.Repeat([]byte("Hello, World! "), 1000)

		encoder := NewStdEncoder(StdAlphabet)
		assert.Nil(t, encoder.Error)
		encoded := encoder.Encode(largeData)

		decoder := NewStdDecoder(StdAlphabet)
		assert.Nil(t, decoder.Error)
		decoded, err := decoder.Decode(encoded)

		assert.NoError(t, err)
		assert.Equal(t, largeData, decoded)
	})

	t.Run("single character encoding", func(t *testing.T) {
		encoder := NewStdEncoder(StdAlphabet)
		assert.Nil(t, encoder.Error)
		result := encoder.Encode([]byte("A"))
		assert.NotEmpty(t, result)
		assert.True(t, strings.HasSuffix(string(result), "======"))
	})

	t.Run("padding edge cases", func(t *testing.T) {
		// Test different padding scenarios
		testCases := []struct {
			input    []byte
			expected string
		}{
			{[]byte{0x00}, "AA======"},
			{[]byte{0x00, 0x00}, "AAAA===="},
			{[]byte{0x00, 0x00, 0x00}, "AAAAA==="},
			{[]byte{0x00, 0x00, 0x00, 0x00}, "AAAAAAA="},
		}

		encoder := NewStdEncoder(StdAlphabet)
		assert.Nil(t, encoder.Error)

		for _, tc := range testCases {
			result := encoder.Encode(tc.input)
			assert.Equal(t, tc.expected, string(result))
		}
	})

	t.Run("nil input handling", func(t *testing.T) {
		encoder := NewStdEncoder(StdAlphabet)
		assert.Nil(t, encoder.Error)
		result := encoder.Encode(nil)
		assert.Nil(t, result)

		decoder := NewStdDecoder(StdAlphabet)
		assert.Nil(t, decoder.Error)
		result2, err := decoder.Decode(nil)
		assert.Nil(t, err)
		assert.Nil(t, result2)
	})
}
