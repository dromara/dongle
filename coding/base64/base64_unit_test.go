package base64

import (
	"bytes"
	"errors"
	"io"
	"testing"

	"github.com/dromara/dongle/internal/mock"
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
		assert.Equal(t, []byte("aGVsbG8gd29ybGQ="), encoded)
		assert.Nil(t, encoder.Error)
	})

	t.Run("encode with different byte counts", func(t *testing.T) {
		encoder := NewStdEncoder(StdAlphabet)

		// Test single byte
		encoded := encoder.Encode([]byte{42})
		assert.Equal(t, []byte("Kg=="), encoded)
		assert.Nil(t, encoder.Error)

		// Test two bytes
		encoded = encoder.Encode([]byte{42, 43})
		assert.Equal(t, []byte("Kis="), encoded)
		assert.Nil(t, encoder.Error)

		// Test three bytes
		encoded = encoder.Encode([]byte{42, 43, 44})
		assert.Equal(t, []byte("Kiss"), encoded)
		assert.Nil(t, encoder.Error)

		// Test four bytes
		encoded = encoder.Encode([]byte{42, 43, 44, 45})
		assert.Equal(t, []byte("KissLQ=="), encoded)
		assert.Nil(t, encoder.Error)

		// Test five bytes
		encoded = encoder.Encode([]byte{42, 43, 44, 45, 46})
		assert.Equal(t, []byte("KissLS4="), encoded)
		assert.Nil(t, encoder.Error)
	})

	t.Run("encode all zeros", func(t *testing.T) {
		encoder := NewStdEncoder(StdAlphabet)
		original := []byte{0, 0, 0, 0}
		encoded := encoder.Encode(original)
		assert.Equal(t, []byte("AAAAAA=="), encoded)
		assert.Nil(t, encoder.Error)
	})

	t.Run("encode unicode string", func(t *testing.T) {
		encoder := NewStdEncoder(StdAlphabet)
		original := []byte("你好世界")
		encoded := encoder.Encode(original)
		assert.Equal(t, []byte("5L2g5aW95LiW55WM"), encoded)
		assert.Nil(t, encoder.Error)
	})

	t.Run("encode binary data", func(t *testing.T) {
		encoder := NewStdEncoder(StdAlphabet)
		original := []byte{0x00, 0x01, 0x02, 0xFF, 0xFE, 0xFD}
		encoded := encoder.Encode(original)
		assert.Equal(t, []byte("AAEC//79"), encoded)
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
		assert.Equal(t, []byte("AAABAgM="), result)
		assert.Nil(t, encoder.Error)
	})

	t.Run("URL alphabet", func(t *testing.T) {
		encoder := NewStdEncoder(URLAlphabet)
		original := []byte("hello world")
		encoded := encoder.Encode(original)
		assert.Equal(t, []byte("aGVsbG8gd29ybGQ="), encoded)
		assert.Nil(t, encoder.Error)
		// URL-safe encoding should not contain + or /
		assert.NotContains(t, string(encoded), "+")
		assert.NotContains(t, string(encoded), "/")
	})
}

func TestNewStdDecoder(t *testing.T) {
	t.Run("new std decoder", func(t *testing.T) {
		decoder := NewStdDecoder(StdAlphabet)
		assert.NotNil(t, decoder)
		assert.Nil(t, decoder.Error)
	})

	t.Run("decoder functionality", func(t *testing.T) {
		decoder := NewStdDecoder(StdAlphabet)
		encoder := NewStdEncoder(StdAlphabet)
		original := []byte("hello")
		encoded := encoder.Encode(original)
		decoded, err := decoder.Decode(encoded)
		assert.Nil(t, err)
		assert.Equal(t, original, decoded)
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
		encoded := []byte("aGVsbG8gd29ybGQ=")
		decoded, err := decoder.Decode(encoded)
		assert.Nil(t, err)
		assert.Equal(t, []byte("hello world"), decoded)
	})

	t.Run("decode with different byte counts", func(t *testing.T) {
		decoder := NewStdDecoder(StdAlphabet)
		encoder := NewStdEncoder(StdAlphabet)

		// Test single byte
		original := []byte{42}
		encoded := encoder.Encode(original)
		decoded, err := decoder.Decode(encoded)
		assert.Nil(t, err)
		assert.Equal(t, original, decoded)

		// Test two bytes
		original = []byte{42, 43}
		encoded = encoder.Encode(original)
		decoded, err = decoder.Decode(encoded)
		assert.Nil(t, err)
		assert.Equal(t, original, decoded)

		// Test three bytes
		original = []byte{42, 43, 44}
		encoded = encoder.Encode(original)
		decoded, err = decoder.Decode(encoded)
		assert.Nil(t, err)
		assert.Equal(t, original, decoded)

		// Test four bytes
		original = []byte{42, 43, 44, 45}
		encoded = encoder.Encode(original)
		decoded, err = decoder.Decode(encoded)
		assert.Nil(t, err)
		assert.Equal(t, original, decoded)

		// Test five bytes
		original = []byte{42, 43, 44, 45, 46}
		encoded = encoder.Encode(original)
		decoded, err = decoder.Decode(encoded)
		assert.Nil(t, err)
		assert.Equal(t, original, decoded)
	})

	t.Run("decode all zeros", func(t *testing.T) {
		decoder := NewStdDecoder(StdAlphabet)
		encoder := NewStdEncoder(StdAlphabet)
		original := []byte{0, 0, 0, 0}
		encoded := encoder.Encode(original)
		decoded, err := decoder.Decode(encoded)
		assert.Nil(t, err)
		assert.Equal(t, original, decoded)
	})

	t.Run("decode unicode string", func(t *testing.T) {
		decoder := NewStdDecoder(StdAlphabet)
		encoded := []byte("5L2g5aW95LiW55WM")
		decoded, err := decoder.Decode(encoded)
		assert.Nil(t, err)
		assert.Equal(t, []byte("你好世界"), decoded)
	})

	t.Run("decode binary data", func(t *testing.T) {
		decoder := NewStdDecoder(StdAlphabet)
		encoder := NewStdEncoder(StdAlphabet)
		original := []byte{0x00, 0x01, 0x02, 0xFF, 0xFE, 0xFD}
		encoded := encoder.Encode(original)
		decoded, err := decoder.Decode(encoded)
		assert.Nil(t, err)
		assert.Equal(t, original, decoded)
	})

	t.Run("decode with leading zeros", func(t *testing.T) {
		decoder := NewStdDecoder(StdAlphabet)
		encoder := NewStdEncoder(StdAlphabet)
		input := []byte{0x00, 0x00, 0x01, 0x02, 0x03}
		encoded := encoder.Encode(input)
		decoded, err := decoder.Decode(encoded)
		assert.Nil(t, err)
		assert.Equal(t, input, decoded)
	})

	t.Run("URL alphabet", func(t *testing.T) {
		decoder := NewStdDecoder(URLAlphabet)
		encoder := NewStdEncoder(URLAlphabet)
		original := []byte("hello world")
		encoded := encoder.Encode(original)
		decoded, err := decoder.Decode(encoded)
		assert.Nil(t, err)
		assert.Equal(t, original, decoded)
	})

	t.Run("custom alphabets", func(t *testing.T) {
		// Test that they produce different results for data that would use + or /
		testData := []byte{0x3F, 0x3F, 0x3F} // This would normally encode to "///"

		stdEncoder := NewStdEncoder(StdAlphabet)
		assert.Nil(t, stdEncoder.Error)
		stdResult := stdEncoder.Encode(testData)

		urlEncoder := NewStdEncoder(URLAlphabet)
		assert.Nil(t, urlEncoder.Error)
		urlResult := urlEncoder.Encode(testData)

		// Standard encoding should contain /
		assert.Contains(t, string(stdResult), "/")

		// URL-safe encoding should not contain / and should contain _
		assert.NotContains(t, string(urlResult), "/")
		assert.Contains(t, string(urlResult), "_")

		// Results should be different
		assert.NotEqual(t, string(stdResult), string(urlResult))
	})
}

func TestNewStreamEncoder(t *testing.T) {
	t.Run("new stream encoder", func(t *testing.T) {
		file := mock.NewFile(nil, "test.txt")
		encoder := NewStreamEncoder(file, StdAlphabet)
		assert.NotNil(t, encoder)
	})
}

func TestStreamEncoder_Write(t *testing.T) {
	t.Run("write data", func(t *testing.T) {
		file := mock.NewFile(nil, "test.txt")
		encoder := NewStreamEncoder(file, StdAlphabet)
		data := []byte("hello world")
		n, err := encoder.Write(data)
		assert.NoError(t, err)
		assert.Equal(t, len(data), n)
	})

	t.Run("write multiple times", func(t *testing.T) {
		file := mock.NewFile(nil, "test.txt")
		encoder := NewStreamEncoder(file, StdAlphabet)

		encoder.Write([]byte("hello"))
		encoder.Write([]byte(" world"))

		err := encoder.Close()
		assert.NoError(t, err)
		assert.Equal(t, "aGVsbG8gd29ybGQ=", string(file.Bytes()))
	})
}

func TestStreamEncoder_Close(t *testing.T) {
	t.Run("close with data", func(t *testing.T) {
		file := mock.NewFile(nil, "test.txt")
		encoder := NewStreamEncoder(file, StdAlphabet)
		encoder.Write([]byte("hello world"))

		err := encoder.Close()
		assert.NoError(t, err)
		assert.Equal(t, "aGVsbG8gd29ybGQ=", string(file.Bytes()))
	})

	t.Run("close without data", func(t *testing.T) {
		file := mock.NewFile(nil, "test.txt")
		encoder := NewStreamEncoder(file, StdAlphabet)

		err := encoder.Close()
		assert.NoError(t, err)
		assert.Empty(t, string(file.Bytes()))
	})

	t.Run("close with write error", func(t *testing.T) {
		errorWriter := mock.NewErrorWriteCloser(errors.New("write error"))
		encoder := NewStreamEncoder(errorWriter, StdAlphabet)

		// Write data that will leave 1-2 bytes in buffer
		encoder.Write([]byte("a")) // 1 byte, will be buffered

		err := encoder.Close()
		assert.Error(t, err)
		assert.Equal(t, "write error", err.Error())
	})

	t.Run("close with existing error", func(t *testing.T) {
		encoder := &StreamEncoder{Error: errors.New("existing error")}

		err := encoder.Close()
		assert.Error(t, err)
		assert.Equal(t, "existing error", err.Error())
	})
}

func TestNewStreamDecoder(t *testing.T) {
	t.Run("new stream decoder", func(t *testing.T) {
		file := mock.NewFile([]byte("test"), "test.txt")
		decoder := NewStreamDecoder(file, StdAlphabet)
		assert.NotNil(t, decoder)
	})
}

func TestStreamDecoder_Read(t *testing.T) {
	t.Run("read from buffer", func(t *testing.T) {
		encoder := NewStdEncoder(StdAlphabet)
		encoded := encoder.Encode([]byte("hello"))

		file := mock.NewFile(encoded, "test.txt")
		decoder := NewStreamDecoder(file, StdAlphabet)

		buf := make([]byte, 10)
		n, err := decoder.Read(buf)
		assert.NoError(t, err)
		assert.Equal(t, 5, n)
		assert.Equal(t, []byte("hello"), buf[:n])
	})

	t.Run("read from reader", func(t *testing.T) {
		// First encode some data
		encoder := NewStdEncoder(StdAlphabet)
		encoded := encoder.Encode([]byte("hello world"))

		file := mock.NewFile(encoded, "test.txt")
		decoder := NewStreamDecoder(file, StdAlphabet)

		buf := make([]byte, 20)
		n, err := decoder.Read(buf)
		assert.NoError(t, err)
		assert.Equal(t, 11, n)
		assert.Equal(t, []byte("hello world"), buf[:n])
	})

	t.Run("read with partial buffer", func(t *testing.T) {
		// First encode some data
		encoder := NewStdEncoder(StdAlphabet)
		encoded := encoder.Encode([]byte("hello world"))

		file := mock.NewFile(encoded, "test.txt")
		decoder := NewStreamDecoder(file, StdAlphabet)

		// Read with small buffer
		buf := make([]byte, 5)
		n, err := decoder.Read(buf)
		assert.NoError(t, err)
		assert.True(t, n >= 0)
		assert.True(t, n <= 5)

		// Read remaining data
		buf2 := make([]byte, 10)
		n2, err2 := decoder.Read(buf2)
		if err2 == io.EOF {
			assert.True(t, n2 >= 0)
		} else {
			assert.NoError(t, err2)
			assert.True(t, n2 >= 0)
		}
	})

	t.Run("read from empty reader", func(t *testing.T) {
		file := mock.NewFile([]byte{}, "test.txt")
		decoder := NewStreamDecoder(file, StdAlphabet)

		buf := make([]byte, 10)
		n, err := decoder.Read(buf)
		assert.Equal(t, io.EOF, err)
		assert.Equal(t, 0, n)
	})
}

func TestStdError(t *testing.T) {
	t.Run("error_fields", func(t *testing.T) {
		encoder := NewStdEncoder(StdAlphabet)
		decoder := NewStdDecoder(StdAlphabet)
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
		assert.Equal(t, "coding/base64: invalid alphabet, the alphabet length must be 64, got 50", err1.Error())

		err2 := CorruptInputError(5)
		assert.Equal(t, "coding/base64: illegal data at input byte 5", err2.Error())

		err3 := CorruptInputError(0)
		assert.Equal(t, "coding/base64: illegal data at input byte 0", err3.Error())
	})

	t.Run("decode invalid character", func(t *testing.T) {
		decoder := NewStdDecoder(StdAlphabet)
		result, err := decoder.Decode([]byte("invalid!"))
		assert.Error(t, err)
		assert.Nil(t, result)
	})

	t.Run("encoder invalid alphabet", func(t *testing.T) {
		encoder := NewStdEncoder("invalid")
		assert.NotNil(t, encoder.Error)
		assert.Equal(t, "coding/base64: invalid alphabet, the alphabet length must be 64, got 7", encoder.Error.Error())
		result := encoder.Encode([]byte("hello"))
		assert.Nil(t, result)
	})

	t.Run("decoder invalid alphabet", func(t *testing.T) {
		decoder := NewStdDecoder("invalid")
		assert.NotNil(t, decoder.Error)
		assert.Equal(t, "coding/base64: invalid alphabet, the alphabet length must be 64, got 7", decoder.Error.Error())
		result, err := decoder.Decode([]byte("aGVsbG8="))
		assert.Nil(t, result)
		assert.NotNil(t, err)
		assert.Equal(t, "coding/base64: invalid alphabet, the alphabet length must be 64, got 7", err.Error())
	})
}

func TestStreamError(t *testing.T) {
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
		if err != nil {
			assert.Error(t, err)
		}
		assert.True(t, n >= 0)
	})

	t.Run("stream decoder with mock error reader", func(t *testing.T) {
		errorReader := mock.NewErrorReadWriteCloser(assert.AnError)
		decoder := NewStreamDecoder(errorReader, StdAlphabet)

		buf := make([]byte, 10)
		n, err := decoder.Read(buf)
		assert.Equal(t, assert.AnError, err)
		assert.Equal(t, 0, n)
	})

	t.Run("stream encoder with error", func(t *testing.T) {
		encoder := &StreamEncoder{Error: assert.AnError}
		n, err := encoder.Write([]byte("hello"))
		assert.Equal(t, 0, n)
		assert.Equal(t, assert.AnError, err)
	})

	t.Run("stream encoder close with error", func(t *testing.T) {
		encoder := &StreamEncoder{Error: assert.AnError}
		err := encoder.Close()
		assert.Equal(t, assert.AnError, err)
	})

	t.Run("stream decoder with error", func(t *testing.T) {
		decoder := &StreamDecoder{Error: assert.AnError}
		buf := make([]byte, 10)
		n, err := decoder.Read(buf)
		assert.Equal(t, 0, n)
		assert.Equal(t, assert.AnError, err)
	})
}

// Test convenience functions
func TestConvenienceFunctions(t *testing.T) {
	t.Run("Encode convenience function", func(t *testing.T) {
		data := []byte("hello world")
		encoded := Encode(data)
		assert.Equal(t, []byte("aGVsbG8gd29ybGQ="), encoded)
	})

	t.Run("EncodeURLSafe convenience function", func(t *testing.T) {
		data := []byte("hello world")
		encoded := EncodeURLSafe(data)
		assert.Equal(t, []byte("aGVsbG8gd29ybGQ="), encoded)
		// URL-safe encoding should not contain + or /
		assert.NotContains(t, string(encoded), "+")
		assert.NotContains(t, string(encoded), "/")
	})

	t.Run("Decode convenience function", func(t *testing.T) {
		encoded := []byte("aGVsbG8gd29ybGQ=")
		decoded := Decode(encoded)
		assert.Equal(t, []byte("hello world"), decoded)
	})

	t.Run("DecodeURLSafe convenience function", func(t *testing.T) {
		encoded := []byte("aGVsbG8gd29ybGQ=")
		decoded := DecodeURLSafe(encoded)
		assert.Equal(t, []byte("hello world"), decoded)
	})

	t.Run("Decode convenience function with invalid input", func(t *testing.T) {
		encoded := []byte("invalid!")
		decoded := Decode(encoded)
		// Should return empty result when there's an error
		assert.Nil(t, decoded)
	})

	t.Run("DecodeURLSafe convenience function with invalid input", func(t *testing.T) {
		encoded := []byte("invalid!")
		decoded := DecodeURLSafe(encoded)
		// Should return empty result when there's an error
		assert.Nil(t, decoded)
	})
}

// Test edge cases and error conditions
func TestEdgeCases(t *testing.T) {
	t.Run("encoder with empty alphabet", func(t *testing.T) {
		encoder := NewStdEncoder("")
		assert.NotNil(t, encoder.Error)
		assert.Equal(t, "coding/base64: invalid alphabet, the alphabet length must be 64, got 0", encoder.Error.Error())
		result := encoder.Encode([]byte("hello"))
		assert.Nil(t, result)
	})

	t.Run("decoder with empty alphabet", func(t *testing.T) {
		decoder := NewStdDecoder("")
		assert.NotNil(t, decoder.Error)
		assert.Equal(t, "coding/base64: invalid alphabet, the alphabet length must be 64, got 0", decoder.Error.Error())
		result, err := decoder.Decode([]byte("aGVsbG8="))
		assert.Nil(t, result)
		assert.NotNil(t, err)
		assert.Equal(t, "coding/base64: invalid alphabet, the alphabet length must be 64, got 0", err.Error())
	})

	t.Run("stream encoder with empty alphabet", func(t *testing.T) {
		file := mock.NewFile(nil, "test.txt")
		encoder := NewStreamEncoder(file, "")
		// Type assert to access Error field
		streamEncoder := encoder.(*StreamEncoder)
		assert.NotNil(t, streamEncoder.Error)
		assert.Equal(t, "coding/base64: invalid alphabet, the alphabet length must be 64, got 0", streamEncoder.Error.Error())
	})

	t.Run("stream decoder with empty alphabet", func(t *testing.T) {
		file := mock.NewFile([]byte("test"), "test.txt")
		decoder := NewStreamDecoder(file, "")
		// Type assert to access Error field
		streamDecoder := decoder.(*StreamDecoder)
		assert.NotNil(t, streamDecoder.Error)
		assert.Equal(t, "coding/base64: invalid alphabet, the alphabet length must be 64, got 0", streamDecoder.Error.Error())
	})

	t.Run("stream encoder with very long alphabet", func(t *testing.T) {
		file := mock.NewFile(nil, "test.txt")
		longAlphabet := string(make([]byte, 100)) // 100 bytes
		encoder := NewStreamEncoder(file, longAlphabet)
		// Type assert to access Error field
		streamEncoder := encoder.(*StreamEncoder)
		assert.NotNil(t, streamEncoder.Error)
		assert.Equal(t, "coding/base64: invalid alphabet, the alphabet length must be 64, got 100", streamEncoder.Error.Error())
	})

	t.Run("stream decoder with very long alphabet", func(t *testing.T) {
		file := mock.NewFile([]byte("test"), "test.txt")
		longAlphabet := string(make([]byte, 100)) // 100 bytes
		decoder := NewStreamDecoder(file, longAlphabet)
		// Type assert to access Error field
		streamDecoder := decoder.(*StreamDecoder)
		assert.NotNil(t, streamDecoder.Error)
		assert.Equal(t, "coding/base64: invalid alphabet, the alphabet length must be 64, got 100", streamDecoder.Error.Error())
	})

	t.Run("decode with corrupted input that causes std library error", func(t *testing.T) {
		decoder := NewStdDecoder(StdAlphabet)
		// Create input that will cause the standard library to return an error
		corruptedInput := []byte("aGVsbG8=invalid")
		result, err := decoder.Decode(corruptedInput)
		assert.Nil(t, result)
		assert.NotNil(t, err)
		assert.Contains(t, err.Error(), "illegal data at input byte")
	})

	t.Run("decode with padding issues", func(t *testing.T) {
		decoder := NewStdDecoder(StdAlphabet)
		// Test with invalid padding
		invalidPadding := []byte("aGVsbG8")
		result, err := decoder.Decode(invalidPadding)
		assert.Nil(t, result)
		assert.NotNil(t, err)
		assert.Contains(t, err.Error(), "illegal data at input byte")
	})

	t.Run("decode with non-base64 characters", func(t *testing.T) {
		decoder := NewStdDecoder(StdAlphabet)
		// Test with characters not in the base64 alphabet
		invalidChars := []byte("aGVsbG8!@#")
		result, err := decoder.Decode(invalidChars)
		assert.NotNil(t, err)
		assert.Nil(t, result)
		assert.Contains(t, err.Error(), "illegal data at input byte")
	})

	t.Run("stream encoder write with nil buffer", func(t *testing.T) {
		file := mock.NewFile(nil, "test.txt")
		encoder := NewStreamEncoder(file, StdAlphabet)
		n, err := encoder.Write(nil)
		assert.NoError(t, err)
		assert.Equal(t, 0, n)
	})

	t.Run("stream encoder write with empty buffer", func(t *testing.T) {
		file := mock.NewFile(nil, "test.txt")
		encoder := NewStreamEncoder(file, StdAlphabet)
		n, err := encoder.Write([]byte{})
		assert.NoError(t, err)
		assert.Equal(t, 0, n)
	})

	t.Run("stream encoder close with empty buffer", func(t *testing.T) {
		file := mock.NewFile(nil, "test.txt")
		encoder := NewStreamEncoder(file, StdAlphabet)
		err := encoder.Close()
		assert.NoError(t, err)
		assert.Empty(t, string(file.Bytes()))
	})

	t.Run("stream decoder read with nil buffer", func(t *testing.T) {
		file := mock.NewFile([]byte("aGVsbG8="), "test.txt")
		decoder := NewStreamDecoder(file, StdAlphabet)
		n, err := decoder.Read(nil)
		assert.NoError(t, err)
		assert.Equal(t, 0, n)
	})

	t.Run("stream decoder read with empty buffer", func(t *testing.T) {
		file := mock.NewFile([]byte("aGVsbG8="), "test.txt")
		decoder := NewStreamDecoder(file, StdAlphabet)
		emptyBuf := make([]byte, 0)
		n, err := decoder.Read(emptyBuf)
		assert.NoError(t, err)
		assert.Equal(t, 0, n)
	})

	t.Run("stream encoder close with write error", func(t *testing.T) {
		// Create a mock writer that returns an error on Write
		errorWriter := mock.NewErrorReadWriteCloser(assert.AnError)
		encoder := NewStreamEncoder(errorWriter, StdAlphabet)

		// Write data that will trigger encoding in Write method
		// "hello" is 5 bytes, will be split into 1 complete 3-byte chunk + 2 remaining bytes
		// The first chunk will be encoded in Write, triggering the error
		n, err := encoder.Write([]byte("hello"))
		assert.Error(t, err)
		assert.Equal(t, 5, n)
		assert.Equal(t, assert.AnError, err)
	})
}
