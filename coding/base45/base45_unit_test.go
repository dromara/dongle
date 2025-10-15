package base45

import (
	"bytes"
	"errors"
	"io"
	"strings"
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
		original := []byte("Hello")
		encoded := encoder.Encode(original)
		assert.Equal(t, []byte("%69 VDL2"), encoded)
		assert.Nil(t, encoder.Error)
	})

	t.Run("encode with different byte counts", func(t *testing.T) {
		encoder := NewStdEncoder()

		// Test single byte
		encoded := encoder.Encode([]byte{42})
		assert.Equal(t, []byte(".0"), encoded)
		assert.Nil(t, encoder.Error)

		// Test two bytes
		encoded = encoder.Encode([]byte{42, 43})
		assert.Equal(t, []byte("+E5"), encoded)
		assert.Nil(t, encoder.Error)

		// Test three bytes
		encoded = encoder.Encode([]byte{42, 43, 44})
		assert.Equal(t, []byte("+E5:0"), encoded)
		assert.Nil(t, encoder.Error)

		// Test four bytes
		encoded = encoder.Encode([]byte{42, 43, 44, 45})
		assert.Equal(t, []byte("+E5EQ5"), encoded)
		assert.Nil(t, encoder.Error)

		// Test five bytes
		encoded = encoder.Encode([]byte{42, 43, 44, 45, 46})
		assert.Equal(t, []byte("+E5EQ511"), encoded)
		assert.Nil(t, encoder.Error)
	})

	t.Run("encode all zeros", func(t *testing.T) {
		encoder := NewStdEncoder()
		original := []byte{0, 0, 0, 0}
		encoded := encoder.Encode(original)
		assert.Equal(t, []byte("000000"), encoded)
		assert.Nil(t, encoder.Error)
	})

	t.Run("encode unicode string", func(t *testing.T) {
		encoder := NewStdEncoder()
		original := []byte("你好世界")
		encoded := encoder.Encode(original)
		assert.Equal(t, []byte("C-SEFK*.K7-SL3JY+I"), encoded)
		assert.Nil(t, encoder.Error)
	})

	t.Run("encode binary data", func(t *testing.T) {
		encoder := NewStdEncoder()
		original := []byte{0x00, 0x01, 0x02, 0xFF, 0xFE, 0xFD}
		encoded := encoder.Encode(original)
		assert.Equal(t, []byte("1002H0RAW"), encoded)
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
		assert.Equal(t, []byte("000X5030"), result)
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
		assert.Equal(t, "+8D VD82EK4F.KEA2", buf.String())
	})

	t.Run("close with data success", func(t *testing.T) {
		var buf bytes.Buffer
		encoder := NewStreamEncoder(&buf)

		encoder.Write([]byte("test"))
		err := encoder.Close()

		assert.Nil(t, err)
		assert.Equal(t, "7WE QE", buf.String())
	})

	t.Run("close with single byte", func(t *testing.T) {
		var buf bytes.Buffer
		encoder := NewStreamEncoder(&buf)

		encoder.Write([]byte("a"))
		err := encoder.Close()

		assert.Nil(t, err)
		assert.Equal(t, "72", buf.String())
	})

	t.Run("close with two bytes", func(t *testing.T) {
		var buf bytes.Buffer
		encoder := NewStreamEncoder(&buf)

		encoder.Write([]byte("ab"))
		err := encoder.Close()

		assert.Nil(t, err)
		assert.Equal(t, "0EC", buf.String())
	})

	t.Run("close with data", func(t *testing.T) {
		var buf bytes.Buffer
		encoder := NewStreamEncoder(&buf)

		encoder.Write([]byte("hello"))
		err := encoder.Close()

		assert.Nil(t, err)
		assert.Equal(t, "+8D VDL2", buf.String())
	})

	// Test getOutputSize with zero length input
	t.Run("getOutputSize zero length", func(t *testing.T) {
		encoder := NewStdEncoder()
		result := encoder.Encode([]byte{})
		assert.Nil(t, result)
		assert.Equal(t, 0, len(result))
	})

	// Test getOutputSize function directly for 100% coverage
	t.Run("getOutputSize function direct test", func(t *testing.T) {
		encoder := NewStdEncoder()

		// Test with zero length (this branch is logically unreachable, but we test it for coverage)
		// Since getOutputSize is a private method, we can't call it directly
		// Instead, let's test the edge case by creating a very specific scenario

		// Test with 1 byte input (should produce 2 characters)
		result := encoder.Encode([]byte{42})
		assert.Equal(t, 2, len(result))

		// Test with 2 bytes input (should produce 3 characters)
		result = encoder.Encode([]byte{42, 43})
		assert.Equal(t, 3, len(result))

		// Test with 3 bytes input (should produce 5 characters: 3 + 2)
		result = encoder.Encode([]byte{42, 43, 44})
		assert.Equal(t, 5, len(result))

		// Test with 4 bytes input (2 pairs, should produce 6 characters)
		result = encoder.Encode([]byte{42, 43, 44, 45})
		assert.Equal(t, 6, len(result))

		// Test with 5 bytes input (2 pairs + 1 single, should produce 8 characters)
		result = encoder.Encode([]byte{42, 43, 44, 45, 46})
		assert.Equal(t, 8, len(result))

		// Test with 6 bytes input (3 pairs, should produce 9 characters)
		result = encoder.Encode([]byte{42, 43, 44, 45, 46, 47})
		assert.Equal(t, 9, len(result))

		// Test with 7 bytes input (3 pairs + 1 single, should produce 11 characters)
		result = encoder.Encode([]byte{42, 43, 44, 45, 46, 47, 48})
		assert.Equal(t, 11, len(result))

		// Test with 8 bytes input (4 pairs, should produce 12 characters)
		result = encoder.Encode([]byte{42, 43, 44, 45, 46, 47, 48, 49})
		assert.Equal(t, 12, len(result))

		// Test with 9 bytes input (4 pairs + 1 single, should produce 14 characters)
		result = encoder.Encode([]byte{42, 43, 44, 45, 46, 47, 48, 49, 50})
		assert.Equal(t, 14, len(result))

		// Test with 10 bytes input (5 pairs, should produce 15 characters)
		result = encoder.Encode([]byte{42, 43, 44, 45, 46, 47, 48, 49, 50, 51})
		assert.Equal(t, 15, len(result))
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
		encoded := []byte("%69 VDL2")
		decoded, err := decoder.Decode(encoded)
		assert.Nil(t, err)
		assert.Equal(t, []byte("Hello"), decoded)
	})

	t.Run("decode with different byte counts", func(t *testing.T) {
		decoder := NewStdDecoder()

		// Test single byte
		encoded := []byte(".0")
		decoded, err := decoder.Decode(encoded)
		assert.Nil(t, err)
		assert.Equal(t, []byte{42}, decoded)

		// Test two bytes
		encoded = []byte("+E5")
		decoded, err = decoder.Decode(encoded)
		assert.Nil(t, err)
		assert.Equal(t, []byte{42, 43}, decoded)

		// Test three bytes
		encoded = []byte("+E5:0")
		decoded, err = decoder.Decode(encoded)
		assert.Nil(t, err)
		assert.Equal(t, []byte{42, 43, 44}, decoded)

		// Test four bytes
		encoded = []byte("+E5EQ5")
		decoded, err = decoder.Decode(encoded)
		assert.Nil(t, err)
		assert.Equal(t, []byte{42, 43, 44, 45}, decoded)

		// Test five bytes
		encoded = []byte("+E5EQ511")
		decoded, err = decoder.Decode(encoded)
		assert.Nil(t, err)
		assert.Equal(t, []byte{42, 43, 44, 45, 46}, decoded)
	})

	t.Run("decode all zeros", func(t *testing.T) {
		decoder := NewStdDecoder()
		encoded := []byte("000000")
		decoded, err := decoder.Decode(encoded)
		assert.Nil(t, err)
		assert.Equal(t, []byte{0, 0, 0, 0}, decoded)
	})

	t.Run("decode unicode string", func(t *testing.T) {
		decoder := NewStdDecoder()
		encoded := []byte("C-SEFK*.K7-SL3JY+I")
		decoded, err := decoder.Decode(encoded)
		assert.Nil(t, err)
		assert.Equal(t, []byte("你好世界"), decoded)
	})

	t.Run("decode binary data", func(t *testing.T) {
		decoder := NewStdDecoder()
		encoded := []byte("1002H0RAW")
		decoded, err := decoder.Decode(encoded)
		assert.Nil(t, err)
		assert.Equal(t, []byte{0x00, 0x01, 0x02, 0xFF, 0xFE, 0xFD}, decoded)
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

	t.Run("decode value exceeds maxUint16", func(t *testing.T) {
		decoder := NewStdDecoder()
		result, err := decoder.Decode([]byte(":::"))
		assert.Nil(t, result)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "illegal data")
	})

	t.Run("decode value exceeds 255", func(t *testing.T) {
		decoder := NewStdDecoder()
		result, err := decoder.Decode([]byte("::"))
		assert.Nil(t, result)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "illegal data")
	})

	t.Run("decode with unicode character", func(t *testing.T) {
		decoder := NewStdDecoder()
		// Create input with Unicode character > 255
		// Use a character that is definitely > 255 (e.g., 0x100 = 256)
		// Create a byte slice with a character > 255
		unicodeInput := make([]byte, 3)
		unicodeInput[0] = 'A'
		unicodeInput[1] = 0x00 // This will be replaced with a character > 255
		unicodeInput[2] = 'C'

		// Replace the middle character with a value > 255
		// We need to create a byte slice that contains a value > 255
		// Since Go byte is uint8 (0-255), we need to use a different approach
		// Let's create a slice with a rune that is > 255
		unicodeInput = []byte("A")
		unicodeInput = append(unicodeInput, 0x00) // This will be replaced
		unicodeInput = append(unicodeInput, []byte("C")...)

		// Now replace the middle byte with a value > 255
		// We need to use a different approach since Go byte is uint8
		// Let's create a slice with a character that is not in the base45 alphabet
		unicodeInput = []byte("A")
		unicodeInput = append(unicodeInput, 0x80) // 128, which is valid
		unicodeInput = append(unicodeInput, []byte("C")...)

		// Actually, let's use a different approach - create an invalid base45 character
		// that is not in the alphabet
		unicodeInput = []byte("A")
		unicodeInput = append(unicodeInput, 0x7F) // 127, which is not in base45 alphabet
		unicodeInput = append(unicodeInput, []byte("C")...)

		result, err := decoder.Decode(unicodeInput)
		assert.Nil(t, result)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid character")
	})
}

func TestStdEncoderDecoder_ErrorFlags(t *testing.T) {
	t.Run("encoder with existing error", func(t *testing.T) {
		enc := NewStdEncoder()
		enc.Error = errors.New("preset error")
		out := enc.Encode([]byte("hello"))
		assert.Nil(t, out)
	})

	t.Run("decoder with existing error", func(t *testing.T) {
		dec := NewStdDecoder()
		dec.Error = errors.New("preset error")
		out, err := dec.Decode([]byte("%69 VDL2"))
		assert.Nil(t, out)
		assert.EqualError(t, err, "preset error")
	})
}

func TestInternalSizeHelpers(t *testing.T) {
	t.Run("encoder.getOutputSize direct", func(t *testing.T) {
		enc := NewStdEncoder()
		// 覆盖 inputLen==0 分支
		sz0 := enc.getOutputSize(0)
		assert.Equal(t, 0, sz0)
		// 常规分支：偶数/奇数长度
		assert.Equal(t, 3, enc.getOutputSize(2))
		assert.Equal(t, 5, enc.getOutputSize(3))
	})

	t.Run("decoder.getDecodedSize direct", func(t *testing.T) {
		dec := NewStdDecoder()
		// 覆盖 encodedLen==0 分支
		sz0 := dec.getDecodedSize(0)
		assert.Equal(t, 0, sz0)
		// 常规分支：3 的倍数与余 2
		assert.Equal(t, 2, dec.getDecodedSize(3))
		assert.Equal(t, 1, dec.getDecodedSize(2))
		assert.Equal(t, 3, dec.getDecodedSize(5))
		// 额外覆盖：余 1 的情况虽然非法，但函数行为应是 groups*2 + 0
		assert.Equal(t, 2, dec.getDecodedSize(4))
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

	t.Run("write with writer error", func(t *testing.T) {
		// Test that Write properly handles writer errors
		errorWriter := mock.NewErrorWriteCloser(errors.New("writer error"))
		encoder := NewStreamEncoder(errorWriter)

		// Write data that will trigger encoding and writing
		data := []byte("ab") // 2 bytes = complete pair
		n, err := encoder.Write(data)

		assert.Equal(t, 2, n)
		assert.Error(t, err)
		assert.Equal(t, "writer error", err.Error())
	})

	t.Run("write with remainder buffering", func(t *testing.T) {
		var buf bytes.Buffer
		encoder := NewStreamEncoder(&buf)

		// Write 1 byte (incomplete pair)
		data1 := []byte("a")
		n1, err1 := encoder.Write(data1)
		assert.Equal(t, 1, n1)
		assert.Nil(t, err1)
		assert.Empty(t, buf.String()) // Nothing written yet

		// Write 1 more byte to complete the pair
		data2 := []byte("b")
		n2, err2 := encoder.Write(data2)
		assert.Equal(t, 1, n2)
		assert.Nil(t, err2)
		assert.Equal(t, "0EC", buf.String()) // Now the pair is encoded

		// Close to handle any remaining bytes
		err := encoder.Close()
		assert.Nil(t, err)
	})

	t.Run("write with buffer and new data combination", func(t *testing.T) {
		var buf bytes.Buffer
		encoder := NewStreamEncoder(&buf)

		// Write 1 byte (buffered)
		data1 := []byte("a")
		n1, err1 := encoder.Write(data1)
		assert.Equal(t, 1, n1)
		assert.Nil(t, err1)
		assert.Empty(t, buf.String())

		// Write 3 bytes (1 buffered + 3 new = 4 bytes = 2 pairs)
		data2 := []byte("bcd")
		n2, err2 := encoder.Write(data2)
		assert.Equal(t, 3, n2)
		assert.Nil(t, err2)
		// Should have encoded 2 pairs: "ab" and "cd"
		assert.Contains(t, buf.String(), "0EC") // "ab" encoded
	})
}

func TestStreamEncoder_Close(t *testing.T) {
	t.Run("close with data", func(t *testing.T) {
		var buf bytes.Buffer
		encoder := NewStreamEncoder(&buf)

		encoder.Write([]byte("hello"))
		err := encoder.Close()

		assert.Nil(t, err)
		assert.Equal(t, "+8D VDL2", buf.String())
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
		// Test that Close properly handles write errors when encoding remaining bytes
		errorWriter := mock.NewErrorWriteCloser(errors.New("write error"))
		encoder := NewStreamEncoder(errorWriter)

		// Write a single byte that will be buffered
		n, err := encoder.Write([]byte("h")) // 1 byte = incomplete pair
		assert.Equal(t, 1, n)
		assert.Nil(t, err) // Write should succeed as it only buffers

		// Close should fail when trying to encode the remaining byte
		err = encoder.Close()
		assert.Error(t, err)
		assert.Equal(t, "write error", err.Error())
	})
}

func TestStreamDecoder_Read(t *testing.T) {
	t.Run("read decoded data", func(t *testing.T) {
		encoded := "+8D VDL2"
		file := mock.NewFile([]byte(encoded), "test.txt")
		decoder := NewStreamDecoder(file)

		buf := make([]byte, 10)
		n, err := decoder.Read(buf)

		assert.Equal(t, 5, n)
		assert.Nil(t, err)
		assert.Equal(t, []byte("hello"), buf[:n])
	})

	t.Run("read with large buffer", func(t *testing.T) {
		encoded := "+8D VDL2"
		file := mock.NewFile([]byte(encoded), "test.txt")
		decoder := NewStreamDecoder(file)

		buf := make([]byte, 100)
		n, err := decoder.Read(buf)

		assert.Equal(t, 5, n)
		assert.Nil(t, err)
		assert.Equal(t, []byte("hello"), buf[:n])
	})

	t.Run("read with small buffer", func(t *testing.T) {
		encoded := "+8D VDL2"
		file := mock.NewFile([]byte(encoded), "test.txt")
		decoder := NewStreamDecoder(file)

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
		file := mock.NewFile([]byte("ABC DEF"), "test.txt")
		decoder := NewStreamDecoder(file)

		buf := make([]byte, 10)
		n, err := decoder.Read(buf)

		assert.Equal(t, 0, n)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid length")
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
		file := mock.NewFile([]byte{}, "test.txt")
		decoder := NewStreamDecoder(file)

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
		result, err := decoder.Decode([]byte("ABC!"))
		assert.Error(t, err)
		assert.Nil(t, result)
	})

	t.Run("encoder invalid alphabet", func(t *testing.T) {
		encoder := NewStdEncoder()
		// Create encoder with invalid alphabet length
		encoder.alphabet = "invalid"
		// The encoder will not validate alphabet length in Encode method
		// So we just test that it works with the invalid alphabet
		result := encoder.Encode([]byte("hello"))
		assert.NotNil(t, result)
		assert.Nil(t, encoder.Error)
	})

	t.Run("decoder invalid alphabet", func(t *testing.T) {
		decoder := NewStdDecoder()
		// Create decoder with invalid alphabet length
		decoder.alphabet = "invalid"
		// The decoder will not validate alphabet length in Decode method
		// So we just test that it works with the invalid alphabet
		result, err := decoder.Decode([]byte("ABC"))
		assert.NotNil(t, result)
		assert.Nil(t, err)
		assert.Nil(t, decoder.Error)
	})

	t.Run("invalid length error message", func(t *testing.T) {
		err := InvalidLengthError{Length: 3, Mod: 3}
		expected := "coding/base45: invalid length n=3. It should be n mod 3 = [0, 2] NOT n mod 3 = 3"
		assert.Equal(t, expected, err.Error())
	})

	t.Run("invalid character error message", func(t *testing.T) {
		err := InvalidCharacterError{Char: '!', Position: 5}
		expected := "coding/base45: invalid character ! at position: 5"
		assert.Equal(t, expected, err.Error())
	})

	t.Run("corrupt input error message", func(t *testing.T) {
		err := CorruptInputError(5)
		expected := "coding/base45: illegal data at input byte 5"
		assert.Equal(t, expected, err.Error())
	})
}

func TestStreamError(t *testing.T) {
	t.Run("stream encoder close with writer error", func(t *testing.T) {
		errorWriter := mock.NewErrorWriteCloser(assert.AnError)
		encoder := NewStreamEncoder(errorWriter)
		// Write a single byte that will be buffered (not immediately encoded)
		_, err := encoder.Write([]byte("t"))
		assert.NoError(t, err)

		// Close should fail when trying to encode the buffered byte
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

	t.Run("read with invalid data", func(t *testing.T) {
		file := mock.NewFile([]byte("invalid!"), "test.txt")
		decoder := NewStreamDecoder(file)

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
		file := mock.NewFile([]byte("test"), "test.txt")
		decoder := NewStreamDecoder(file)
		decoder.(*StreamDecoder).Error = assert.AnError

		buf := make([]byte, 10)
		n, err := decoder.Read(buf)
		assert.Error(t, err)
		assert.Equal(t, 0, n)
	})
}
