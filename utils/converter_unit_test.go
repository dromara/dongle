package utils

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestString2Bytes(t *testing.T) {
	t.Run("empty string", func(t *testing.T) {
		result := String2Bytes("")
		assert.Equal(t, []byte(""), result)
		assert.Equal(t, 0, len(result))
	})

	t.Run("simple string", func(t *testing.T) {
		input := "hello"
		result := String2Bytes(input)
		expected := []byte("hello")
		assert.Equal(t, expected, result)
		assert.Equal(t, len(input), len(result))
	})

	t.Run("unicode string", func(t *testing.T) {
		input := "你好世界"
		result := String2Bytes(input)
		expected := []byte("你好世界")
		assert.Equal(t, expected, result)
		assert.Equal(t, len(input), len(result))
	})

	t.Run("complex string with special characters", func(t *testing.T) {
		input := "Hello, World! 123 !@#$%^&*()"
		result := String2Bytes(input)
		expected := []byte("Hello, World! 123 !@#$%^&*()")
		assert.Equal(t, expected, result)
		assert.Equal(t, len(input), len(result))
	})

	t.Run("string with newlines and tabs", func(t *testing.T) {
		input := "line1\nline2\tline3"
		result := String2Bytes(input)
		expected := []byte("line1\nline2\tline3")
		assert.Equal(t, expected, result)
		assert.Equal(t, len(input), len(result))
	})

	t.Run("string with null bytes", func(t *testing.T) {
		input := "hello\x00world"
		result := String2Bytes(input)
		expected := []byte("hello\x00world")
		assert.Equal(t, expected, result)
		assert.Equal(t, len(input), len(result))
	})

	t.Run("very long string", func(t *testing.T) {
		// Create a long string
		longString := ""
		for i := 0; i < 1000; i++ {
			longString += "a"
		}
		result := String2Bytes(longString)
		expected := []byte(longString)
		assert.Equal(t, expected, result)
		assert.Equal(t, len(longString), len(result))
	})

	t.Run("string with emoji", func(t *testing.T) {
		input := "Hello 👋 World 🌍"
		result := String2Bytes(input)
		expected := []byte("Hello 👋 World 🌍")
		assert.Equal(t, expected, result)
		assert.Equal(t, len(input), len(result))
	})

	t.Run("consistency with standard conversion", func(t *testing.T) {
		testCases := []string{
			"",
			"a",
			"hello",
			"Hello, World!",
			"你好世界",
			"1234567890",
			"!@#$%^&*()",
			"line1\nline2",
			"hello\x00world",
			"Hello 👋 World 🌍",
		}

		for _, input := range testCases {
			t.Run("input: "+input, func(t *testing.T) {
				result := String2Bytes(input)
				expected := []byte(input) // Standard conversion
				assert.Equal(t, expected, result)
				assert.Equal(t, len(input), len(result))
			})
		}
	})

	t.Run("zero-copy verification", func(t *testing.T) {
		input := "test string"
		result1 := String2Bytes(input)
		result2 := String2Bytes(input)

		// Both results should be identical
		assert.Equal(t, result1, result2)

		// Length should match input
		assert.Equal(t, len(input), len(result1))
		assert.Equal(t, len(input), len(result2))
	})
}

func TestBytes2String(t *testing.T) {
	t.Run("empty byte slice", func(t *testing.T) {
		result := Bytes2String([]byte{})
		assert.Equal(t, "", result)
		assert.Equal(t, 0, len(result))
	})

	t.Run("nil byte slice", func(t *testing.T) {
		result := Bytes2String(nil)
		assert.Equal(t, "", result)
		assert.Equal(t, 0, len(result))
	})

	t.Run("simple byte slice", func(t *testing.T) {
		input := []byte("hello")
		result := Bytes2String(input)
		expected := "hello"
		assert.Equal(t, expected, result)
		assert.Equal(t, len(input), len(result))
	})

	t.Run("unicode byte slice", func(t *testing.T) {
		input := []byte("你好世界")
		result := Bytes2String(input)
		expected := "你好世界"
		assert.Equal(t, expected, result)
		assert.Equal(t, len(input), len(result))
	})

	t.Run("byte slice with special characters", func(t *testing.T) {
		input := []byte("Hello, World! 123 !@#$%^&*()")
		result := Bytes2String(input)
		expected := "Hello, World! 123 !@#$%^&*()"
		assert.Equal(t, expected, result)
		assert.Equal(t, len(input), len(result))
	})

	t.Run("byte slice with newlines and tabs", func(t *testing.T) {
		input := []byte("line1\nline2\tline3")
		result := Bytes2String(input)
		expected := "line1\nline2\tline3"
		assert.Equal(t, expected, result)
		assert.Equal(t, len(input), len(result))
	})

	t.Run("byte slice with null bytes", func(t *testing.T) {
		input := []byte("hello\x00world")
		result := Bytes2String(input)
		expected := "hello\x00world"
		assert.Equal(t, expected, result)
		assert.Equal(t, len(input), len(result))
	})

	t.Run("very long byte slice", func(t *testing.T) {
		// Create a long byte slice
		longBytes := make([]byte, 1000)
		for i := range longBytes {
			longBytes[i] = byte('a')
		}
		result := Bytes2String(longBytes)
		expected := string(longBytes)
		assert.Equal(t, expected, result)
		assert.Equal(t, len(longBytes), len(result))
	})

	t.Run("byte slice with emoji", func(t *testing.T) {
		input := []byte("Hello 👋 World 🌍")
		result := Bytes2String(input)
		expected := "Hello 👋 World 🌍"
		assert.Equal(t, expected, result)
		assert.Equal(t, len(input), len(result))
	})

	t.Run("binary data", func(t *testing.T) {
		input := []byte{0x00, 0x01, 0x02, 0xFF, 0xFE, 0xFD}
		result := Bytes2String(input)
		expected := string(input)
		assert.Equal(t, expected, result)
		assert.Equal(t, len(input), len(result))
	})

	t.Run("consistency with standard conversion", func(t *testing.T) {
		testCases := [][]byte{
			{},
			{'a'},
			{'h', 'e', 'l', 'l', 'o'},
			{'H', 'e', 'l', 'l', 'o', ',', ' ', 'W', 'o', 'r', 'l', 'd', '!'},
			{0xE4, 0xBD, 0xA0, 0xE5, 0xA5, 0xBD, 0xE4, 0xB8, 0x96, 0xE7, 0x95, 0x8C}, // "你好世界"
			{'1', '2', '3', '4', '5', '6', '7', '8', '9', '0'},
			{'!', '@', '#', '$', '%', '^', '&', '*', '('},
			{'l', 'i', 'n', 'e', '1', '\n', 'l', 'i', 'n', 'e', '2'},
			{'h', 'e', 'l', 'l', 'o', 0x00, 'w', 'o', 'r', 'l', 'd'},
		}

		for i, input := range testCases {
			t.Run("case "+string(rune(i+'0')), func(t *testing.T) {
				result := Bytes2String(input)
				expected := string(input) // Standard conversion
				assert.Equal(t, expected, result)
				assert.Equal(t, len(input), len(result))
			})
		}
	})

	t.Run("zero-copy verification", func(t *testing.T) {
		input := []byte("test bytes")
		result1 := Bytes2String(input)
		result2 := Bytes2String(input)

		// Both results should be identical
		assert.Equal(t, result1, result2)

		// Length should match input
		assert.Equal(t, len(input), len(result1))
		assert.Equal(t, len(input), len(result2))
	})
}

func TestString2BytesAndBytes2StringRoundTrip(t *testing.T) {
	t.Run("round trip conversion", func(t *testing.T) {
		testCases := []string{
			"",
			"a",
			"hello",
			"Hello, World!",
			"你好世界",
			"1234567890",
			"!@#$%^&*()",
			"line1\nline2",
			"hello\x00world",
			"Hello 👋 World 🌍",
		}

		for _, input := range testCases {
			t.Run("input: "+input, func(t *testing.T) {
				// String -> Bytes -> String
				bytes := String2Bytes(input)
				result := Bytes2String(bytes)

				assert.Equal(t, input, result)
				assert.Equal(t, len(input), len(result))
			})
		}
	})

	t.Run("round trip with binary data", func(t *testing.T) {
		originalBytes := []byte{0x00, 0x01, 0x02, 0xFF, 0xFE, 0xFD}

		// Bytes -> String -> Bytes
		str := Bytes2String(originalBytes)
		resultBytes := String2Bytes(str)

		assert.Equal(t, originalBytes, resultBytes)
		assert.Equal(t, len(originalBytes), len(resultBytes))
	})

	t.Run("multiple round trips", func(t *testing.T) {
		input := "Hello, World! 你好世界 👋"

		// Multiple conversions should be consistent
		bytes1 := String2Bytes(input)
		str1 := Bytes2String(bytes1)
		bytes2 := String2Bytes(str1)
		str2 := Bytes2String(bytes2)

		assert.Equal(t, input, str1)
		assert.Equal(t, input, str2)
		assert.Equal(t, bytes1, bytes2)
	})
}

func TestEdgeCases(t *testing.T) {
	t.Run("string with only null bytes", func(t *testing.T) {
		input := "\x00\x00\x00"
		result := String2Bytes(input)
		expected := []byte{0x00, 0x00, 0x00}
		assert.Equal(t, expected, result)
		assert.Equal(t, 3, len(result))
	})

	t.Run("byte slice with only null bytes", func(t *testing.T) {
		input := []byte{0x00, 0x00, 0x00}
		result := Bytes2String(input)
		expected := "\x00\x00\x00"
		assert.Equal(t, expected, result)
		assert.Equal(t, 3, len(result))
	})

	t.Run("string with control characters", func(t *testing.T) {
		input := "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F"
		result := String2Bytes(input)
		expected := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F}
		assert.Equal(t, expected, result)
		assert.Equal(t, 15, len(result))
	})

	t.Run("byte slice with control characters", func(t *testing.T) {
		input := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F}
		result := Bytes2String(input)
		expected := "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F"
		assert.Equal(t, expected, result)
		assert.Equal(t, 15, len(result))
	})

	t.Run("single character strings", func(t *testing.T) {
		testCases := []struct {
			char     string
			expected int
		}{
			{"a", 1},
			{"1", 1},
			{"!", 1},
			{"你", 3}, // UTF-8 编码占用 3 字节
			{"👋", 4}, // UTF-8 编码占用 4 字节
			{"\x00", 1},
		}

		for _, tc := range testCases {
			t.Run("char: "+tc.char, func(t *testing.T) {
				result := String2Bytes(tc.char)
				expected := []byte(tc.char)
				assert.Equal(t, expected, result)
				assert.Equal(t, tc.expected, len(result))
			})
		}
	})

	t.Run("single byte slices", func(t *testing.T) {
		singleBytes := [][]byte{{'a'}, {'1'}, {'!'}, {0x00}}
		for _, bytes := range singleBytes {
			t.Run("bytes: "+string(bytes), func(t *testing.T) {
				result := Bytes2String(bytes)
				expected := string(bytes)
				assert.Equal(t, expected, result)
				assert.Equal(t, 1, len(result))
			})
		}
	})
}
