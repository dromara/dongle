package md2

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMD2_TestVectors(t *testing.T) {
	// Based on RFC 1319 and known MD2 test vectors
	testCases := []struct {
		input    string
		expected string
		desc     string
	}{
		{
			input:    "",
			expected: "8350e5a3e24c153df2275c9f80692773",
			desc:     "empty string",
		},
		{
			input:    "a",
			expected: "32ec01ec4a6dac72c0ab96fb34c0b5d1",
			desc:     "single character",
		},
		{
			input:    "abc",
			expected: "da853b0d3f88d99b30283a69e6ded6bb",
			desc:     "three characters",
		},
		{
			input:    "message digest",
			expected: "ab4f496bfb2a530b219ff33031fe06b0",
			desc:     "message digest",
		},
		{
			input:    "abcdefghijklmnopqrstuvwxyz",
			expected: "4e8ddff3650292ab5a4108c3aa47940b",
			desc:     "alphabet",
		},
		{
			input:    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
			expected: "da33def2a42df13975352846c30338cd",
			desc:     "alphanumeric",
		},
		{
			input:    "12345678901234567890123456789012345678901234567890123456789012345678901234567890",
			expected: "d5976f79d83d3a0dc9806c3c66f3efd8",
			desc:     "digits",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			hasher := New()
			hasher.Write([]byte(tc.input))
			hash := hasher.Sum(nil)
			actual := hex.EncodeToString(hash)

			assert.Equal(t, tc.expected, actual,
				"Input: '%s', Expected: %s, Got: %s", tc.input, tc.expected, actual)
		})
	}
}

func TestMD2_EdgeCases(t *testing.T) {
	testCases := []struct {
		input    string
		expected string
		desc     string
	}{
		{
			input:    "The quick brown fox jumps over the lazy dog",
			expected: "03d85a0d629d2c442e987525319fc471",
			desc:     "quick brown fox",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			hasher := New()
			hasher.Write([]byte(tc.input))
			hash := hasher.Sum(nil)
			actual := hex.EncodeToString(hash)

			assert.Equal(t, tc.expected, actual,
				"Input: %q, Expected: %s, Got: %s", tc.input, tc.expected, actual)
		})
	}
}

func TestMD2_BlockSize(t *testing.T) {
	hasher := New()
	assert.Equal(t, BlockSize, hasher.BlockSize())
}

func TestMD2_Size(t *testing.T) {
	hasher := New()
	assert.Equal(t, BlockSize, hasher.Size())
}

func TestMD2_Reset(t *testing.T) {
	hasher := New()

	// Write some data
	hasher.Write([]byte("test"))
	hash1 := hasher.Sum(nil)

	// Reset and write the same data
	hasher.Reset()
	hasher.Write([]byte("test"))
	hash2 := hasher.Sum(nil)

	// Results should be identical
	assert.Equal(t, hash1, hash2)
}

func TestMD2_WriteMultiple(t *testing.T) {
	hasher := New()

	// Write data in multiple chunks
	hasher.Write([]byte("Hello"))
	hasher.Write([]byte(", "))
	hasher.Write([]byte("World!"))

	hash1 := hex.EncodeToString(hasher.Sum(nil))

	// Write the same data in one chunk
	hasher.Reset()
	hasher.Write([]byte("Hello, World!"))
	hash2 := hex.EncodeToString(hasher.Sum(nil))

	// Results should be identical
	assert.Equal(t, hash1, hash2)
}

func TestMD2_Sum(t *testing.T) {
	hasher := New()
	hasher.Write([]byte("test"))

	// Test Sum(nil)
	hash1 := hasher.Sum(nil)
	assert.Equal(t, BlockSize, len(hash1))

	// Test Sum with existing slice
	prefix := []byte("prefix")
	hash2 := hasher.Sum(prefix)
	assert.Equal(t, len(prefix)+BlockSize, len(hash2))
	assert.Equal(t, prefix, hash2[:len(prefix)])
	assert.Equal(t, hash1, hash2[len(prefix):])
}

func TestMD2_LargeData(t *testing.T) {
	hasher := New()

	// Create large data
	data := make([]byte, 10000)
	for i := range data {
		data[i] = byte(i % 256)
	}

	hasher.Write(data)
	hash := hasher.Sum(nil)

	// Hash should be correct size
	assert.Equal(t, BlockSize, len(hash))

	// Hash should not be all zeros
	allZero := true
	for _, b := range hash {
		if b != 0 {
			allZero = false
			break
		}
	}
	assert.False(t, allZero, "Hash should not be all zeros")
}

func TestMD2_Consistency(t *testing.T) {
	// Test that multiple instances produce the same result
	input := "test input"

	hasher1 := New()
	hasher1.Write([]byte(input))
	hash1 := hex.EncodeToString(hasher1.Sum(nil))

	hasher2 := New()
	hasher2.Write([]byte(input))
	hash2 := hex.EncodeToString(hasher2.Sum(nil))

	assert.Equal(t, hash1, hash2, "Multiple instances should produce identical results")
}

func TestMD2_BinaryData(t *testing.T) {
	// Test with binary data
	binaryData := []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f}

	hasher := New()
	hasher.Write(binaryData)
	hash := hasher.Sum(nil)

	// Hash should be correct size
	assert.Equal(t, BlockSize, len(hash))

	// Hash should not be all zeros
	allZero := true
	for _, b := range hash {
		if b != 0 {
			allZero = false
			break
		}
	}
	assert.False(t, allZero, "Hash should not be all zeros")
}

func TestMD2_UnicodeData(t *testing.T) {
	// Test with Unicode data
	unicodeData := "你好世界"

	hasher := New()
	hasher.Write([]byte(unicodeData))
	hash := hasher.Sum(nil)

	// Hash should be correct size
	assert.Equal(t, BlockSize, len(hash))

	// Hash should not be all zeros
	allZero := true
	for _, b := range hash {
		if b != 0 {
			allZero = false
			break
		}
	}
	assert.False(t, allZero, "Hash should not be all zeros")
}

func TestMD2_WriteEdgeCases(t *testing.T) {
	t.Run("write empty slice", func(t *testing.T) {
		hasher := New()
		n, err := hasher.Write([]byte{})
		assert.NoError(t, err)
		assert.Equal(t, 0, n)
	})

	t.Run("write single byte", func(t *testing.T) {
		hasher := New()
		n, err := hasher.Write([]byte{0x01})
		assert.NoError(t, err)
		assert.Equal(t, 1, n)
	})

	t.Run("write exactly one block", func(t *testing.T) {
		hasher := New()
		data := make([]byte, BlockSize)
		for i := range data {
			data[i] = byte(i)
		}
		n, err := hasher.Write(data)
		assert.NoError(t, err)
		assert.Equal(t, BlockSize, n)
	})

	t.Run("write multiple blocks", func(t *testing.T) {
		hasher := New()
		data := make([]byte, BlockSize*3)
		for i := range data {
			data[i] = byte(i)
		}
		n, err := hasher.Write(data)
		assert.NoError(t, err)
		assert.Equal(t, BlockSize*3, n)
	})

	t.Run("write partial block then complete", func(t *testing.T) {
		hasher := New()

		// Write partial block
		partial := []byte{0x01, 0x02, 0x03}
		n, err := hasher.Write(partial)
		assert.NoError(t, err)
		assert.Equal(t, 3, n)

		// Write more data to complete the block
		more := make([]byte, BlockSize-3)
		for i := range more {
			more[i] = byte(i + 4)
		}
		n, err = hasher.Write(more)
		assert.NoError(t, err)
		assert.Equal(t, BlockSize-3, n)
	})

	t.Run("write large data in chunks", func(t *testing.T) {
		hasher := New()
		totalSize := 10000
		chunkSize := 100

		for i := 0; i < totalSize; i += chunkSize {
			end := i + chunkSize
			if end > totalSize {
				end = totalSize
			}

			chunk := make([]byte, end-i)
			for j := range chunk {
				chunk[j] = byte(i + j)
			}

			n, err := hasher.Write(chunk)
			assert.NoError(t, err)
			assert.Equal(t, len(chunk), n)
		}

		hash := hasher.Sum(nil)
		assert.Equal(t, BlockSize, len(hash))
	})
}
