package cipher

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNoPadding(t *testing.T) {
	t.Run("No padding with data", func(t *testing.T) {
		data := []byte("Hello, World!")
		padded := NewNoPadding(data)
		assert.Equal(t, data, padded)
	})

	t.Run("No unpadding with data", func(t *testing.T) {
		data := []byte("Hello, World!")
		unpadded := NewNoUnPadding(data)
		assert.Equal(t, data, unpadded)
	})

	t.Run("No padding with empty data", func(t *testing.T) {
		var data []byte
		padded := NewNoPadding(data)
		assert.Equal(t, data, padded)
	})

	t.Run("No unpadding with empty data", func(t *testing.T) {
		var data []byte
		unpadded := NewNoUnPadding(data)
		assert.Equal(t, data, unpadded)
	})
}

func TestZeroPadding(t *testing.T) {
	t.Run("Zero padding with partial block", func(t *testing.T) {
		data := []byte("Hello")
		blockSize := 8
		expected := []byte("Hello\x00\x00\x00")
		padded := NewZeroPadding(data, blockSize)
		assert.Equal(t, expected, padded)
	})

	t.Run("Zero padding with exact block size", func(t *testing.T) {
		data := []byte("12345678") // 8 bytes
		blockSize := 8
		expected := []byte("12345678") // No padding for exact block size
		padded := NewZeroPadding(data, blockSize)
		assert.Equal(t, expected, padded)
	})

	t.Run("Zero padding with exact block size 16", func(t *testing.T) {
		data := []byte("1234567890123456") // 16 bytes, exact multiple of 8
		blockSize := 8
		expected := []byte("1234567890123456") // No padding for exact block size
		padded := NewZeroPadding(data, blockSize)
		assert.Equal(t, expected, padded)
	})

	t.Run("Zero padding with multiple blocks", func(t *testing.T) {
		data := []byte("Hello World")
		blockSize := 4
		expected := []byte("Hello World\x00")
		padded := NewZeroPadding(data, blockSize)
		assert.Equal(t, expected, padded)
	})

	t.Run("Zero padding with empty data", func(t *testing.T) {
		var data []byte
		blockSize := 8
		padded := NewZeroPadding(data, blockSize)
		assert.Equal(t, data, padded) // Empty data returns as is with zero padding
	})

	t.Run("Zero unpadding with trailing zeros", func(t *testing.T) {
		data := []byte("Hello\x00\x00\x00")
		expected := []byte("Hello")
		unpadded := NewZeroUnPadding(data)
		assert.Equal(t, expected, unpadded)
	})

	t.Run("Zero unpadding with no trailing zeros", func(t *testing.T) {
		data := []byte("Hello")
		expected := []byte("Hello")
		unpadded := NewZeroUnPadding(data)
		assert.Equal(t, expected, unpadded)
	})

	t.Run("Zero unpadding with all zeros", func(t *testing.T) {
		data := []byte{0, 0, 0, 0}
		unpadded := NewZeroUnPadding(data)
		assert.Equal(t, []byte{}, unpadded)
	})

	t.Run("Zero unpadding with empty data", func(t *testing.T) {
		var data []byte
		unpadded := NewZeroUnPadding(data)
		assert.Nil(t, unpadded)
	})
}

func TestPKCS7Padding(t *testing.T) {
	t.Run("PKCS7 padding with 1 byte needed", func(t *testing.T) {
		data := []byte("Hello")
		blockSize := 8
		expected := []byte("Hello\x03\x03\x03")
		padded := NewPKCS7Padding(data, blockSize)
		assert.Equal(t, expected, padded)
	})

	t.Run("PKCS7 padding with 3 bytes needed", func(t *testing.T) {
		data := []byte("Hello")
		blockSize := 8
		expected := []byte("Hello\x03\x03\x03")
		padded := NewPKCS7Padding(data, blockSize)
		assert.Equal(t, expected, padded)
	})

	t.Run("PKCS7 padding with exact block size", func(t *testing.T) {
		data := []byte("12345678") // 8 bytes
		blockSize := 8
		expected := []byte("12345678\x08\x08\x08\x08\x08\x08\x08\x08")
		padded := NewPKCS7Padding(data, blockSize)
		assert.Equal(t, expected, padded)
	})

	t.Run("PKCS7 padding with empty data", func(t *testing.T) {
		var data []byte
		blockSize := 8
		expected := []byte{0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08}
		padded := NewPKCS7Padding(data, blockSize)
		assert.Equal(t, expected, padded)
	})

	t.Run("PKCS7 unpadding with 1 byte padding", func(t *testing.T) {
		data := []byte("Hello\x01")
		expected := []byte("Hello")
		unpadded := NewPKCS7UnPadding(data)
		assert.Equal(t, expected, unpadded)
	})

	t.Run("PKCS7 unpadding with 3 bytes padding", func(t *testing.T) {
		data := []byte("Hello\x03\x03\x03")
		expected := []byte("Hello")
		unpadded := NewPKCS7UnPadding(data)
		assert.Equal(t, expected, unpadded)
	})

	t.Run("PKCS7 unpadding with full block padding", func(t *testing.T) {
		data := []byte("\x08\x08\x08\x08\x08\x08\x08\x08")
		unpadded := NewPKCS7UnPadding(data)
		assert.Equal(t, []byte{}, unpadded)
	})

	t.Run("PKCS7 unpadding with invalid padding size", func(t *testing.T) {
		data := []byte("Hello\x09") // padding size > data length
		unpadded := NewPKCS7UnPadding(data)
		assert.Equal(t, data, unpadded) // Should return original data
	})

	t.Run("PKCS7 unpadding with invalid padding size larger than data", func(t *testing.T) {
		data := []byte("Hi\x10") // padding size 16 > data length 3
		unpadded := NewPKCS7UnPadding(data)
		assert.Equal(t, data, unpadded) // Should return original data
	})

	t.Run("PKCS7 unpadding with zero padding size", func(t *testing.T) {
		data := []byte("Hello\x00") // padding size 0
		unpadded := NewPKCS7UnPadding(data)
		assert.Equal(t, data, unpadded) // Should return original data
	})

	t.Run("PKCS7 unpadding with padding size equal to data length", func(t *testing.T) {
		data := []byte("\x01") // padding size 1, data length 1
		unpadded := NewPKCS7UnPadding(data)
		assert.Equal(t, []byte{}, unpadded) // Should return empty data
	})

	t.Run("PKCS7 unpadding with empty data", func(t *testing.T) {
		var data []byte
		unpadded := NewPKCS7UnPadding(data)
		assert.Nil(t, unpadded) // Should return nil
	})
}

func TestPKCS5Padding(t *testing.T) {
	t.Run("PKCS5 padding with 1 byte needed", func(t *testing.T) {
		data := []byte("1234567") // 7 bytes
		expected := []byte("1234567\x01")
		padded := NewPKCS5Padding(data)
		assert.Equal(t, expected, padded)
	})

	t.Run("PKCS5 padding with 3 bytes needed", func(t *testing.T) {
		data := []byte("12345") // 5 bytes
		expected := []byte("12345\x03\x03\x03")
		padded := NewPKCS5Padding(data)
		assert.Equal(t, expected, padded)
	})

	t.Run("PKCS5 padding with exact block size", func(t *testing.T) {
		data := []byte("12345678") // 8 bytes
		expected := []byte("12345678\x08\x08\x08\x08\x08\x08\x08\x08")
		padded := NewPKCS5Padding(data)
		assert.Equal(t, expected, padded)
	})

	t.Run("PKCS5 padding with empty data", func(t *testing.T) {
		var data []byte
		expected := []byte{0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08}
		padded := NewPKCS5Padding(data)
		assert.Equal(t, expected, padded)
	})

	t.Run("PKCS5 unpadding with 1 byte padding", func(t *testing.T) {
		data := []byte("1234567\x01")
		expected := []byte("1234567")
		unpadded := NewPKCS5UnPadding(data)
		assert.Equal(t, expected, unpadded)
	})

	t.Run("PKCS5 unpadding with 3 bytes padding", func(t *testing.T) {
		data := []byte("12345\x03\x03\x03")
		expected := []byte("12345")
		unpadded := NewPKCS5UnPadding(data)
		assert.Equal(t, expected, unpadded)
	})

	t.Run("PKCS5 unpadding with full block padding", func(t *testing.T) {
		data := []byte("\x08\x08\x08\x08\x08\x08\x08\x08")
		unpadded := NewPKCS5UnPadding(data)
		assert.Equal(t, []byte{}, unpadded)
	})
}

func TestAnsiX923Padding(t *testing.T) {
	t.Run("AnsiX923 padding with 1 byte needed", func(t *testing.T) {
		data := []byte("Hello")
		blockSize := 8
		expected := []byte("Hello\x00\x00\x03")
		padded := NewAnsiX923Padding(data, blockSize)
		assert.Equal(t, expected, padded)
	})

	t.Run("AnsiX923 padding with 3 bytes needed", func(t *testing.T) {
		data := []byte("Hello")
		blockSize := 8
		expected := []byte("Hello\x00\x00\x03")
		padded := NewAnsiX923Padding(data, blockSize)
		assert.Equal(t, expected, padded)
	})

	t.Run("AnsiX923 padding with exact block size", func(t *testing.T) {
		data := []byte("12345678") // 8 bytes
		blockSize := 8
		expected := []byte("12345678\x00\x00\x00\x00\x00\x00\x00\x08")
		padded := NewAnsiX923Padding(data, blockSize)
		assert.Equal(t, expected, padded)
	})

	t.Run("AnsiX923 padding with exact block size 16", func(t *testing.T) {
		data := []byte("1234567890123456") // 16 bytes, exact multiple of 8
		blockSize := 8
		expected := []byte("1234567890123456\x00\x00\x00\x00\x00\x00\x00\x08")
		padded := NewAnsiX923Padding(data, blockSize)
		assert.Equal(t, expected, padded)
	})

	t.Run("AnsiX923 padding with multiple blocks", func(t *testing.T) {
		data := []byte("Hello World")
		blockSize := 4
		expected := []byte("Hello World\x01")
		padded := NewAnsiX923Padding(data, blockSize)
		assert.Equal(t, expected, padded)
	})

	t.Run("AnsiX923 padding with empty data", func(t *testing.T) {
		var data []byte
		blockSize := 8
		expected := []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08}
		padded := NewAnsiX923Padding(data, blockSize)
		assert.Equal(t, expected, padded)
	})

	t.Run("AnsiX923 unpadding with 1 byte padding", func(t *testing.T) {
		// Create test data with proper AnsiX923 padding (all zeros except last byte)
		data := make([]byte, 8)
		copy(data, "1234567")
		data[7] = 1 // Last byte is padding length
		expected := []byte("1234567")
		unpadded := NewAnsiX923UnPadding(data)
		assert.Equal(t, expected, unpadded)
	})

	t.Run("AnsiX923 unpadding with 3 bytes padding", func(t *testing.T) {
		// Create test data with proper AnsiX923 padding (all zeros except last byte)
		data := make([]byte, 8)
		copy(data, "12345")
		data[7] = 3 // Last byte is padding length
		expected := []byte("12345")
		unpadded := NewAnsiX923UnPadding(data)
		assert.Equal(t, expected, unpadded)
	})

	t.Run("AnsiX923 unpadding with full block padding", func(t *testing.T) {
		data := []byte{0, 0, 0, 0, 0, 0, 0, 8}
		unpadded := NewAnsiX923UnPadding(data)
		assert.Equal(t, []byte{}, unpadded)
	})

	t.Run("AnsiX923 unpadding with invalid padding size", func(t *testing.T) {
		data := []byte{0, 0, 0, 0, 0, 0, 0, 9} // padding size > data length
		unpadded := NewAnsiX923UnPadding(data)
		assert.Equal(t, data, unpadded) // Should return original data
	})

	t.Run("AnsiX923 unpadding with zero padding size", func(t *testing.T) {
		data := []byte{0, 0, 0, 0, 0, 0, 0, 0} // padding size = 0
		unpadded := NewAnsiX923UnPadding(data)
		assert.Equal(t, data, unpadded) // Should return original data
	})

	t.Run("AnsiX923 unpadding with non-zero padding bytes", func(t *testing.T) {
		// Create test data with non-zero padding bytes
		data := make([]byte, 8)
		copy(data, "123456")
		data[6] = 0x01 // Non-zero padding byte
		data[7] = 0x02 // Padding length
		unpadded := NewAnsiX923UnPadding(data)
		assert.Equal(t, data, unpadded) // Should return original data due to invalid padding
	})

	t.Run("AnsiX923 unpadding with padding size equal to data length", func(t *testing.T) {
		data := []byte{0, 0, 0, 0, 0, 0, 0, 8} // padding size = data length
		unpadded := NewAnsiX923UnPadding(data)
		assert.Equal(t, []byte{}, unpadded)
	})

	t.Run("AnsiX923 unpadding with empty data", func(t *testing.T) {
		var data []byte
		unpadded := NewAnsiX923UnPadding(data)
		assert.Nil(t, unpadded)
	})
}

func TestISO97971Padding(t *testing.T) {
	t.Run("ISO97971 padding with 1 byte needed", func(t *testing.T) {
		data := []byte("Hello")
		blockSize := 8
		expected := []byte("Hello\x80\x00\x00")
		padded := NewISO97971Padding(data, blockSize)
		assert.Equal(t, expected, padded)
	})

	t.Run("ISO97971 padding with 3 bytes needed", func(t *testing.T) {
		data := []byte("Hello")
		blockSize := 8
		expected := []byte("Hello\x80\x00\x00")
		padded := NewISO97971Padding(data, blockSize)
		assert.Equal(t, expected, padded)
	})

	t.Run("ISO97971 padding with exact block size", func(t *testing.T) {
		data := []byte("12345678") // 8 bytes
		blockSize := 8
		expected := []byte("12345678\x80\x00\x00\x00\x00\x00\x00\x00")
		padded := NewISO97971Padding(data, blockSize)
		assert.Equal(t, expected, padded)
	})

	t.Run("ISO97971 padding with exact block size 16", func(t *testing.T) {
		data := []byte("1234567890123456") // 16 bytes, exact multiple of 8
		blockSize := 8
		expected := []byte("1234567890123456\x80\x00\x00\x00\x00\x00\x00\x00")
		padded := NewISO97971Padding(data, blockSize)
		assert.Equal(t, expected, padded)
	})

	t.Run("ISO97971 padding with multiple blocks", func(t *testing.T) {
		data := []byte("Hello World")
		blockSize := 4
		expected := []byte("Hello World\x80")
		padded := NewISO97971Padding(data, blockSize)
		assert.Equal(t, expected, padded)
	})

	t.Run("ISO97971 padding with empty data", func(t *testing.T) {
		var data []byte
		blockSize := 8
		expected := []byte{0x80, 0, 0, 0, 0, 0, 0, 0}
		padded := NewISO97971Padding(data, blockSize)
		assert.Equal(t, expected, padded)
	})

	t.Run("ISO97971 unpadding with 1 byte padding", func(t *testing.T) {
		data := []byte("Hello\x80")
		expected := []byte("Hello")
		unpadded := NewISO97971UnPadding(data)
		assert.Equal(t, expected, unpadded)
	})

	t.Run("ISO97971 unpadding with 3 bytes padding", func(t *testing.T) {
		data := []byte("Hello\x80\x00\x00")
		expected := []byte("Hello")
		unpadded := NewISO97971UnPadding(data)
		assert.Equal(t, expected, unpadded)
	})

	t.Run("ISO97971 unpadding with full block padding", func(t *testing.T) {
		data := []byte{0x80, 0, 0, 0, 0, 0, 0, 0}
		unpadded := NewISO97971UnPadding(data)
		assert.Equal(t, []byte{}, unpadded)
	})

	t.Run("ISO97971 unpadding with no 0x80 byte", func(t *testing.T) {
		data := []byte("Hello\x00\x00\x00")
		unpadded := NewISO97971UnPadding(data)
		assert.Equal(t, data, unpadded) // Should return original data
	})

	t.Run("ISO97971 unpadding with non-zero bytes after 0x80", func(t *testing.T) {
		data := []byte("Hello\x80\x01\x00") // Non-zero byte after 0x80
		unpadded := NewISO97971UnPadding(data)
		assert.Equal(t, data, unpadded) // Should return original data
	})

	t.Run("ISO97971 unpadding with multiple 0x80 bytes", func(t *testing.T) {
		data := []byte("Hello\x80\x00\x80\x00") // Multiple 0x80 bytes, should find last one
		expected := []byte("Hello\x80\x00")
		unpadded := NewISO97971UnPadding(data)
		assert.Equal(t, expected, unpadded)
	})

	t.Run("ISO97971 unpadding with 0x80 at beginning", func(t *testing.T) {
		data := []byte("\x80\x00\x00\x00")
		unpadded := NewISO97971UnPadding(data)
		assert.Equal(t, []byte{}, unpadded)
	})

	t.Run("ISO97971 unpadding with empty data", func(t *testing.T) {
		var data []byte
		unpadded := NewISO97971UnPadding(data)
		assert.Nil(t, unpadded)
	})
}

func TestISO10126Padding(t *testing.T) {
	t.Run("ISO10126 padding with 1 byte needed", func(t *testing.T) {
		data := []byte("Hello")
		blockSize := 8
		padded := NewISO10126Padding(data, blockSize)
		assert.Equal(t, 8, len(padded))
		assert.Equal(t, data, padded[:5])
		assert.Equal(t, byte(3), padded[7]) // Last byte should be padding length
	})

	t.Run("ISO10126 padding with 3 bytes needed", func(t *testing.T) {
		data := []byte("Hello")
		blockSize := 8
		padded := NewISO10126Padding(data, blockSize)
		assert.Equal(t, 8, len(padded))
		assert.Equal(t, data, padded[:5])
		assert.Equal(t, byte(3), padded[7]) // Last byte should be padding length
	})

	t.Run("ISO10126 padding with exact block size", func(t *testing.T) {
		data := []byte("12345678") // 8 bytes
		blockSize := 8
		padded := NewISO10126Padding(data, blockSize)
		assert.Equal(t, 16, len(padded)) // Adds full block
		assert.Equal(t, data, padded[:8])
		assert.Equal(t, byte(8), padded[15]) // Last byte should be padding length
	})

	t.Run("ISO10126 padding with exact block size 16", func(t *testing.T) {
		data := []byte("1234567890123456") // 16 bytes, exact multiple of 8
		blockSize := 8
		padded := NewISO10126Padding(data, blockSize)
		assert.Equal(t, 24, len(padded)) // Adds full block
		assert.Equal(t, data, padded[:16])
		assert.Equal(t, byte(8), padded[23]) // Last byte should be padding length
	})

	t.Run("ISO10126 padding with multiple blocks", func(t *testing.T) {
		data := []byte("Hello World")
		blockSize := 4
		padded := NewISO10126Padding(data, blockSize)
		assert.Equal(t, 12, len(padded)) // Adds 1 byte padding
		assert.Equal(t, data, padded[:11])
		assert.Equal(t, byte(1), padded[11]) // Last byte should be padding length
	})

	t.Run("ISO10126 padding with empty data", func(t *testing.T) {
		var data []byte
		blockSize := 8
		padded := NewISO10126Padding(data, blockSize)
		assert.Equal(t, 8, len(padded))
		assert.Equal(t, byte(8), padded[7]) // Last byte should be padding length
	})

	t.Run("ISO10126 padding with single byte padding", func(t *testing.T) {
		data := []byte("1234567")
		blockSize := 8
		padded := NewISO10126Padding(data, blockSize)
		assert.Equal(t, 8, len(padded))
		assert.Equal(t, data, padded[:7])
		assert.Equal(t, byte(1), padded[7]) // Last byte should be padding length
	})

	t.Run("ISO10126 unpadding with 1 byte padding", func(t *testing.T) {
		// Create test data with random padding bytes (except last byte)
		data := make([]byte, 8)
		copy(data, "1234567")
		data[7] = 1 // Last byte is padding length
		expected := []byte("1234567")
		unpadded := NewISO10126UnPadding(data)
		assert.Equal(t, expected, unpadded)
	})

	t.Run("ISO10126 unpadding with 3 bytes padding", func(t *testing.T) {
		// Create test data with random padding bytes (except last byte)
		data := make([]byte, 8)
		copy(data, "12345")
		data[7] = 3 // Last byte is padding length
		expected := []byte("12345")
		unpadded := NewISO10126UnPadding(data)
		assert.Equal(t, expected, unpadded)
	})

	t.Run("ISO10126 unpadding with full block padding", func(t *testing.T) {
		data := []byte{0, 0, 0, 0, 0, 0, 0, 8}
		unpadded := NewISO10126UnPadding(data)
		assert.Equal(t, []byte{}, unpadded)
	})

	t.Run("ISO10126 unpadding with invalid padding size", func(t *testing.T) {
		data := []byte{0, 0, 0, 0, 0, 0, 0, 9} // padding size > data length
		unpadded := NewISO10126UnPadding(data)
		assert.Equal(t, data, unpadded) // Should return original data
	})

	t.Run("ISO10126 unpadding with zero padding size", func(t *testing.T) {
		data := []byte{0, 0, 0, 0, 0, 0, 0, 0} // padding size = 0
		unpadded := NewISO10126UnPadding(data)
		assert.Equal(t, data, unpadded) // Should return original data
	})

	t.Run("ISO10126 unpadding with padding size equal to data length", func(t *testing.T) {
		data := []byte{0, 0, 0, 0, 0, 0, 0, 8} // padding size = data length
		unpadded := NewISO10126UnPadding(data)
		assert.Equal(t, []byte{}, unpadded)
	})

	t.Run("ISO10126 unpadding with empty data", func(t *testing.T) {
		var data []byte
		unpadded := NewISO10126UnPadding(data)
		assert.Nil(t, unpadded)
	})
}

func TestISO78164Padding(t *testing.T) {
	t.Run("ISO78164 padding with 1 byte needed", func(t *testing.T) {
		data := []byte("1234567") // 7 bytes
		blockSize := 8
		expected := []byte("1234567\x80")
		padded := NewISO78164Padding(data, blockSize)
		assert.Equal(t, expected, padded)
	})

	t.Run("ISO78164 padding with 3 bytes needed", func(t *testing.T) {
		data := []byte("12345") // 5 bytes
		blockSize := 8
		expected := []byte("12345\x80\x00\x00")
		padded := NewISO78164Padding(data, blockSize)
		assert.Equal(t, expected, padded)
	})

	t.Run("ISO78164 padding with exact block size", func(t *testing.T) {
		data := []byte("12345678") // 8 bytes
		blockSize := 8
		expected := []byte("12345678\x80\x00\x00\x00\x00\x00\x00\x00")
		padded := NewISO78164Padding(data, blockSize)
		assert.Equal(t, expected, padded)
	})

	t.Run("ISO78164 padding with empty data", func(t *testing.T) {
		var data []byte
		blockSize := 8
		expected := []byte{0x80, 0, 0, 0, 0, 0, 0, 0}
		padded := NewISO78164Padding(data, blockSize)
		assert.Equal(t, expected, padded)
	})

	t.Run("ISO78164 unpadding with 1 byte padding", func(t *testing.T) {
		data := []byte("1234567\x80")
		expected := []byte("1234567")
		unpadded := NewISO78164UnPadding(data)
		assert.Equal(t, expected, unpadded)
	})

	t.Run("ISO78164 unpadding with 3 bytes padding", func(t *testing.T) {
		data := []byte("12345\x80\x00\x00")
		expected := []byte("12345")
		unpadded := NewISO78164UnPadding(data)
		assert.Equal(t, expected, unpadded)
	})

	t.Run("ISO78164 unpadding with full block padding", func(t *testing.T) {
		data := []byte{0x80, 0, 0, 0, 0, 0, 0, 0}
		unpadded := NewISO78164UnPadding(data)
		assert.Equal(t, []byte{}, unpadded)
	})
}

func TestBitPadding(t *testing.T) {
	t.Run("Bit padding with 1 byte needed", func(t *testing.T) {
		data := []byte("1234567") // 7 bytes
		blockSize := 8
		padded := NewBitPadding(data, blockSize)
		assert.Equal(t, blockSize, len(padded))
		assert.Equal(t, data, padded[:len(data)])
		assert.Equal(t, byte(0x80), padded[len(data)]) // First padding byte should be 0x80
	})

	t.Run("Bit padding with 3 bytes needed", func(t *testing.T) {
		data := []byte("12345") // 5 bytes
		blockSize := 8
		padded := NewBitPadding(data, blockSize)
		assert.Equal(t, blockSize, len(padded))
		assert.Equal(t, data, padded[:len(data)])
		assert.Equal(t, byte(0x80), padded[len(data)]) // First padding byte should be 0x80
	})

	t.Run("Bit padding with exact block size", func(t *testing.T) {
		data := []byte("12345678") // 8 bytes
		blockSize := 8
		padded := NewBitPadding(data, blockSize)
		assert.Equal(t, blockSize*2, len(padded)) // Adds full block
		assert.Equal(t, data, padded[:len(data)])
		assert.Equal(t, byte(0x80), padded[len(data)]) // First padding byte should be 0x80
	})

	t.Run("Bit padding with exact block size 16", func(t *testing.T) {
		data := []byte("1234567890123456") // 16 bytes, exact multiple of 8
		blockSize := 8
		padded := NewBitPadding(data, blockSize)
		assert.Equal(t, blockSize*3, len(padded)) // Adds full block
		assert.Equal(t, data, padded[:len(data)])
		assert.Equal(t, byte(0x80), padded[len(data)]) // First padding byte should be 0x80
	})

	t.Run("Bit padding with multiple blocks", func(t *testing.T) {
		data := []byte("1234567890123456") // 16 bytes (2 blocks)
		blockSize := 8
		padded := NewBitPadding(data, blockSize)
		assert.Equal(t, blockSize*3, len(padded)) // Adds full block
		assert.Equal(t, data, padded[:len(data)])
		assert.Equal(t, byte(0x80), padded[len(data)]) // First padding byte should be 0x80
	})

	t.Run("Bit padding with empty data", func(t *testing.T) {
		var data []byte
		blockSize := 8
		padded := NewBitPadding(data, blockSize)
		assert.Equal(t, blockSize, len(padded))
		assert.Equal(t, byte(0x80), padded[0]) // First padding byte should be 0x80
	})

	t.Run("Bit unpadding with 1 byte padding", func(t *testing.T) {
		data := []byte("1234567\x80")
		expected := []byte("1234567")
		unpadded := NewBitUnPadding(data)
		assert.Equal(t, expected, unpadded)
	})

	t.Run("Bit unpadding with 3 bytes padding", func(t *testing.T) {
		data := []byte("12345\x80\x00\x00")
		expected := []byte("12345")
		unpadded := NewBitUnPadding(data)
		assert.Equal(t, expected, unpadded)
	})

	t.Run("Bit unpadding with full block padding", func(t *testing.T) {
		data := []byte{0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
		unpadded := NewBitUnPadding(data)
		assert.Equal(t, []byte{}, unpadded)
	})
}

func TestPaddingModes(t *testing.T) {
	t.Run("No padding mode", func(t *testing.T) {
		assert.Equal(t, PaddingMode("No"), No)
	})

	t.Run("Zero padding mode", func(t *testing.T) {
		assert.Equal(t, PaddingMode("Zero"), Zero)
	})

	t.Run("PKCS5 padding mode", func(t *testing.T) {
		assert.Equal(t, PaddingMode("PKCS5"), PKCS5)
	})

	t.Run("PKCS7 padding mode", func(t *testing.T) {
		assert.Equal(t, PaddingMode("PKCS7"), PKCS7)
	})

	t.Run("AnsiX923 padding mode", func(t *testing.T) {
		assert.Equal(t, PaddingMode("AnsiX.923"), AnsiX923)
	})

	t.Run("ISO97971 padding mode", func(t *testing.T) {
		assert.Equal(t, PaddingMode("ISO9797-1"), ISO97971)
	})

	t.Run("ISO10126 padding mode", func(t *testing.T) {
		assert.Equal(t, PaddingMode("ISO10126"), ISO10126)
	})

	t.Run("ISO78164 padding mode", func(t *testing.T) {
		assert.Equal(t, PaddingMode("ISO7816-4"), ISO78164)
	})

	t.Run("Bit padding mode", func(t *testing.T) {
		assert.Equal(t, PaddingMode("Bit"), Bit)
	})
}
