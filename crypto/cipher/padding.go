package cipher

import (
	"bytes"
	"crypto/rand"
)

// PaddingMode represents the different padding schemes available for block ciphers
type PaddingMode string

// Supported padding modes for block cipher operations
const (
	No       PaddingMode = "No"        // No padding - data must be exact block size
	Zero     PaddingMode = "Zero"      // Zero padding - fills with zeros, always adds padding
	PKCS5    PaddingMode = "PKCS5"     // PKCS5 padding - RFC 2898, 8-byte blocks only
	PKCS7    PaddingMode = "PKCS7"     // PKCS7 padding - RFC 5652, variable block size
	AnsiX923 PaddingMode = "AnsiX.923" // ANSI X.923 padding - zeros + length byte
	ISO97971 PaddingMode = "ISO9797-1" // ISO/IEC 9797-1 padding method 1
	ISO10126 PaddingMode = "ISO10126"  // ISO/IEC 10126 padding - random + length byte
	ISO78164 PaddingMode = "ISO7816-4" // ISO/IEC 7816-4 padding - same as ISO9797-1
	Bit      PaddingMode = "Bit"       // Bit padding - 0x80 + zeros
)

// newNoPadding applies no padding to the source data.
// This function simply returns the original data without modification.
//
// Note: Data must already be a multiple of the block size for this to work correctly.
func newNoPadding(src []byte) []byte {
	return src
}

// newNoUnPadding removes no padding from the source data.
// This function simply returns the original data without modification.
func newNoUnPadding(src []byte) []byte {
	return src
}

// newZeroPadding applies zero padding to the source data.
// Zero padding adds padding bytes (filled with zeros) to reach the block size.
// If the data length is already a multiple of block size, no padding is added.
// For empty data, no padding is added.
func newZeroPadding(src []byte, blockSize int) []byte {
	if len(src) == 0 {
		return src
	}

	paddingSize := blockSize - len(src)%blockSize
	if paddingSize == blockSize {
		// Data length is exactly a multiple of block size, no padding needed
		return src
	}

	return append(src, make([]byte, paddingSize)...)
}

// newZeroUnPadding removes zero padding from the source data.
// This function removes trailing zero bytes from the data.
func newZeroUnPadding(src []byte) []byte {
	if len(src) == 0 {
		return nil
	}

	lastNonZero := len(src) - 1
	for lastNonZero >= 0 && src[lastNonZero] == 0 {
		lastNonZero--
	}

	return src[:lastNonZero+1]
}

// newPKCS7Padding applies PKCS7 padding to the source data.
// PKCS7 padding adds N bytes, each with value N, where N is the number of padding bytes needed.
// This is the most commonly used padding scheme in modern cryptography.
func newPKCS7Padding(src []byte, blockSize int) []byte {
	paddingSize := blockSize - len(src)%blockSize
	paddingBytes := bytes.Repeat([]byte{byte(paddingSize)}, paddingSize)
	return append(src, paddingBytes...)
}

// newPKCS7UnPadding removes PKCS7 padding from the source data.
// This function reads the last byte to determine the padding size and removes that many bytes.
func newPKCS7UnPadding(src []byte) []byte {
	if len(src) == 0 {
		return nil
	}

	paddingSize := int(src[len(src)-1])
	if paddingSize > len(src) || paddingSize == 0 {
		return src // Invalid padding, return original data
	}

	return src[:len(src)-paddingSize]
}

// newPKCS5Padding applies PKCS5 padding to the source data.
// PKCS5 padding is identical to PKCS7 padding but is limited to 8-byte blocks.
// This function calls PKCS7 padding with a fixed block size of 8.
func newPKCS5Padding(src []byte) []byte {
	return newPKCS7Padding(src, 8)
}

// newPKCS5UnPadding removes PKCS5 padding from the source data.
// This function calls PKCS7 unpadding since PKCS5 and PKCS7 are identical.
func newPKCS5UnPadding(src []byte) []byte {
	return newPKCS7UnPadding(src)
}

// newAnsiX923Padding applies ANSI X.923 padding to the source data.
// ANSI X.923 padding fills with zeros and adds the padding length as the last byte.
// If the data length is already a multiple of block size, a full block of padding is added.
func newAnsiX923Padding(src []byte, blockSize int) []byte {
	paddingSize := blockSize - len(src)%blockSize

	paddingBytes := make([]byte, paddingSize)
	paddingBytes[paddingSize-1] = byte(paddingSize)
	return append(src, paddingBytes...)
}

// newAnsiX923UnPadding removes ANSI X.923 padding from the source data.
// This function validates that all padding bytes except the last are zero.
func newAnsiX923UnPadding(src []byte) []byte {
	if len(src) == 0 {
		return nil
	}
	paddingSize := int(src[len(src)-1])
	if paddingSize > len(src) || paddingSize == 0 {
		return src
	}

	// Verify all padding bytes except the last are zero
	for i := len(src) - paddingSize; i < len(src)-1; i++ {
		if src[i] != 0 {
			return src
		}
	}

	return src[:len(src)-paddingSize]
}

// newISO97971Padding applies ISO/IEC 9797-1 padding method 1 to the source data.
// ISO9797-1 method 1 adds a 0x80 byte followed by zero bytes to reach the block size.
// If the data length is already a multiple of block size, a full block of padding is added.
func newISO97971Padding(src []byte, blockSize int) []byte {
	paddingSize := blockSize - len(src)%blockSize

	paddingBytes := make([]byte, paddingSize)
	paddingBytes[0] = 0x80

	return append(src, paddingBytes...)
}

// newISO97971UnPadding removes ISO/IEC 9797-1 padding method 1 from the source data.
// This function finds the last 0x80 byte and validates that all bytes after it are zero.
func newISO97971UnPadding(src []byte) []byte {
	if len(src) == 0 {
		return nil
	}
	// Find the last 0x80 byte
	lastIndex := -1
	for i := len(src) - 1; i >= 0; i-- {
		if src[i] == 0x80 {
			lastIndex = i
			break
		}
	}

	if lastIndex == -1 {
		return src
	}

	// Verify all bytes after 0x80 are zero
	for i := lastIndex + 1; i < len(src); i++ {
		if src[i] != 0x00 {
			return src
		}
	}

	return src[:lastIndex]
}

// newISO10126Padding applies ISO/IEC 10126 padding to the source data.
// ISO10126 padding fills with random bytes and adds the padding length as the last byte.
// This padding scheme provides better security by using random padding bytes.
func newISO10126Padding(src []byte, blockSize int) []byte {
	paddingSize := blockSize - len(src)%blockSize

	paddingBytes := make([]byte, paddingSize)
	if paddingSize > 1 {
		rand.Read(paddingBytes[:paddingSize-1])
	}
	paddingBytes[paddingSize-1] = byte(paddingSize)

	return append(src, paddingBytes...)
}

// newISO10126UnPadding removes ISO/IEC 10126 padding from the source data.
// This function reads the last byte to determine the padding size and removes that many bytes.
//
// Note: The random padding bytes are not validated, only the length is used.
func newISO10126UnPadding(src []byte) []byte {
	if len(src) == 0 {
		return nil
	}
	paddingSize := int(src[len(src)-1])
	if paddingSize > len(src) || paddingSize == 0 {
		return src
	}

	return src[:len(src)-paddingSize]
}

// newISO78164Padding applies ISO/IEC 7816-4 padding to the source data.
// ISO7816-4 padding is identical to ISO9797-1 method 1 padding.
// This function calls ISO9797-1 padding implementation.
func newISO78164Padding(src []byte, blockSize int) []byte {
	return newISO97971Padding(src, blockSize)
}

// newISO78164UnPadding removes ISO/IEC 7816-4 padding from the source data.
// This function calls ISO9797-1 unpadding since they are identical.
func newISO78164UnPadding(src []byte) []byte {
	return newISO97971UnPadding(src)
}

// newBitPadding applies bit padding to the source data.
// Bit padding adds a 0x80 byte followed by zero bytes to reach the block size.
// This is similar to ISO9797-1 method 1 but with a different name.
func newBitPadding(src []byte, blockSize int) []byte {
	paddingSize := blockSize - len(src)%blockSize

	paddingBytes := make([]byte, paddingSize)
	paddingBytes[0] = 0x80

	return append(src, paddingBytes...)
}

// newBitUnPadding removes bit padding from the source data.
// This function calls ISO9797-1 unpadding since they are identical.
func newBitUnPadding(src []byte) []byte {
	return newISO97971UnPadding(src)
}
