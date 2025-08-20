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

// NewNoPadding applies no padding to the source data.
// This function simply returns the original data without modification.
//
// Note: Data must already be a multiple of the block size for this to work correctly.
func NewNoPadding(src []byte) []byte {
	return src
}

// NewNoUnPadding removes no padding from the source data.
// This function simply returns the original data without modification.
func NewNoUnPadding(src []byte) []byte {
	return src
}

// NewZeroPadding applies zero padding to the source data.
// Zero padding adds padding bytes (filled with zeros) to reach the block size.
// If the data length is already a multiple of block size, no padding is added.
// For empty data, no padding is added.
func NewZeroPadding(src []byte, blockSize int) []byte {
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

// NewZeroUnPadding removes zero padding from the source data.
// This function removes trailing zero bytes from the data.
func NewZeroUnPadding(src []byte) []byte {
	if len(src) == 0 {
		return nil
	}

	lastNonZero := len(src) - 1
	for lastNonZero >= 0 && src[lastNonZero] == 0 {
		lastNonZero--
	}

	return src[:lastNonZero+1]
}

// NewPKCS7Padding applies PKCS7 padding to the source data.
// PKCS7 padding adds N bytes, each with value N, where N is the number of padding bytes needed.
// This is the most commonly used padding scheme in modern cryptography.
func NewPKCS7Padding(src []byte, blockSize int) []byte {
	paddingSize := blockSize - len(src)%blockSize
	paddingBytes := bytes.Repeat([]byte{byte(paddingSize)}, paddingSize)
	return append(src, paddingBytes...)
}

// NewPKCS7UnPadding removes PKCS7 padding from the source data.
// This function reads the last byte to determine the padding size and removes that many bytes.
func NewPKCS7UnPadding(src []byte) []byte {
	if len(src) == 0 {
		return nil
	}

	paddingSize := int(src[len(src)-1])
	if paddingSize > len(src) || paddingSize == 0 {
		return src // Invalid padding, return original data
	}

	return src[:len(src)-paddingSize]
}

// NewPKCS5Padding applies PKCS5 padding to the source data.
// PKCS5 padding is identical to PKCS7 padding but is limited to 8-byte blocks.
// This function calls PKCS7 padding with a fixed block size of 8.
func NewPKCS5Padding(src []byte) []byte {
	return NewPKCS7Padding(src, 8)
}

// NewPKCS5UnPadding removes PKCS5 padding from the source data.
// This function calls PKCS7 unpadding since PKCS5 and PKCS7 are identical.
func NewPKCS5UnPadding(src []byte) []byte {
	return NewPKCS7UnPadding(src)
}

// NewAnsiX923Padding applies ANSI X.923 padding to the source data.
// ANSI X.923 padding fills with zeros and adds the padding length as the last byte.
// If the data length is already a multiple of block size, a full block of padding is added.
func NewAnsiX923Padding(src []byte, blockSize int) []byte {
	paddingSize := blockSize - len(src)%blockSize

	paddingBytes := make([]byte, paddingSize)
	paddingBytes[paddingSize-1] = byte(paddingSize)
	return append(src, paddingBytes...)
}

// NewAnsiX923UnPadding removes ANSI X.923 padding from the source data.
// This function validates that all padding bytes except the last are zero.
func NewAnsiX923UnPadding(src []byte) []byte {
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

// NewISO97971Padding applies ISO/IEC 9797-1 padding method 1 to the source data.
// ISO9797-1 method 1 adds a 0x80 byte followed by zero bytes to reach the block size.
// If the data length is already a multiple of block size, a full block of padding is added.
func NewISO97971Padding(src []byte, blockSize int) []byte {
	paddingSize := blockSize - len(src)%blockSize

	paddingBytes := make([]byte, paddingSize)
	paddingBytes[0] = 0x80

	return append(src, paddingBytes...)
}

// NewISO97971UnPadding removes ISO/IEC 9797-1 padding method 1 from the source data.
// This function finds the last 0x80 byte and validates that all bytes after it are zero.
func NewISO97971UnPadding(src []byte) []byte {
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

// NewISO10126Padding applies ISO/IEC 10126 padding to the source data.
// ISO10126 padding fills with random bytes and adds the padding length as the last byte.
// This padding scheme provides better security by using random padding bytes.
func NewISO10126Padding(src []byte, blockSize int) []byte {
	paddingSize := blockSize - len(src)%blockSize

	paddingBytes := make([]byte, paddingSize)
	if paddingSize > 1 {
		rand.Read(paddingBytes[:paddingSize-1])
	}
	paddingBytes[paddingSize-1] = byte(paddingSize)

	return append(src, paddingBytes...)
}

// NewISO10126UnPadding removes ISO/IEC 10126 padding from the source data.
// This function reads the last byte to determine the padding size and removes that many bytes.
//
// Note: The random padding bytes are not validated, only the length is used.
func NewISO10126UnPadding(src []byte) []byte {
	if len(src) == 0 {
		return nil
	}
	paddingSize := int(src[len(src)-1])
	if paddingSize > len(src) || paddingSize == 0 {
		return src
	}

	return src[:len(src)-paddingSize]
}

// NewISO78164Padding applies ISO/IEC 7816-4 padding to the source data.
// ISO7816-4 padding is identical to ISO9797-1 method 1 padding.
// This function calls ISO9797-1 padding implementation.
func NewISO78164Padding(src []byte, blockSize int) []byte {
	return NewISO97971Padding(src, blockSize)
}

// NewISO78164UnPadding removes ISO/IEC 7816-4 padding from the source data.
// This function calls ISO9797-1 unpadding since they are identical.
func NewISO78164UnPadding(src []byte) []byte {
	return NewISO97971UnPadding(src)
}

// NewBitPadding applies bit padding to the source data.
// Bit padding adds a 0x80 byte followed by zero bytes to reach the block size.
// This is similar to ISO9797-1 method 1 but with a different name.
func NewBitPadding(src []byte, blockSize int) []byte {
	paddingSize := blockSize - len(src)%blockSize

	paddingBytes := make([]byte, paddingSize)
	paddingBytes[0] = 0x80

	return append(src, paddingBytes...)
}

// NewBitUnPadding removes bit padding from the source data.
// This function calls ISO9797-1 unpadding since they are identical.
func NewBitUnPadding(src []byte) []byte {
	return NewISO97971UnPadding(src)
}

// padding is an internal function that applies the specified padding mode to source data.
// This function serves as a dispatcher to the appropriate padding implementation.
func padding(src []byte, padding PaddingMode, blockSize int) []byte {
	switch padding {
	case No:
		return NewNoPadding(src)
	case Zero:
		return NewZeroPadding(src, blockSize)
	case PKCS5:
		return NewPKCS5Padding(src)
	case PKCS7:
		return NewPKCS7Padding(src, blockSize)
	case AnsiX923:
		return NewAnsiX923Padding(src, blockSize)
	case ISO97971:
		return NewISO97971Padding(src, blockSize)
	case ISO10126:
		return NewISO10126Padding(src, blockSize)
	case ISO78164:
		return NewISO78164Padding(src, blockSize)
	case Bit:
		return NewBitPadding(src, blockSize)
	default:
		return NewNoPadding(src)
	}
}

// unpadding is an internal function that removes the specified padding mode from data.
// This function serves as a dispatcher to the appropriate unpadding implementation.
func unpadding(dst []byte, padding PaddingMode) []byte {
	switch padding {
	case No:
		return NewNoUnPadding(dst)
	case Zero:
		return NewZeroUnPadding(dst)
	case PKCS5:
		return NewPKCS5UnPadding(dst)
	case PKCS7:
		return NewPKCS7UnPadding(dst)
	case AnsiX923:
		return NewAnsiX923UnPadding(dst)
	case ISO97971:
		return NewISO97971UnPadding(dst)
	case ISO10126:
		return NewISO10126UnPadding(dst)
	case ISO78164:
		return NewISO78164UnPadding(dst)
	case Bit:
		return NewBitUnPadding(dst)
	default:
		return NewNoUnPadding(dst)
	}
}
