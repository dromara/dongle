package cipher

import (
	"bytes"
	"crypto/rand"
)

// PaddingMode defines a PaddingMode type.
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
	TBC      PaddingMode = "TBC"       // TBC padding - 0x00 if last byte MSB=1, else 0xFF
)

// NewNoPadding adds no padding to the source data.
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

// NewZeroPadding adds zero padding to the source data.
// Zero padding adds padding bytes (filled with zeros) to reach the block size.
// If the data length is already a multiple of block size and not empty, no padding is added.
// Empty data always gets padded to a full block.
func NewZeroPadding(src []byte, blockSize int) []byte {
	paddingSize := blockSize - len(src)%blockSize
	if paddingSize == blockSize && len(src) > 0 {
		// Data length is exactly a multiple of block size and not empty, no padding needed
		return src
	}
	return append(src, make([]byte, paddingSize)...)
}

// NewZeroUnPadding removes zero padding from the source data.
// This function removes trailing zero bytes from the data.
func NewZeroUnPadding(src []byte) []byte {
	lastNonZero := len(src) - 1
	for lastNonZero >= 0 && src[lastNonZero] == 0 {
		lastNonZero--
	}
	return src[:lastNonZero+1]
}

// NewPKCS7Padding adds PKCS7 padding to the source data.
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
	paddingSize := int(src[len(src)-1])
	if paddingSize > len(src) || paddingSize == 0 {
		return src // Invalid padding, return original data
	}
	return src[:len(src)-paddingSize]
}

// NewPKCS5Padding adds PKCS5 padding to the source data.
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

// NewAnsiX923Padding adds ANSI X.923 padding to the source data.
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
	paddingSize := int(src[len(src)-1])
	if paddingSize > len(src) || paddingSize == 0 {
		return src
	}
	for i := len(src) - paddingSize; i < len(src)-1; i++ {
		if src[i] != 0 {
			return src
		}
	}
	return src[:len(src)-paddingSize]
}

// NewISO97971Padding adds ISO/IEC 9797-1 padding method 1 to the source data.
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

// NewISO10126Padding adds ISO/IEC 10126 padding to the source data.
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
	paddingSize := int(src[len(src)-1])
	if paddingSize > len(src) || paddingSize == 0 {
		return src
	}
	return src[:len(src)-paddingSize]
}

// NewISO78164Padding adds ISO/IEC 7816-4 padding to the source data.
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

// NewBitPadding adds bit padding to the source data.
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

// NewTBCPadding adds TBC (Trailing Bit Complement) padding to the source data.
// TBC padding fills the padding bytes with 0x00 if the most significant bit
// (MSB) of the last data byte is 0; otherwise it fills with 0xFF.
// If the data length is already a multiple of block size, a full block
// of padding is added following the same rule.
func NewTBCPadding(src []byte, blockSize int) []byte {
	paddingSize := blockSize - len(src)%blockSize
	// Determine pad byte based on MSB of last data byte. For empty data,
	// default to 0x00 as if last data byte MSB were 0.
	paddingBytes := byte(0x00)
	if len(src) > 0 && src[len(src)-1]&0x80 != 0 {
		paddingBytes = 0xFF
	}
	repeatBytes := bytes.Repeat([]byte{paddingBytes}, paddingSize)
	return append(src, repeatBytes...)
}

// NewTBCUnPadding removes TBC padding from the source data by stripping all
// trailing bytes equal to the last byte value. This mirrors the ambiguity of
// zero padding removal and does not perform strict validation.
func NewTBCUnPadding(src []byte) []byte {
	if len(src) == 0 {
		return src
	}
	paddingBytes := src[len(src)-1]
	i := len(src) - 1
	for i >= 0 && src[i] == paddingBytes {
		i--
	}
	return src[:i+1]
}
