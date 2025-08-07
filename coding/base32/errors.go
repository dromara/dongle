package base32

import "fmt"

// AlphabetSizeError represents an error when the base32 alphabet is invalid.
// Base32 requires an alphabet of exactly 32 characters for proper encoding
// and decoding operations. This error occurs when the alphabet length
// does not meet this requirement.
type AlphabetSizeError int

// Error returns a formatted error message describing the invalid alphabet length.
// The message includes the actual length and the required length for debugging.
func (e AlphabetSizeError) Error() string {
	return fmt.Sprintf("coding/base32: invalid alphabet, the alphabet length must be 32, got %d", int(e))
}

// CorruptInputError represents an error when corrupted or invalid base32 data
// is detected during decoding. This error occurs when an invalid character
// is found in the input or when the input data is malformed.
type CorruptInputError int64

// Error returns a formatted error message describing the corrupted input.
// The message includes the position where corruption was detected.
func (e CorruptInputError) Error() string {
	return fmt.Sprintf("coding/base32: illegal data at input byte %d", int64(e))
}
