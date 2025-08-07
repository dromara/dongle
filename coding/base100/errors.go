package base100

import "fmt"

// InvalidLengthError represents an error when the base100 input length is invalid.
// Base100 encoding requires each input byte to be represented by exactly 4 bytes,
// so the input length must be divisible by 4 for proper decoding.
type InvalidLengthError int

// Error returns a formatted error message describing the invalid length.
// The message includes the actual length and the requirement for debugging.
func (e InvalidLengthError) Error() string {
	return fmt.Sprintf("coding/base100: invalid length, data length must be divisible by 4, got %d", int(e))
}

// CorruptInputError represents an error when corrupted or invalid base100 data
// is detected during decoding. This error occurs when an invalid character
// is found in the input or when the input data is malformed.
type CorruptInputError int64

// Error returns a formatted error message describing the corrupted input.
// The message includes the position where corruption was detected.
func (e CorruptInputError) Error() string {
	return fmt.Sprintf("coding/base100: illegal data at input byte %d", int64(e))
}
