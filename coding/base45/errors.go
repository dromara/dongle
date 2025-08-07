package base45

import "fmt"

// InvalidLengthError represents an error when the base45 input length is invalid.
// Base45 requires input length to be congruent to 0 or 2 modulo 3.
// This error occurs when the input length does not meet this requirement.
type InvalidLengthError struct {
	Length int // The invalid input length
	Mod    int // The actual modulo value that caused the error
}

// Error returns a formatted error message describing the invalid input length.
// The message includes the actual length and modulo value for debugging.
func (e InvalidLengthError) Error() string {
	return fmt.Sprintf("coding/base45: invalid length n=%d. It should be n mod 3 = [0, 2] NOT n mod 3 = %d", e.Length, e.Mod)
}

// InvalidCharacterError represents an error when an invalid character is found
// in base45 input. This error occurs when a character is not part of the
// base45 alphabet or is outside the valid range.
type InvalidCharacterError struct {
	Char     rune // The invalid character that was found
	Position int  // The position of the invalid character in the input
}

// Error returns a formatted error message describing the invalid character.
// The message includes the character and its position for debugging.
func (e InvalidCharacterError) Error() string {
	return fmt.Sprintf("coding/base45: invalid character %s at position: %d", string(e.Char), e.Position)
}

// CorruptInputError represents an error when corrupted or invalid base45 data
// is detected during decoding. This error occurs when the decoded value
// exceeds the expected range or when the input data is malformed.
type CorruptInputError int64

// Error returns a formatted error message describing the corrupted input.
// The message includes the position where corruption was detected.
func (e CorruptInputError) Error() string {
	return fmt.Sprintf("coding/base45: illegal data at input byte %d", int64(e))
}
