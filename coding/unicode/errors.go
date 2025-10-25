package unicode

import "fmt"

// DecodeFailedError represents an error when unicode decoding fails.
// This error occurs when invalid unicode escape sequences are encountered
// during decoding operations.
type DecodeFailedError struct {
	Input string // The invalid input that caused the error
}

// Error returns a formatted error message describing the decode failure.
func (e DecodeFailedError) Error() string {
	return fmt.Sprintf("coding/unicode: failed to decode data: %s", e.Input)
}

// InvalidUnicodeError represents an error when invalid unicode data is encountered.
// This error occurs when malformed unicode escape sequences are found.
type InvalidUnicodeError struct {
	Char string // The invalid unicode character that was found
}

// Error returns a formatted error message describing the invalid unicode.
func (e InvalidUnicodeError) Error() string {
	return fmt.Sprintf("coding/unicode: invalid unicode character: %s", e.Char)
}

// EncodeFailedError represents an error when unicode encoding fails.
// This error is rarely used since strconv.QuoteToASCII rarely fails.
type EncodeFailedError struct {
	Input string // The input that failed to encode
}

// Error returns a formatted error message describing the encode failure.
func (e EncodeFailedError) Error() string {
	return fmt.Sprintf("coding/unicode: failed to encode data: %s", e.Input)
}
