package morse

import "fmt"

// InvalidInputError represents an error when the morse input is invalid.
// This error occurs when the input contains spaces or other invalid characters.
type InvalidInputError struct {
}

// Error returns a formatted error message describing the invalid input.
func (e InvalidInputError) Error() string {
	return fmt.Sprintf("coding/morse: input cannot contain spaces")
}

// InvalidCharacterError represents an error when an invalid morse character is found
// during decoding. This error occurs when a morse code sequence is not recognized.
type InvalidCharacterError struct {
	Char string // The invalid morse character that was found
}

// Error returns a formatted error message describing the invalid character.
func (e InvalidCharacterError) Error() string {
	return fmt.Sprintf("coding/morse: unknown character %s", e.Char)
}
