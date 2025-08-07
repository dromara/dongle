package base85

import "fmt"

// CorruptInputError represents an error when corrupted or invalid base85 data
// is detected during decoding. This error occurs when an invalid character
// is found in the input or when the input data is malformed.
type CorruptInputError int64

// Error returns a formatted error message describing the corrupted input.
// The message includes the position where corruption was detected.
func (e CorruptInputError) Error() string {
	return fmt.Sprintf("coding/base85: illegal data at input byte %d", int64(e))
}
