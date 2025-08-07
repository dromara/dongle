package rc4

import (
	"fmt"
)

// KeySizeError represents an error when the RC4 key size is invalid.
// RC4 keys must be between 1 and 256 bytes long.
// This error occurs when the provided key does not meet these size requirements.
type KeySizeError int

// Error returns a formatted error message describing the invalid key size.
// The message includes the actual key size and the required size range for debugging.
func (k KeySizeError) Error() string {
	return fmt.Sprintf("crypto/rc4: invalid key size %d, must be between 1 and 256 bytes", k)
}

// WriteError represents an error when writing encrypted data fails.
// This error occurs when writing encrypted data to the underlying writer fails.
// The error includes the underlying error for detailed debugging.
type WriteError struct {
	Err error // The underlying error that caused the failure
}

// Error returns a formatted error message describing the write failure.
// The message includes the underlying error for debugging.
func (e WriteError) Error() string {
	return fmt.Sprintf("crypto/rc4: failed to write encrypted data: %v", e.Err)
}

// ReadError represents an error when reading encrypted data fails.
// This error occurs when reading encrypted data from the underlying reader fails.
// The error includes the underlying error for detailed debugging.
type ReadError struct {
	Err error // The underlying error that caused the failure
}

// Error returns a formatted error message describing the read failure.
// The message includes the underlying error for debugging.
func (e ReadError) Error() string {
	return fmt.Sprintf("crypto/rc4: failed to read encrypted data: %v", e.Err)
}
