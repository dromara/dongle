package salsa20

import (
	"fmt"
)

// KeySizeError represents an error when the Salsa20 key size is invalid.
// Salsa20 keys must be exactly 32 bytes (256 bits) long.
// This error occurs when the provided key does not meet this size requirement.
type KeySizeError int

// Error returns a formatted error message describing the invalid key size.
// The message includes the actual key size and the required size for debugging.
func (k KeySizeError) Error() string {
	return fmt.Sprintf("crypto/salsa20: invalid key size %d, must be exactly 32 bytes", k)
}

// NonceSizeError represents an error when the Salsa20 nonce size is invalid.
// Salsa20 nonces must be exactly 8 bytes (64 bits) long.
// This error occurs when the provided nonce does not meet this size requirement.
type NonceSizeError int

// Error returns a formatted error message describing the invalid nonce size.
// The message includes the actual nonce size and the required size for debugging.
func (n NonceSizeError) Error() string {
	return fmt.Sprintf("crypto/salsa20: invalid nonce size %d, must be exactly 8 bytes", n)
}

// EncryptError represents an error when Salsa20 encryption fails.
// This error occurs when the underlying Salsa20 encryption operation fails.
// The error includes the underlying error for detailed debugging.
type EncryptError struct {
	Err error // The underlying error that caused the failure
}

// Error returns a formatted error message describing the encryption failure.
// The message includes the underlying error for debugging.
func (e EncryptError) Error() string {
	return fmt.Sprintf("crypto/salsa20: failed to encrypt data: %v", e.Err)
}

// DecryptError represents an error when Salsa20 decryption fails.
// This error occurs when the underlying Salsa20 decryption operation fails.
// The error includes the underlying error for detailed debugging.
type DecryptError struct {
	Err error // The underlying error that caused the failure
}

// Error returns a formatted error message describing the decryption failure.
// The message includes the underlying error for debugging.
func (e DecryptError) Error() string {
	return fmt.Sprintf("crypto/salsa20: failed to decrypt data: %v", e.Err)
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
	return fmt.Sprintf("crypto/salsa20: failed to write encrypted data: %v", e.Err)
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
	return fmt.Sprintf("crypto/salsa20: failed to read encrypted data: %v", e.Err)
}
