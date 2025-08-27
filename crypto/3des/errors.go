package triple_des

import (
	"fmt"
)

// KeySizeError represents an error when the Triple DES key size is invalid.
// Triple DES keys must be exactly 16 or 24 bytes (128 or 192 bits).
// For 16-byte keys, the implementation automatically expands them to 24 bytes
// using the pattern key1 + key2 + key1.
// This error occurs when the provided key does not meet these size requirements.
type KeySizeError int

// Error returns a formatted error message describing the invalid key size.
// The message includes the actual key size and the required sizes for debugging.
func (k KeySizeError) Error() string {
	return fmt.Sprintf("crypto/3des: invalid key size %d, must be 16 or 24 bytes", k)
}

// EncryptError represents an error when Triple DES encryption operation fails.
// This error occurs when the encryption process fails due to various reasons.
// The error includes the underlying error for detailed debugging.
type EncryptError struct {
	Err error // The underlying error that caused the failure
}

// Error returns a formatted error message describing the encryption failure.
// The message includes the underlying error for debugging.
func (e EncryptError) Error() string {
	return fmt.Sprintf("crypto/3des: failed to encrypt data: %v", e.Err)
}

// DecryptError represents an error when Triple DES decryption operation fails.
// This error occurs when the decryption process fails due to various reasons.
// The error includes the underlying error for detailed debugging.
type DecryptError struct {
	Err error // The underlying error that caused the failure
}

// Error returns a formatted error message describing the decryption failure.
// The message includes the underlying error for debugging.
func (e DecryptError) Error() string {
	return fmt.Sprintf("crypto/3des: failed to decrypt data: %v", e.Err)
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
	return fmt.Sprintf("crypto/3des: failed to read encrypted data: %v", e.Err)
}

// BufferError represents an error when the buffer size is too small.
// This error occurs when the provided buffer is too small to hold the decrypted data.
// The error includes both buffer size and data size for detailed debugging.
type BufferError struct {
	bufferSize int // The size of the provided buffer
	dataSize   int // The size of the data that needs to be stored
}

// Error returns a formatted error message describing the buffer size issue.
// The message includes both buffer size and data size for debugging.
func (e BufferError) Error() string {
	return fmt.Sprintf("crypto/3des: buffer size %d is too small for data size %d", e.bufferSize, e.dataSize)
}
