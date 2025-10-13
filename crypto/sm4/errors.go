package sm4

import "fmt"

// KeySizeError represents an error when the SM4 key size is invalid.
// SM4 keys must be exactly 16 bytes (128 bits).
type KeySizeError int

// Error returns the error message for KeySizeError.
func (k KeySizeError) Error() string {
	return fmt.Sprintf("crypto/sm4: invalid key size %d, key must be 16 bytes", int(k))
}

// EncryptError represents an error during SM4 encryption.
type EncryptError struct {
	Err error
}

// Error returns the error message for EncryptError.
func (e EncryptError) Error() string {
	return fmt.Sprintf("crypto/sm4: encryption failed: %v", e.Err)
}

// DecryptError represents an error during SM4 decryption.
type DecryptError struct {
	Err error
}

// Error returns the error message for DecryptError.
func (d DecryptError) Error() string {
	return fmt.Sprintf("crypto/sm4: decryption failed: %v", d.Err)
}

// ReadError represents an error during data reading in streaming operations.
type ReadError struct {
	Err error
}

// Error returns the error message for ReadError.
func (r ReadError) Error() string {
	return fmt.Sprintf("crypto/sm4: read failed: %v", r.Err)
}
