package cipher

import "fmt"

// InvalidSrcError represents an error when the source data length is invalid
// for the specified block cipher mode. This error occurs when the source
// data length is not a multiple of the block size, which is required for
// most block cipher operations.
type InvalidSrcError struct {
	mode BlockMode // The cipher mode that caused the error
	src  []byte    // The source data that has invalid length
	size int       // The required block size for the cipher
}

// Error returns a formatted error message describing the invalid source data length.
// The message includes the cipher mode, actual source length, and required block size.
func (e InvalidSrcError) Error() string {
	return fmt.Sprintf("%s: src length %d must be a multiple of block size %d", e.mode, len(e.src), e.size)
}

// EmptyIVError represents an error when the initialization vector (IV) is empty
// for cipher modes that require an IV. This error occurs when the IV is nil
// or has zero length, which is not allowed for secure cipher operations.
type EmptyIVError struct {
	mode BlockMode // The cipher mode that requires a non-empty IV
}

// Error returns a formatted error message indicating that the IV cannot be empty
// for the specified cipher mode.
func (e EmptyIVError) Error() string {
	return fmt.Sprintf("%s: iv cannot be empty", e.mode)
}

// InvalidIVError represents an error when the initialization vector (IV) length
// is invalid for the specified block cipher. This error occurs when the IV
// length does not match the required block size for the cipher.
type InvalidIVError struct {
	mode BlockMode // The cipher mode that caused the error
	iv   []byte    // The IV that has invalid length
	size int       // The required block size for the cipher
}

// Error returns a formatted error message describing the invalid IV length.
// The message includes the cipher mode, actual IV length, and required block size.
func (e InvalidIVError) Error() string {
	return fmt.Sprintf("%s: iv length %d must equal block size %d", e.mode, len(e.iv), e.size)
}

// EmptyNonceError represents an error when the nonce (number used once) is empty
// for cipher modes that require a nonce, such as GCM mode. This error occurs
// when the nonce is nil or has zero length, which is required for secure
// authenticated encryption.
type EmptyNonceError struct {
	mode BlockMode // The cipher mode that requires a non-empty nonce
}

// Error returns a formatted error message indicating that the nonce cannot be empty
// for the specified cipher mode.
func (e EmptyNonceError) Error() string {
	return fmt.Sprintf("%s: nonce cannot be empty", e.mode)
}

// CreateCipherError represents an error that occurs during cipher creation.
// This error wraps the underlying error that prevented the cipher from
// being created successfully, such as invalid key length or unsupported
// cipher mode.
type CreateCipherError struct {
	mode BlockMode // The cipher mode that failed to be created
	err  error     // The underlying error that caused the creation failure
}

// Error returns a formatted error message describing the cipher creation failure.
// The message includes the cipher mode and the underlying error details.
func (e CreateCipherError) Error() string {
	return fmt.Sprintf("%s: failed to create cipher: %v", e.mode, e.err)
}
