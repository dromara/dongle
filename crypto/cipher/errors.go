package cipher

import "fmt"

// EmptySrcError represents an error when the source data is empty.
type EmptySrcError struct {
	mode BlockMode
}

// Error returns a formatted error message indicating that the source cannot be empty
// for the specified cipher mode.
func (e EmptySrcError) Error() string {
	return fmt.Sprintf("src cannot be empty in '%s' block mode", e.mode)
}

// EmptyIVError represents an error when the initialization vector (IV) is empty
// for cipher modes that require an IV. This error occurs when the IV is nil
// or has zero length, which is not allowed for secure cipher operations.
type EmptyIVError struct {
	mode BlockMode
}

// Error returns a formatted error message indicating that the IV cannot be empty
// for the specified cipher mode.
func (e EmptyIVError) Error() string {
	return fmt.Sprintf("iv cannot be empty in '%s' block mode", e.mode)
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
	return fmt.Sprintf("nonce cannot be empty in '%s' block mode", e.mode)
}

// InvalidPlaintextError represents an error when the plaintext length is invalid
// for the specified block cipher mode. This error occurs when the plaintext
// length is not a multiple of the block size, which is required for most
// block cipher operations.
type InvalidPlaintextError struct {
	mode BlockMode // The cipher mode that caused the error
	src  []byte    // The source data that has invalid length
	size int       // The required block size for the cipher
}

// Error returns a formatted error message describing the invalid plaintext length.
// The message includes the cipher mode, actual plaintext length, and required block size.
func (e InvalidPlaintextError) Error() string {
	return fmt.Sprintf("plaintext length %d must be a multiple of block size %d in '%s' block mode", len(e.src), e.size, e.mode)
}

// InvalidCiphertextError represents an error when the ciphertext length is invalid
// for the specified block cipher mode. This error occurs when the ciphertext
// length is not a multiple of the block size, which is required for most
// block cipher operations.
type InvalidCiphertextError struct {
	mode BlockMode // The cipher mode that caused the error
	src  []byte    // The source data that has invalid length
	size int       // The required block size for the cipher
}

// Error returns a formatted error message describing the invalid ciphertext length.
// The message includes the ciphertext length, required block size, and cipher mode.
func (e InvalidCiphertextError) Error() string {
	return fmt.Sprintf("raw ciphertext by decoding length %d must be a multiple of block size %d in '%s' block mode", len(e.src), e.size, e.mode)
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
	return fmt.Sprintf("iv length %d must equal block size %d in '%s' block mode", len(e.iv), e.size, e.mode)
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
	return fmt.Sprintf("failed to create cipher in '%s' block mode: %v", e.mode, e.err)
}

// UnsupportedBlockModeError represents an error when an unsupported block mode is used.
type UnsupportedBlockModeError struct {
	mode BlockMode
}

// Error returns a formatted error message describing the unsupported mode.
// The message includes the mode name and explains why it's not supported.
func (e UnsupportedBlockModeError) Error() string {
	return fmt.Sprintf("unsupported block mode '%s'", e.mode)
}

// UnsupportedPaddingModeError represents an error when an unsupported padding mode is used.
type UnsupportedPaddingModeError struct {
	mode PaddingMode
}

// Error returns a formatted error message describing the unsupported padding mode.
// The message includes the mode name and explains why it's not supported.
func (e UnsupportedPaddingModeError) Error() string {
	return fmt.Sprintf("unsupported padding mode '%s'", e.mode)
}
