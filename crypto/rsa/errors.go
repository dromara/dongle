package rsa

import "fmt"

type NilKeyPairError struct {
}

func (e NilKeyPairError) Error() string {
	return fmt.Sprintf("crypto/rsa: keypair cannot be nil")
}

type PublicKeyUnsetError struct {
}

// Error returns a formatted error message indicating that the key is not set.
// The message provides guidance to use the SetKey() method to resolve the issue.
func (k PublicKeyUnsetError) Error() string {
	return fmt.Sprintf("public key not set, please use SetPublicKey() method")
}

type PrivateKeyUnsetError struct {
}

func (k PrivateKeyUnsetError) Error() string {
	return fmt.Sprintf("private key not set, please use SetPrivateKey() method")
}

type KeyPairError struct {
	Err error
}

func (e KeyPairError) Error() string {
	return fmt.Sprintf("crypto/rsa: %v", e.Err)
}

type EncryptError struct {
	Err error
}

func (e EncryptError) Error() string {
	return fmt.Sprintf("crypto/rsa: failed to encrypt data: %v", e.Err)
}

type DecryptError struct {
	Err error
}

func (e DecryptError) Error() string {
	return fmt.Sprintf("crypto/rsa: failed to decrypt data: %v", e.Err)
}

type SignError struct {
	Err error
}

func (e SignError) Error() string {
	return fmt.Sprintf("crypto/rsa: failed to sign data: %v", e.Err)
}

type VerifyError struct {
	Err error
}

func (e VerifyError) Error() string {
	return fmt.Sprintf("crypto/rsa: failed to verify signature: %v", e.Err)
}

type ReadError struct {
	Err error
}

func (e ReadError) Error() string {
	return fmt.Sprintf("crypto/rsa: failed to read encrypted data: %v", e.Err)
}

type BufferError struct {
	bufferSize int
	dataSize   int
}

func (e BufferError) Error() string {
	return fmt.Sprintf("crypto/rsa: buffer size %d is too small for data size %d", e.bufferSize, e.dataSize)
}

type DataTooLargeError struct {
}

func (e DataTooLargeError) Error() string {
	return fmt.Sprintf("crypto/rsa: data too large for direct encryption")
}

type NoSignatureError struct {
}

func (e NoSignatureError) Error() string {
	return fmt.Sprintf("crypto/rsa: no signature provided for verification")
}
