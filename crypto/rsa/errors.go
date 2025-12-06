package rsa

import "fmt"

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
