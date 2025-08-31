package ed25519

import "fmt"

type NilKeyPairError struct {
}

func (e NilKeyPairError) Error() string {
	return fmt.Sprintf("key pair cannot be nil")
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
	if e.Err == nil {
		return fmt.Sprintf("invalid key pair")
	}
	return fmt.Sprintf("invalid key pair: %v", e.Err)
}

type SignError struct {
	Err error
}

func (e SignError) Error() string {
	if e.Err == nil {
		return fmt.Sprintf("sign error")
	}
	return fmt.Sprintf("sign error: %v", e.Err)
}

type VerifyError struct {
	Err error
}

func (e VerifyError) Error() string {
	if e.Err == nil {
		return fmt.Sprintf("verify error")
	}
	return fmt.Sprintf("verify error: %v", e.Err)
}

type ReadError struct {
	Err error
}

func (e ReadError) Error() string {
	if e.Err == nil {
		return fmt.Sprintf("read error")
	}
	return fmt.Sprintf("read error: %v", e.Err)
}

type NoSignatureError struct {
}

func (e NoSignatureError) Error() string {
	return fmt.Sprintf("crypto/ed25519: no signature provided for verification")
}