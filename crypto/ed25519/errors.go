package ed25519

import "fmt"

type SignError struct {
	Err error
}

func (e SignError) Error() string {
	return fmt.Sprintf("crypto/ed25519: failed to sign data: %v", e.Err)
}

type VerifyError struct {
	Err error
}

func (e VerifyError) Error() string {
	return fmt.Sprintf("crypto/ed25519: failed to verify signature: %v", e.Err)
}

type ReadError struct {
	Err error
}

func (e ReadError) Error() string {
	return fmt.Sprintf("crypto/ed25519: failed to read data: %v", e.Err)
}
