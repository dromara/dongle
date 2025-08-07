package keypair

import "fmt"

type NilPemBlockError struct {
}

func (e NilPemBlockError) Error() string {
	return fmt.Sprintf("pem block cannot be nil")
}

type InvalidPublicKeyError struct {
	Err error
}

func (e InvalidPublicKeyError) Error() string {
	return fmt.Sprintf("invalid public key: %v", e.Err)
}

type InvalidPrivateKeyError struct {
	Err error
}

func (e InvalidPrivateKeyError) Error() string {
	return fmt.Sprintf(" invalid private key: %v", e.Err)
}
