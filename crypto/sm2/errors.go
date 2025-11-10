package sm2

import "fmt"

type NilKeyPairError struct{}

func (e NilKeyPairError) Error() string {
	return fmt.Sprintf("key pair cannot be nil")
}

type PublicKeyUnsetError struct{}

func (e PublicKeyUnsetError) Error() string {
	return fmt.Sprintf("public key not set, please use SetPublicKey() method")
}

type PrivateKeyUnsetError struct{}

func (e PrivateKeyUnsetError) Error() string {
	return fmt.Sprintf("private key not set, please use SetPrivateKey() method")
}

type KeyPairError struct{ Err error }

func (e KeyPairError) Error() string {
	if e.Err == nil {
		return fmt.Sprintf("invalid key pair")
	}
	return fmt.Sprintf("invalid key pair: %v", e.Err)
}

type SignError struct{ Err error }

func (e SignError) Error() string {
	if e.Err == nil {
		return fmt.Sprintf("sign error")
	}
	return fmt.Sprintf("sign error: %v", e.Err)
}

type VerifyError struct{ Err error }

func (e VerifyError) Error() string {
	if e.Err == nil {
		return fmt.Sprintf("verify error")
	}
	return fmt.Sprintf("verify error: %v", e.Err)
}

type ReadError struct{ Err error }

func (e ReadError) Error() string {
	if e.Err == nil {
		return fmt.Sprintf("read error")
	}
	return fmt.Sprintf("read error: %v", e.Err)
}

type NoSignatureError struct{}

func (e NoSignatureError) Error() string {
	return fmt.Sprintf("crypto/sm2: no signature provided for verification")
}

type EncryptError struct{ Err error }

func (e EncryptError) Error() string {
	if e.Err == nil {
		return fmt.Sprintf("encrypt error")
	}
	return fmt.Sprintf("encrypt error: %v", e.Err)
}

type DecryptError struct{ Err error }

func (e DecryptError) Error() string {
	if e.Err == nil {
		return fmt.Sprintf("decrypt error")
	}
	return fmt.Sprintf("decrypt error: %v", e.Err)
}
