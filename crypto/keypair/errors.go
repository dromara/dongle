package keypair

import "fmt"

type EmptyPublicKeyError struct {
}

func (e EmptyPublicKeyError) Error() string {
	return "public key cannot be empty"
}

type EmptyPrivateKeyError struct {
}

func (e EmptyPrivateKeyError) Error() string {
	return "private key cannot be empty"
}

type InvalidPublicKeyError struct {
	Err error
}

func (e InvalidPublicKeyError) Error() string {
	if e.Err == nil {
		return "invalid public key"
	}
	return fmt.Sprintf("invalid public key: %v", e.Err)
}

type InvalidPrivateKeyError struct {
	Err error
}

func (e InvalidPrivateKeyError) Error() string {
	if e.Err == nil {
		return "invalid private key"
	}
	return fmt.Sprintf(" invalid private key: %v", e.Err)
}

type UnsupportedPemTypeError struct {
}

// Error returns a formatted error message describing the unsupported padding mode.
// The message includes the mode name and explains why it's not supported.
func (e UnsupportedPemTypeError) Error() string {
	return "unsupported pem block type"
}
