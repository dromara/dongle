package keypair

import "fmt"

type EmptyPublicKeyError struct {
}

func (e EmptyPublicKeyError) Error() string {
	return "public key cannot be empty"
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

type EmptyPrivateKeyError struct {
}

func (e EmptyPrivateKeyError) Error() string {
	return "private key cannot be empty"
}

type InvalidPrivateKeyError struct {
	Err error
}

func (e InvalidPrivateKeyError) Error() string {
	if e.Err == nil {
		return "invalid private key"
	}
	return fmt.Sprintf("invalid private key: %v", e.Err)
}

type EmptyFormatError struct {
}

func (e EmptyFormatError) Error() string {
	return "key format cannot be empty, please call SetFormat() to set key format (PKCS1/PKCS8)"
}

type UnsupportedKeyFormatError struct {
	// Algorithm is the algorithm that rejected the key, for example "RSA".
	Algorithm string
	// Detail explains why the key could not be used, it is empty when the
	// error only reports that the requested format is unknown.
	Detail string
}

func (e UnsupportedKeyFormatError) Error() string {
	switch {
	case e.Detail != "" && e.Algorithm != "":
		return fmt.Sprintf("unsupported %s key format: %s", e.Algorithm, e.Detail)
	case e.Detail != "":
		return fmt.Sprintf("unsupported key format: %s", e.Detail)
	case e.Algorithm != "":
		return fmt.Sprintf("unsupported %s key format", e.Algorithm)
	}
	return "unsupported key format, only PKCS1 and PKCS8 are supported"
}

type EmptyPaddingError struct {
}

func (e EmptyPaddingError) Error() string {
	return "padding scheme cannot be empty, please call SetPadding() to set padding scheme (PKCS1v15/OAEP/PSS)"
}

type UnsupportedPaddingSchemeError struct {
	Padding string
}

func (e UnsupportedPaddingSchemeError) Error() string {
	return fmt.Sprintf("unsupported padding scheme: %s, only PKCS1v15, OAEP, and PSS are supported", e.Padding)
}

type EmptySignatureError struct {
}

func (e EmptySignatureError) Error() string {
	return "no signature provided for verification"
}
