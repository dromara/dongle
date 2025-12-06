package keypair

import (
	"errors"
	"testing"
)

func TestEmptyPublicKeyError_Error(t *testing.T) {
	err := EmptyPublicKeyError{}
	expected := "public key cannot be empty"
	if err.Error() != expected {
		t.Errorf("EmptyPublicKeyError.Error() = %q, want %q", err.Error(), expected)
	}
}

func TestInvalidPublicKeyError_Error(t *testing.T) {
	originalErr := errors.New("test error")
	err := InvalidPublicKeyError{Err: originalErr}
	expected := "invalid public key: test error"
	if err.Error() != expected {
		t.Errorf("InvalidPublicKeyError.Error() = %q, want %q", err.Error(), expected)
	}
}

func TestEmptyPrivateKeyError_Error(t *testing.T) {
	err := EmptyPrivateKeyError{}
	expected := "private key cannot be empty"
	if err.Error() != expected {
		t.Errorf("EmptyPrivateKeyError.Error() = %q, want %q", err.Error(), expected)
	}
}

func TestInvalidPrivateKeyError_Error(t *testing.T) {
	originalErr := errors.New("test error")
	err := InvalidPrivateKeyError{Err: originalErr}
	expected := " invalid private key: test error"
	if err.Error() != expected {
		t.Errorf("InvalidPrivateKeyError.Error() = %q, want %q", err.Error(), expected)
	}
}

func TestEmptyFormatError_Error(t *testing.T) {
	err := EmptyFormatError{}
	expected := "key format cannot be empty, please call SetFormat() to set key format (PKCS1/PKCS8)"
	if err.Error() != expected {
		t.Errorf("EmptyFormatError.Error() = %q, want %q", err.Error(), expected)
	}
}

func TestUnsupportedKeyFormatError_Error(t *testing.T) {
	err := UnsupportedKeyFormatError{}
	expected := "unsupported key format, only PKCS1 and PKCS8 are supported"
	if err.Error() != expected {
		t.Errorf("UnsupportedKeyFormatError.Error() = %q, want %q", err.Error(), expected)
	}
}

func TestEmptyPaddingError_Error(t *testing.T) {
	err := EmptyPaddingError{}
	expected := "padding scheme cannot be empty, please call SetPadding() to set padding scheme (PKCS1v15/OAEP/PSS)"
	if err.Error() != expected {
		t.Errorf("EmptyPaddingError.Error() = %q, want %q", err.Error(), expected)
	}
}

func TestUnsupportedPaddingSchemeError_Error(t *testing.T) {
	err := UnsupportedPaddingSchemeError{Padding: "InvalidPadding"}
	expected := "unsupported padding scheme: InvalidPadding, only PKCS1v15, OAEP, and PSS are supported"
	if err.Error() != expected {
		t.Errorf("UnsupportedPaddingSchemeError.Error() = %q, want %q", err.Error(), expected)
	}
}

func TestEmptySignatureError_Error(t *testing.T) {
	err := EmptySignatureError{}
	expected := "no signature provided for verification"
	if err.Error() != expected {
		t.Errorf("EmptySignatureError.Error() = %q, want %q", err.Error(), expected)
	}
}
