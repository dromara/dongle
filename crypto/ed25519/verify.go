package ed25519

import (
	"crypto/ed25519"
	"io"

	"github.com/dromara/dongle/crypto/keypair"
)

// StdVerifier represents a standard ED25519 verifier.
type StdVerifier struct {
	keypair keypair.Ed25519KeyPair
	cache   cache // Cached keys for better performance
	Error   error // Error field for storing verification errors
}

// NewStdVerifier creates a new standard ED25519 verifier.
func NewStdVerifier(kp *keypair.Ed25519KeyPair) *StdVerifier {
	v := &StdVerifier{
		keypair: *kp,
	}
	if len(kp.PublicKey) == 0 {
		v.Error = VerifyError{Err: keypair.EmptyPublicKeyError{}}
		return v
	}

	pubKey, err := kp.ParsePublicKey()
	if err != nil {
		v.Error = VerifyError{Err: err}
		return v
	}
	v.cache.pubKey = pubKey

	return v
}

// Verify verifies the signature for the given data using the ED25519 public key.
func (v *StdVerifier) Verify(src, sign []byte) (valid bool, err error) {
	// Check for existing errors from initialization
	if v.Error != nil {
		err = v.Error
		return
	}
	if len(src) == 0 {
		return
	}
	if len(sign) == 0 {
		err = VerifyError{Err: keypair.EmptySignatureError{}}
		return
	}

	// ED25519 verification does not require hashing as it handles hashing internally
	valid = ed25519.Verify(v.cache.pubKey, src, sign)
	if !valid {
		v.Error = VerifyError{Err: nil}
		return false, v.Error
	}
	return
}

// StreamVerifier represents a streaming ED25519 verifier that processes data in chunks.
type StreamVerifier struct {
	keypair   keypair.Ed25519KeyPair // Key pair containing public key
	cache     cache                  // Cached keys for better performance
	reader    io.Reader              // Underlying reader for signature input
	buffer    []byte                 // Buffer to accumulate data for verification
	signature []byte                 // Signature to verify
	verified  bool                   // Whether verification has been performed
	Error     error                  // Error field for storing verification errors
}

// NewStreamVerifier creates a new streaming ED25519 verifier.
func NewStreamVerifier(r io.Reader, kp *keypair.Ed25519KeyPair) io.WriteCloser {
	v := &StreamVerifier{
		reader:  r,
		keypair: *kp,
	}
	if len(kp.PublicKey) == 0 {
		v.Error = VerifyError{Err: keypair.EmptyPublicKeyError{}}
		return v
	}

	pubKey, err := kp.ParsePublicKey()
	if err != nil {
		v.Error = VerifyError{Err: err}
		return v
	}
	v.cache.pubKey = pubKey

	return v
}

// verify verifies the signature for the given data.
func (v *StreamVerifier) verify(data, sign []byte) (valid bool, err error) {
	if v.Error != nil {
		err = v.Error
		return
	}
	if len(data) == 0 {
		return
	}

	if len(sign) == 0 {
		err = VerifyError{Err: keypair.EmptySignatureError{}}
		return
	}

	valid = ed25519.Verify(v.cache.pubKey, data, sign)
	if !valid {
		v.Error = VerifyError{Err: nil}
		return false, v.Error
	}
	return valid, nil
}

// Write accumulates data for verification.
func (v *StreamVerifier) Write(p []byte) (n int, err error) {
	if v.Error != nil {
		err = v.Error
		return
	}

	if len(p) == 0 {
		return
	}

	// Append data to buffer
	v.buffer = append(v.buffer, p...)
	return len(p), nil
}

// Close performs the final verification.
func (v *StreamVerifier) Close() error {
	if v.Error != nil {
		return v.Error
	}

	// Read signature data from the underlying reader
	var err error
	v.signature, err = io.ReadAll(v.reader)
	if err != nil {
		return ReadError{Err: err}
	}
	if len(v.signature) == 0 {
		return nil
	}

	// Verify the signature using the accumulated data
	valid, err := v.verify(v.buffer, v.signature)
	if err != nil {
		return err
	}

	v.verified = valid

	// Close the underlying reader if it implements io.Closer
	if closer, ok := v.reader.(io.Closer); ok {
		return closer.Close()
	}

	return nil
}
