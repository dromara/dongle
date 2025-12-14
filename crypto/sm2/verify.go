package sm2

import (
	"io"

	"github.com/dromara/dongle/crypto/internal/sm2"
	"github.com/dromara/dongle/crypto/keypair"
)

// StdVerifier verifies data using an SM2 public key.
type StdVerifier struct {
	keypair keypair.Sm2KeyPair
	cache   cache
	Error   error
}

// NewStdVerifier creates a new SM2 verifier bound to the given key pair.
func NewStdVerifier(kp *keypair.Sm2KeyPair) *StdVerifier {
	v := &StdVerifier{keypair: *kp}
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

// Verify verifies an SM2 signature for the given data.
func (v *StdVerifier) Verify(src, sign []byte) (valid bool, err error) {
	if v.Error != nil {
		return false, v.Error
	}
	if len(src) == 0 {
		return false, nil
	}
	if len(sign) == 0 {
		err = VerifyError{Err: keypair.EmptySignatureError{}}
		return false, err
	}

	// Verify the signature (Verify internally calculates ZA and digest)
	valid = sm2.Verify(v.cache.pubKey, src, v.keypair.UID, sign)
	if !valid {
		v.Error = VerifyError{Err: nil}
		return false, v.Error
	}

	return valid, nil
}

// StreamVerifier reads signature from an io.Reader and verifies data written to it.
type StreamVerifier struct {
	reader    io.Reader
	keypair   keypair.Sm2KeyPair
	cache     cache
	buffer    []byte
	signature []byte
	verified  bool
	Error     error
}

// NewStreamVerifier creates a WriteCloser that verifies data written to it
// using the signature read from the provided reader.
func NewStreamVerifier(r io.Reader, kp *keypair.Sm2KeyPair) io.WriteCloser {
	v := &StreamVerifier{
		reader:  r,
		keypair: *kp,
		buffer:  make([]byte, 0),
	}
	if len(kp.PublicKey) == 0 {
		v.Error = VerifyError{Err: keypair.EmptyPublicKeyError{}}
		return v
	}

	// Parse and cache the public key for reuse
	pubKey, err := kp.ParsePublicKey()
	if err != nil {
		v.Error = VerifyError{Err: err}
		return v
	}
	v.cache.pubKey = pubKey

	return v
}

// verify verifies the signature for the given data.
func (v *StreamVerifier) verify(data, signature []byte) (valid bool, err error) {
	if len(data) == 0 || len(signature) == 0 {
		return false, nil
	}

	// Verify the signature (Verify internally calculates ZA and digest)
	valid = sm2.Verify(v.cache.pubKey, data, v.keypair.UID, signature)
	if !valid {
		v.Error = VerifyError{Err: nil}
		return false, v.Error
	}

	return valid, nil
}

// Write buffers data for verification.
func (v *StreamVerifier) Write(p []byte) (n int, err error) {
	if v.Error != nil {
		return 0, v.Error
	}
	if len(p) == 0 {
		return 0, nil
	}
	v.buffer = append(v.buffer, p...)
	return len(p), nil
}

// Close reads the signature from the underlying reader and performs verification.
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
	// Verify the signature using the buffered data
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
