package ed25519

import (
	"crypto/ed25519"
	"io"

	"github.com/dromara/dongle/crypto/keypair"
)

// StdSigner represents a standard ED25519 signer.
type StdSigner struct {
	keypair *keypair.Ed25519KeyPair // The key pair containing private key
	Error   error                   // Error field for storing signature errors
}

// NewStdSigner creates a new standard ED25519 signer.
func NewStdSigner(kp *keypair.Ed25519KeyPair) *StdSigner {
	s := &StdSigner{
		keypair: kp,
	}
	if kp == nil {
		s.Error = NilKeyPairError{}
		return s
	}
	if len(kp.PrivateKey) == 0 {
		s.Error = KeyPairError{Err: nil}
	}
	return s
}

// Sign generates a signature for the given data using the ED25519 private key
func (s *StdSigner) Sign(src []byte) (sign []byte, err error) {
	// Check for existing errors from initialization
	if s.Error != nil {
		err = s.Error
		return
	}

	if len(src) == 0 {
		return
	}

	// Parse the private key from PEM format
	priKey, err := s.keypair.ParsePrivateKey()
	if err != nil {
		s.Error = KeyPairError{Err: err}
		return nil, s.Error
	}

	// Generate signature using ED25519
	sign = ed25519.Sign(priKey, src)

	// Store the signature in the keypair
	s.keypair.Sign = sign
	return
}

// StdVerifier represents a standard ED25519 verifier.
type StdVerifier struct {
	keypair *keypair.Ed25519KeyPair // The key pair containing public key
	Error   error                   // Error field for storing verification errors
}

// NewStdVerifier creates a new standard ED25519 verifier.
func NewStdVerifier(kp *keypair.Ed25519KeyPair) *StdVerifier {
	v := &StdVerifier{
		keypair: kp,
	}
	if kp == nil {
		v.Error = NilKeyPairError{}
		return v
	}
	if len(kp.PublicKey) == 0 {
		v.Error = KeyPairError{Err: nil}
	}
	return v
}

// Verify verifies the signature for the given data using the ED25519 public key.
func (v *StdVerifier) Verify(src, sign []byte) (valid bool, err error) {
	// Check for existing errors from initialization
	if v.Error != nil {
		err = v.Error
		return
	}
	if len(src) == 0 || len(sign) == 0 {
		return
	}

	pubKey, err := v.keypair.ParsePublicKey()
	if err != nil {
		err = KeyPairError{Err: err}
		return
	}

	// ED25519 verification does not require hashing as it handles hashing internally
	valid = ed25519.Verify(pubKey, src, sign)
	if !valid {
		err = VerifyError{Err: nil}
	}
	return
}

// StreamSigner represents a streaming ED25519 signer that processes data in chunks.
type StreamSigner struct {
	writer  io.Writer               // Underlying writer for signature output
	keypair *keypair.Ed25519KeyPair // The key pair containing private key
	buffer  []byte                  // Buffer to accumulate data for signing
	Error   error                   // Error field for storing signature errors
}

// NewStreamSigner creates a new streaming ED25519 signer.
func NewStreamSigner(w io.Writer, kp *keypair.Ed25519KeyPair) io.WriteCloser {
	s := &StreamSigner{
		writer:  w,
		keypair: kp,
		buffer:  make([]byte, 0),
	}

	if kp == nil {
		s.Error = NilKeyPairError{}
		return s
	}

	if len(kp.PrivateKey) == 0 {
		s.Error = KeyPairError{Err: nil}
	}
	return s
}

// Write accumulates data for signing using efficient buffer management.
func (s *StreamSigner) Write(p []byte) (n int, err error) {
	// Check for existing errors from initialization
	if s.Error != nil {
		err = s.Error
		return
	}

	if len(p) == 0 {
		return
	}

	// Use efficient buffer growth strategy for true streaming
	// Pre-allocate buffer capacity to avoid frequent reallocations
	if cap(s.buffer) < len(s.buffer)+len(p) {
		newCap := len(s.buffer) + len(p)
		if newCap < 2*cap(s.buffer) {
			newCap = 2 * cap(s.buffer)
		}
		newBuffer := make([]byte, len(s.buffer), newCap)
		copy(newBuffer, s.buffer)
		s.buffer = newBuffer
	}

	// Append data to buffer
	s.buffer = append(s.buffer, p...)
	return len(p), nil
}

// Close generates the signature and writes it to the underlying writer.
func (s *StreamSigner) Close() error {
	if s.Error != nil {
		return s.Error
	}

	// Generate signature for the accumulated data
	signature, err := s.Sign(s.buffer)
	if err != nil {
		return err
	}

	// Write signature to the underlying writer
	_, err = s.writer.Write(signature)
	if err != nil {
		return err
	}

	// Close the underlying writer if it implements io.Closer
	if closer, ok := s.writer.(io.Closer); ok {
		return closer.Close()
	}

	return nil
}

// Sign generates a signature for the given data.
func (s *StreamSigner) Sign(data []byte) (signature []byte, err error) {
	if len(data) == 0 {
		return
	}

	// Parse the private key from PEM format
	priKey, err := s.keypair.ParsePrivateKey()
	if err != nil {
		err = KeyPairError{Err: err}
		return
	}

	// ED25519 signing does not require hashing as it handles hashing internally
	signature = ed25519.Sign(priKey, data)
	return
}

// StreamVerifier represents a streaming ED25519 verifier that processes data in chunks.
type StreamVerifier struct {
	reader    io.Reader               // Underlying reader for data input
	keypair   *keypair.Ed25519KeyPair // The key pair containing public key
	buffer    []byte                  // Buffer to accumulate data for verification
	signature []byte                  // Signature to verify
	verified  bool                    // Whether verification has been performed
	Error     error                   // Error field for storing verification errors
}

// NewStreamVerifier creates a new streaming ED25519 verifier.
func NewStreamVerifier(r io.Reader, kp *keypair.Ed25519KeyPair) io.WriteCloser {
	v := &StreamVerifier{
		reader:  r,
		keypair: kp,
		buffer:  make([]byte, 0),
	}

	if kp == nil {
		v.Error = NilKeyPairError{}
		return v
	}

	if len(kp.PublicKey) == 0 {
		v.Error = KeyPairError{Err: nil}
	}
	return v
}

// Write accumulates data for verification using efficient buffer management.
func (v *StreamVerifier) Write(p []byte) (n int, err error) {
	// Check for existing errors from initialization
	if v.Error != nil {
		err = v.Error
		return
	}

	if len(p) == 0 {
		return
	}

	// Use efficient buffer growth strategy for true streaming
	// Pre-allocate buffer capacity to avoid frequent reallocations
	if cap(v.buffer) < len(v.buffer)+len(p) {
		newCap := len(v.buffer) + len(p)
		if newCap < 2*cap(v.buffer) {
			newCap = 2 * cap(v.buffer)
		}
		newBuffer := make([]byte, len(v.buffer), newCap)
		copy(newBuffer, v.buffer)
		v.buffer = newBuffer
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
	valid, verifyErr := v.Verify(v.buffer, v.signature)
	if verifyErr != nil {
		return verifyErr
	}

	v.verified = valid

	// Close the underlying reader if it implements io.Closer
	if closer, ok := v.reader.(io.Closer); ok {
		return closer.Close()
	}

	return nil
}

// Verify verifies the signature for the given data.
func (v *StreamVerifier) Verify(data, signature []byte) (valid bool, err error) {
	if len(data) == 0 || len(signature) == 0 {
		return
	}

	// Parse the public key from PEM format
	pubKey, err := v.keypair.ParsePublicKey()
	if err != nil {
		err = KeyPairError{Err: err}
		return
	}

	valid = ed25519.Verify(pubKey, data, signature)
	if !valid {
		err = VerifyError{Err: nil}
	}
	return
}
