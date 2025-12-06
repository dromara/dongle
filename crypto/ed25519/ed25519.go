// Package ed25519 implements ED25519 digital signature generation and verification with streaming support.
// It provides ED25519 operations using the standard ED25519 algorithm with support
// for high-performance digital signatures and verification.
package ed25519

import (
	"crypto/ed25519"
	"io"

	"github.com/dromara/dongle/crypto/keypair"
)

// StdSigner represents a standard ED25519 signer.
type StdSigner struct {
	keypair keypair.Ed25519KeyPair // The key pair containing private key
	Error   error                  // Error field for storing signature errors
}

// NewStdSigner creates a new standard ED25519 signer.
func NewStdSigner(kp *keypair.Ed25519KeyPair) *StdSigner {
	s := &StdSigner{
		keypair: *kp,
	}
	if len(kp.PrivateKey) == 0 {
		s.Error = SignError{Err: keypair.EmptyPrivateKeyError{}}
		return s
	}
	return s
}

// Sign generates a signature for the given data using the ED25519 private key
func (s *StdSigner) Sign(src []byte) (sign []byte, err error) {
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
		s.Error = SignError{Err: err}
		return nil, s.Error
	}

	// Generate signature using ED25519
	sign = ed25519.Sign(priKey, src)
	return
}

// StdVerifier represents a standard ED25519 verifier.
type StdVerifier struct {
	keypair keypair.Ed25519KeyPair // The key pair containing public key
	Error   error                  // Error field for storing verification errors
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

	pubKey, err := v.keypair.ParsePublicKey()
	if err != nil {
		v.Error = VerifyError{Err: err}
		return false, v.Error
	}

	// ED25519 verification does not require hashing as it handles hashing internally
	valid = ed25519.Verify(pubKey, src, sign)
	if !valid {
		v.Error = VerifyError{Err: nil}
		return false, v.Error
	}
	return
}

// StreamSigner represents a streaming ED25519 signer that processes data in chunks.
type StreamSigner struct {
	keypair keypair.Ed25519KeyPair // Key pair containing private key
	priKey  ed25519.PrivateKey     // Cached private key for better performance
	writer  io.Writer              // Underlying writer for signature output
	buffer  []byte                 // Buffer to accumulate data for signing
	Error   error                  // Error field for storing signature errors
}

// NewStreamSigner creates a new streaming ED25519 signer.
func NewStreamSigner(w io.Writer, kp *keypair.Ed25519KeyPair) io.WriteCloser {
	s := &StreamSigner{
		writer:  w,
		keypair: *kp,
	}
	if len(kp.PrivateKey) == 0 {
		s.Error = SignError{Err: keypair.EmptyPrivateKeyError{}}
		return s
	}

	// Parse and cache the private key for reuse
	priKey, err := kp.ParsePrivateKey()
	if err != nil {
		s.Error = SignError{Err: err}
		return s
	}
	s.priKey = priKey

	return s
}

// sign generates a signature for the given data.
func (s *StreamSigner) sign(data []byte) (signature []byte, err error) {
	if len(data) == 0 {
		return
	}

	// Use cached private key
	if s.priKey == nil {
		s.Error = SignError{Err: keypair.EmptyPrivateKeyError{}}
		return nil, s.Error
	}

	// ED25519 signing does not require hashing as it handles hashing internally
	signature = ed25519.Sign(s.priKey, data)
	return
}

// Write accumulates data for signing.
func (s *StreamSigner) Write(p []byte) (n int, err error) {
	if s.Error != nil {
		err = s.Error
		return
	}

	if len(p) == 0 {
		return
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
	signature, err := s.sign(s.buffer)
	if err != nil {
		return err
	}

	// Write signature to the underlying writer
	if _, err = s.writer.Write(signature); err != nil {
		return err
	}

	// Close the underlying writer if it implements io.Closer
	if closer, ok := s.writer.(io.Closer); ok {
		return closer.Close()
	}

	return nil
}

// StreamVerifier represents a streaming ED25519 verifier that processes data in chunks.
type StreamVerifier struct {
	keypair   keypair.Ed25519KeyPair // Key pair containing public key
	pubKey    ed25519.PublicKey      // Cached public key for better performance
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

	// Parse and cache the public key for reuse
	pubKey, err := kp.ParsePublicKey()
	if err != nil {
		v.Error = VerifyError{Err: err}
		return v
	}
	v.pubKey = pubKey

	return v
}

// verify verifies the signature for the given data.
func (v *StreamVerifier) verify(data, signature []byte) (valid bool, err error) {
	if len(data) == 0 || len(signature) == 0 {
		return
	}

	// Use cached public key
	if v.pubKey == nil {
		v.Error = VerifyError{Err: keypair.EmptyPublicKeyError{}}
		return false, v.Error
	}

	valid = ed25519.Verify(v.pubKey, data, signature)
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
