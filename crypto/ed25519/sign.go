package ed25519

import (
	"crypto/ed25519"
	"io"

	"github.com/dromara/dongle/crypto/keypair"
)

// StdSigner represents a standard ED25519 signer.
type StdSigner struct {
	keypair keypair.Ed25519KeyPair // The key pair containing private key
	cache   cache                  // Cached keys for better performance
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

	priKey, err := kp.ParsePrivateKey()
	if err != nil {
		s.Error = SignError{Err: err}
		return s
	}
	s.cache.priKey = priKey

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

	sign = ed25519.Sign(s.cache.priKey, src)
	return
}

// StreamSigner represents a streaming ED25519 signer that processes data in chunks.
type StreamSigner struct {
	keypair keypair.Ed25519KeyPair // Key pair containing private key
	cache   cache                  // Cached keys for better performance
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

	priKey, err := kp.ParsePrivateKey()
	if err != nil {
		s.Error = SignError{Err: err}
		return s
	}
	s.cache.priKey = priKey

	return s
}

// sign generates a signature for the given data.
func (s *StreamSigner) sign(data []byte) (signature []byte, err error) {
	if s.Error != nil {
		err = s.Error
		return
	}
	if len(data) == 0 {
		return
	}

	// ED25519 signing does not require hashing as it handles hashing internally
	signature = ed25519.Sign(s.cache.priKey, data)
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
