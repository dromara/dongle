package sm2

import (
	"io"

	"github.com/dromara/dongle/crypto/internal/sm2"
	"github.com/dromara/dongle/crypto/keypair"
)

// StdSigner signs data using an SM2 private key.
type StdSigner struct {
	keypair keypair.Sm2KeyPair
	cache   cache
	Error   error
}

// NewStdSigner creates a new SM2 signer bound to the given key pair.
func NewStdSigner(kp *keypair.Sm2KeyPair) *StdSigner {
	s := &StdSigner{keypair: *kp}
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

// Sign generates an SM2 signature for the given data.
func (s *StdSigner) Sign(src []byte) (sign []byte, err error) {
	if s.Error != nil {
		err = s.Error
		return
	}
	if len(src) == 0 {
		return
	}
	sign, err = sm2.SignWithPrivateKey(s.cache.priKey, src, s.keypair.UID, uint8(s.keypair.SingMode))
	if err != nil {
		err = SignError{Err: err}
		return
	}
	return
}

// StreamSigner buffers data and writes SM2 signature on Close.
type StreamSigner struct {
	writer  io.Writer
	keypair keypair.Sm2KeyPair
	cache   cache
	buffer  []byte
	Error   error
}

// NewStreamSigner returns a WriteCloser that signs all written data
// with the provided key pair and writes the signature on Close.
func NewStreamSigner(w io.Writer, kp *keypair.Sm2KeyPair) io.WriteCloser {
	s := &StreamSigner{
		writer:  w,
		keypair: *kp,
		buffer:  make([]byte, 0),
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
func (s *StreamSigner) sign(data []byte) (sign []byte, err error) {
	if s.Error != nil {
		err = s.Error
		return
	}
	if len(data) == 0 {
		return
	}
	sign, err = sm2.SignWithPrivateKey(s.cache.priKey, data, s.keypair.UID, uint8(s.keypair.SingMode))
	if err != nil {
		err = SignError{Err: err}
		return
	}
	return
}

// Write buffers data to be signed.
func (s *StreamSigner) Write(p []byte) (n int, err error) {
	if s.Error != nil {
		err = s.Error
		return
	}
	if len(p) == 0 {
		return
	}
	s.buffer = append(s.buffer, p...)
	return len(p), nil
}

// Close signs the buffered data and writes the signature to the
// underlying writer. If the writer implements io.Closer, it is closed.
func (s *StreamSigner) Close() error {
	if s.Error != nil {
		return s.Error
	}
	if len(s.buffer) == 0 {
		if closer, ok := s.writer.(io.Closer); ok {
			return closer.Close()
		}
		return nil
	}
	// Sign the buffered data
	sign, err := s.sign(s.buffer)
	if err != nil {
		return err
	}
	// Write signature to the underlying writer
	if _, writeErr := s.writer.Write(sign); writeErr != nil {
		return SignError{Err: writeErr}
	}
	if closer, ok := s.writer.(io.Closer); ok {
		return closer.Close()
	}
	return nil
}
