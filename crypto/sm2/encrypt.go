package sm2

import (
	"io"

	"github.com/dromara/dongle/crypto/internal/sm2"
	"github.com/dromara/dongle/crypto/keypair"
)

// StdEncrypter encrypts data using an SM2 public key.
// The ciphertext component order is derived from Sm2KeyPair.Order.
type StdEncrypter struct {
	keypair keypair.Sm2KeyPair
	cache   cache
	Error   error
}

// NewStdEncrypter creates a new SM2 encrypter bound to the given key pair.
func NewStdEncrypter(kp *keypair.Sm2KeyPair) *StdEncrypter {
	e := &StdEncrypter{keypair: *kp}
	if len(kp.PublicKey) == 0 {
		e.Error = EncryptError{Err: keypair.EmptyPublicKeyError{}}
		return e
	}
	pubKey, err := kp.ParsePublicKey()
	if err != nil {
		e.Error = EncryptError{Err: err}
		return e
	}
	e.cache.pubKey = pubKey
	return e
}

// Encrypt encrypts data with SM2 public key.
func (e *StdEncrypter) Encrypt(src []byte) (dst []byte, err error) {
	if e.Error != nil {
		err = e.Error
		return
	}
	if len(src) == 0 {
		return
	}
	dst, err = sm2.EncryptWithPublicKey(e.cache.pubKey, src, e.keypair.Window, string(e.keypair.Mode))
	if err != nil {
		err = EncryptError{Err: err}
		return
	}
	return
}

// StreamEncrypter buffers plaintext and writes SM2 ciphertext on Close.
type StreamEncrypter struct {
	writer  io.Writer
	keypair keypair.Sm2KeyPair
	cache   cache
	buffer  []byte
	Error   error
}

// NewStreamEncrypter returns a WriteCloser that encrypts all written data
// with the provided key pair and writes the ciphertext on Close.
func NewStreamEncrypter(w io.Writer, kp *keypair.Sm2KeyPair) io.WriteCloser {
	e := &StreamEncrypter{
		writer:  w,
		keypair: *kp,
		buffer:  make([]byte, 0),
	}
	if len(kp.PublicKey) == 0 {
		e.Error = EncryptError{Err: keypair.EmptyPublicKeyError{}}
		return e
	}
	pubKey, err := kp.ParsePublicKey()
	if err != nil {
		e.Error = EncryptError{Err: err}
		return e
	}
	e.cache.pubKey = pubKey
	return e
}

// encrypt encrypts plaintext with SM2 public key.
func (e *StreamEncrypter) encrypt(src []byte) (dst []byte, err error) {
	if e.Error != nil {
		err = e.Error
		return
	}
	if len(src) == 0 {
		return
	}
	dst, err = sm2.EncryptWithPublicKey(e.cache.pubKey, src, e.keypair.Window, string(e.keypair.Mode))
	if err != nil {
		err = EncryptError{Err: err}
		return
	}
	return
}

// Write buffers plaintext to be encrypted.
func (e *StreamEncrypter) Write(p []byte) (n int, err error) {
	if e.Error != nil {
		err = e.Error
		return
	}
	if len(p) == 0 {
		return
	}
	e.buffer = append(e.buffer, p...)
	return len(p), nil
}

// Close encrypts the buffered plaintext and writes the ciphertext to the
// underlying writer. If the writer implements io.Closer, it is closed.
func (e *StreamEncrypter) Close() error {
	if e.Error != nil {
		return e.Error
	}
	if len(e.buffer) == 0 {
		if closer, ok := e.writer.(io.Closer); ok {
			return closer.Close()
		}
		return nil
	}
	dst, encErr := e.encrypt(e.buffer)
	if encErr != nil {
		return encErr
	}
	if _, writeErr := e.writer.Write(dst); writeErr != nil {
		return writeErr
	}
	if closer, ok := e.writer.(io.Closer); ok {
		return closer.Close()
	}
	return nil
}
