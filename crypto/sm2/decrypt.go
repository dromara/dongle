package sm2

import (
	"io"

	"github.com/dromara/dongle/crypto/internal/sm2"
	"github.com/dromara/dongle/crypto/keypair"
)

// StdDecrypter decrypts data using an SM2 private key.
type StdDecrypter struct {
	keypair keypair.Sm2KeyPair
	cache   cache
	Error   error
}

// NewStdDecrypter creates a new SM2 decrypter bound to the given key pair.
func NewStdDecrypter(kp *keypair.Sm2KeyPair) *StdDecrypter {
	d := &StdDecrypter{keypair: *kp}
	if len(kp.PrivateKey) == 0 {
		d.Error = DecryptError{Err: keypair.EmptyPrivateKeyError{}}
		return d
	}
	priKey, err := kp.ParsePrivateKey()
	if err != nil {
		d.Error = DecryptError{Err: err}
		return d
	}
	d.cache.priKey = priKey
	return d
}

// Decrypt decrypts data with SM2 private key.
func (d *StdDecrypter) Decrypt(src []byte) (dst []byte, err error) {
	if d.Error != nil {
		err = d.Error
		return
	}
	if len(src) == 0 {
		return
	}
	dst, err = sm2.DecryptWithPrivateKey(d.cache.priKey, src, d.keypair.Window, string(d.keypair.Order))
	if err != nil {
		err = DecryptError{Err: err}
		return
	}
	return
}

// StreamDecrypter reads all ciphertext from an io.Reader and exposes the
// decrypted plaintext via Read.
type StreamDecrypter struct {
	reader   io.Reader
	keypair  keypair.Sm2KeyPair
	cache    cache
	buffer   []byte
	position int
	Error    error
}

// NewStreamDecrypter creates a Reader that decrypts the entire input from r
// using the provided key pair, serving plaintext on subsequent Read calls.
func NewStreamDecrypter(r io.Reader, kp *keypair.Sm2KeyPair) io.Reader {
	d := &StreamDecrypter{
		reader:   r,
		keypair:  *kp,
		position: 0,
	}
	if len(kp.PrivateKey) == 0 {
		d.Error = DecryptError{Err: keypair.EmptyPrivateKeyError{}}
		return d
	}
	priKey, err := kp.ParsePrivateKey()
	if err != nil {
		d.Error = DecryptError{Err: err}
		return d
	}
	d.cache.priKey = priKey
	return d
}

// decrypt decrypts ciphertext with SM2 private key.
func (d *StreamDecrypter) decrypt(src []byte) (dst []byte, err error) {
	if d.Error != nil {
		err = d.Error
		return
	}
	if len(src) == 0 {
		return
	}
	dst, err = sm2.DecryptWithPrivateKey(d.cache.priKey, src, d.keypair.Window, string(d.keypair.Order))
	if err != nil {
		err = DecryptError{Err: err}
		return
	}
	return
}

// Read serves decrypted plaintext from the internal buffer.
func (d *StreamDecrypter) Read(p []byte) (n int, err error) {
	if d.Error != nil {
		err = d.Error
		return
	}
	// Serve from buffer if available
	if d.position < len(d.buffer) {
		n = copy(p, d.buffer[d.position:])
		d.position += n
		if d.position >= len(d.buffer) {
			return n, io.EOF
		}
		return
	}
	// Otherwise, read all ciphertext and decrypt once
	enc, err := io.ReadAll(d.reader)
	if err != nil {
		err = ReadError{Err: err}
		return
	}
	if len(enc) == 0 {
		err = io.EOF
		return
	}
	out, err := d.decrypt(enc)
	if err != nil {
		return
	}
	d.buffer = out
	d.position = 0
	// Return plaintext
	n = copy(p, d.buffer)
	d.position += n
	if d.position >= len(d.buffer) {
		return n, io.EOF
	}
	return
}
