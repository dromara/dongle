// Package rc4 implements RC4 encryption and decryption with streaming support
package rc4

import (
	"crypto/rc4"
	"io"
)

// StdEncrypter represents an RC4 encrypter
type StdEncrypter struct {
	key   []byte
	Error error
}

// NewStdEncrypter returns a new RC4 encrypter
func NewStdEncrypter(key []byte) *StdEncrypter {
	e := &StdEncrypter{key: key}
	if len(key) == 0 || len(key) > 256 {
		e.Error = KeySizeError(len(key))
	}
	return e
}

// Encrypt encrypts src using RC4
func (e *StdEncrypter) Encrypt(src []byte) (dst []byte, err error) {
	if e.Error != nil {
		err = e.Error
		return
	}
	if len(src) == 0 {
		return
	}
	cipher, err := rc4.NewCipher(e.key)
	if err == nil {
		dst = make([]byte, len(src))
		cipher.XORKeyStream(dst, src)
	}
	return
}

// StdDecrypter represents an RC4 decrypter
type StdDecrypter struct {
	key   []byte
	Error error
}

// NewStdDecrypter returns a new RC4 decrypter
func NewStdDecrypter(key []byte) *StdDecrypter {
	d := &StdDecrypter{key: key}
	if len(key) == 0 || len(key) > 256 {
		d.Error = KeySizeError(len(key))
	}
	return d
}

// Decrypt decrypts src using RC4
func (d *StdDecrypter) Decrypt(src []byte) (dst []byte, err error) {
	if d.Error != nil {
		err = d.Error
		return
	}

	if len(src) == 0 {
		return
	}
	cipher, err := rc4.NewCipher(d.key)
	if err == nil {
		dst = make([]byte, len(src))
		cipher.XORKeyStream(dst, src)
	}
	return
}

// StreamEncrypter implements io.WriteCloser interface for streaming RC4 encryption
type StreamEncrypter struct {
	writer io.Writer
	cipher *rc4.Cipher
	Error  error
}

// NewStreamEncrypter returns a new RC4 stream encrypter
func NewStreamEncrypter(w io.Writer, key []byte) io.WriteCloser {
	e := &StreamEncrypter{writer: w}
	if len(key) == 0 || len(key) > 256 {
		e.Error = KeySizeError(len(key))
		return e
	}
	e.cipher, e.Error = rc4.NewCipher(key)
	return e
}

// Write implements io.Writer interface
func (e *StreamEncrypter) Write(p []byte) (n int, err error) {
	if e.Error != nil {
		err = e.Error
		return
	}
	if e.cipher == nil {
		return
	}

	encrypted := make([]byte, len(p))
	e.cipher.XORKeyStream(encrypted, p)
	n, writeErr := e.writer.Write(encrypted)
	if writeErr != nil {
		err = WriteError{Err: writeErr}
	}
	return n, err
}

// Close implements io.Closer interface
func (e *StreamEncrypter) Close() error {
	if closer, ok := e.writer.(io.Closer); ok {
		return closer.Close()
	}
	return nil
}

// StreamDecrypter implements io.Reader interface for streaming RC4 decryption
type StreamDecrypter struct {
	reader io.Reader
	cipher *rc4.Cipher
	Error  error
}

// NewStreamDecrypter returns a new RC4 stream decrypter
func NewStreamDecrypter(r io.Reader, key []byte) io.Reader {
	d := &StreamDecrypter{reader: r}
	if len(key) == 0 || len(key) > 256 {
		d.Error = KeySizeError(len(key))
		return d
	}
	d.cipher, d.Error = rc4.NewCipher(key)
	return d
}

// Read implements io.Reader interface
func (d *StreamDecrypter) Read(p []byte) (n int, err error) {
	if d.Error != nil {
		err = d.Error
		return
	}
	n, readErr := d.reader.Read(p)
	if readErr != nil {
		err = ReadError{Err: readErr}
		return n, err
	}
	if n > 0 {
		decrypted := make([]byte, n)
		d.cipher.XORKeyStream(decrypted, p[:n])
		copy(p, decrypted)
	}
	return n, err
}
