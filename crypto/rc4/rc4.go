// Package rc4 implements RC4 encryption and decryption with streaming support
package rc4

import (
	stdCipher "crypto/cipher"
	"crypto/rc4"
	"fmt"
	"io"
)

// StdEncrypter represents an RC4 encrypter
type StdEncrypter struct {
	key    []byte
	cipher stdCipher.Stream // Pre-created cipher for reuse
	Error  error
}

// NewStdEncrypter returns a new RC4 encrypter
func NewStdEncrypter(key []byte) *StdEncrypter {
	e := &StdEncrypter{key: key}
	if len(key) == 0 || len(key) > 256 {
		e.Error = KeySizeError(len(key))
		return e
	}
	cipher, err := rc4.NewCipher(key)
	if err == nil {
		e.cipher = cipher
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
	// Use pre-created cipher for better performance
	if e.cipher == nil {
		// Fallback: create cipher if not available
		cipher, err := rc4.NewCipher(e.key)
		if err == nil {
			e.cipher = cipher
		}
	}
	dst = make([]byte, len(src))
	e.cipher.XORKeyStream(dst, src)
	return
}

// StdDecrypter represents an RC4 decrypter
type StdDecrypter struct {
	key    []byte
	cipher stdCipher.Stream // Pre-created cipher for reuse
	Error  error
}

// NewStdDecrypter returns a new RC4 decrypter
func NewStdDecrypter(key []byte) *StdDecrypter {
	d := &StdDecrypter{key: key}
	if len(key) == 0 || len(key) > 256 {
		d.Error = KeySizeError(len(key))
		return d
	}
	// Pre-create cipher for better performance
	cipher, err := rc4.NewCipher(key)
	if err == nil {
		d.cipher = cipher
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
	// Use pre-created cipher for better performance
	if d.cipher == nil {
		// Fallback: create cipher if not available
		cipher, err := rc4.NewCipher(d.key)
		if err == nil {
			d.cipher = cipher
		}
	}
	dst = make([]byte, len(src))
	d.cipher.XORKeyStream(dst, src)
	return
}

// StreamEncrypter implements io.WriteCloser interface for streaming RC4 encryption
type StreamEncrypter struct {
	writer io.Writer
	cipher stdCipher.Stream // Reused cipher stream for better performance
	Error  error
}

// NewStreamEncrypter returns a new RC4 stream encrypter
func NewStreamEncrypter(w io.Writer, key []byte) io.WriteCloser {
	e := &StreamEncrypter{writer: w}
	if len(key) == 0 || len(key) > 256 {
		e.Error = KeySizeError(len(key))
		return e
	}
	// Pre-create cipher for reuse
	cipher, err := rc4.NewCipher(key)
	if err == nil {
		e.cipher = cipher
	}
	return e
}

// Write implements io.Writer interface
func (e *StreamEncrypter) Write(p []byte) (n int, err error) {
	if e.Error != nil {
		return 0, e.Error
	}
	if e.cipher == nil {
		return 0, WriteError{Err: fmt.Errorf("cipher not initialized")}
	}

	// For stream cipher, we can encrypt in-place but we need a copy for output
	encrypted := make([]byte, len(p))
	e.cipher.XORKeyStream(encrypted, p)
	n, writeErr := e.writer.Write(encrypted)
	if writeErr != nil {
		return n, WriteError{Err: writeErr}
	}
	return n, nil
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
	cipher stdCipher.Stream // Reused cipher stream for better performance
	Error  error
}

// NewStreamDecrypter returns a new RC4 stream decrypter
func NewStreamDecrypter(r io.Reader, key []byte) io.Reader {
	d := &StreamDecrypter{reader: r}
	if len(key) == 0 || len(key) > 256 {
		d.Error = KeySizeError(len(key))
		return d
	}
	// Pre-create cipher for reuse
	cipher, err := rc4.NewCipher(key)
	if err == nil {
		d.cipher = cipher
	}
	return d
}

// Read implements io.Reader interface
func (d *StreamDecrypter) Read(p []byte) (n int, err error) {
	if d.Error != nil {
		return 0, d.Error
	}
	n, readErr := d.reader.Read(p)
	if readErr != nil {
		return n, ReadError{Err: readErr}
	}
	if n > 0 {
		// RC4 is a stream cipher, we can decrypt in-place
		// This avoids creating a temporary buffer, improving performance
		d.cipher.XORKeyStream(p[:n], p[:n])
	}
	return n, nil
}
