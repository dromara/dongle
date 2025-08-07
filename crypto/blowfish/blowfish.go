// Package blowfish implements Blowfish encryption and decryption with streaming support
package blowfish

import (
	"io"

	"github.com/dromara/dongle/crypto/cipher"
	"golang.org/x/crypto/blowfish"
)

// StdEncrypter represents a Blowfish encrypter
type StdEncrypter struct {
	cipher cipher.CipherInterface
	key    []byte
	Error  error
}

// NewStdEncrypter returns a new Blowfish encrypter
func NewStdEncrypter(c cipher.CipherInterface, key []byte) *StdEncrypter {
	e := &StdEncrypter{
		cipher: c,
		key:    key,
	}
	if len(key) < 1 || len(key) > 56 {
		e.Error = KeySizeError(len(key))
	}
	return e
}

func (e *StdEncrypter) Encrypt(src []byte) (dst []byte, err error) {
	if e.Error != nil {
		err = e.Error
		return
	}

	if len(src) == 0 {
		return
	}

	// Create Blowfish cipher block
	block, err := blowfish.NewCipher(e.key)
	if err == nil {
		// Encrypt the data (including empty input, which will be padded by the cipher mode)
		dst, err = e.cipher.Encrypt(src, block)
		if err != nil {
			err = EncryptError{Err: err}
		}
	}
	return
}

// StdDecrypter represents a Blowfish decrypter
type StdDecrypter struct {
	cipher cipher.CipherInterface
	key    []byte
	Error  error
}

// NewStdDecrypter returns a new Blowfish decrypter
func NewStdDecrypter(c cipher.CipherInterface, key []byte) *StdDecrypter {
	d := &StdDecrypter{
		cipher: c,
		key:    key,
	}
	if len(key) < 1 || len(key) > 56 {
		d.Error = KeySizeError(len(key))
	}
	return d
}

func (d *StdDecrypter) Decrypt(src []byte) (dst []byte, err error) {
	if d.Error != nil {
		err = d.Error
		return
	}

	if len(src) == 0 {
		return
	}

	// Create Blowfish cipher block
	block, err := blowfish.NewCipher(d.key)
	if err == nil {
		// Decrypt the data (including empty input, which will be handled by the cipher mode)
		dst, err = d.cipher.Decrypt(src, block)
		if err != nil {
			err = DecryptError{Err: err}
		}
	}
	return
}

// StreamEncrypter implements io.WriteCloser interface for streaming Blowfish encryption
type StreamEncrypter struct {
	writer io.Writer
	cipher cipher.CipherInterface
	key    []byte
	Error  error
}

// NewStreamEncrypter returns a new Blowfish stream encrypter
func NewStreamEncrypter(w io.Writer, c cipher.CipherInterface, key []byte) io.WriteCloser {
	e := &StreamEncrypter{
		writer: w,
		cipher: c,
		key:    key,
	}
	if len(key) < 1 || len(key) > 56 {
		e.Error = KeySizeError(len(key))
		return e
	}
	return e
}

// Write implements io.Writer interface
func (e *StreamEncrypter) Write(p []byte) (n int, err error) {
	if e.Error != nil {
		err = e.Error
		return
	}

	if len(p) == 0 {
		return
	}

	// Create Blowfish cipher block
	block, err := blowfish.NewCipher(e.key)
	var encrypted []byte
	if err == nil {
		// Encrypt the data
		encrypted, err = e.cipher.Encrypt(p, block)
		if err != nil {
			err = EncryptError{Err: err}
			return
		}
	}
	// Write encrypted data
	return e.writer.Write(encrypted)
}

// Close implements io.Closer interface
func (e *StreamEncrypter) Close() error {
	if closer, ok := e.writer.(io.Closer); ok {
		return closer.Close()
	}
	return nil
}

// StreamDecrypter implements io.Reader interface for streaming Blowfish decryption
type StreamDecrypter struct {
	reader io.Reader
	cipher cipher.CipherInterface
	key    []byte
	Error  error
}

// NewStreamDecrypter returns a new Blowfish stream decrypter
func NewStreamDecrypter(r io.Reader, c cipher.CipherInterface, key []byte) io.Reader {
	d := &StreamDecrypter{
		reader: r,
		cipher: c,
		key:    key,
	}

	if len(key) < 1 || len(key) > 56 {
		d.Error = KeySizeError(len(key))
	}

	return d
}

// Read implements io.Reader interface
func (d *StreamDecrypter) Read(p []byte) (n int, err error) {
	if d.Error != nil {
		err = d.Error
		return
	}

	// Read encrypted data from the underlying reader
	// Note: This is a simplified implementation that reads all data at once
	// For true streaming, we would need to implement block-by-block reading
	encrypted, err := io.ReadAll(d.reader)
	if err != nil {
		err = ReadError{Err: err}
		return
	}

	if len(encrypted) == 0 {
		return 0, io.EOF
	}

	// Create Blowfish cipher block
	block, err := blowfish.NewCipher(d.key)
	if err == nil {
		var decrypted []byte
		// Decrypt the data
		decrypted, err = d.cipher.Decrypt(encrypted, block)
		if err != nil {
			err = DecryptError{Err: err}
			return
		}

		// Copy decrypted data to the provided buffer
		n = copy(p, decrypted)
		if n < len(decrypted) {
			// Buffer is too small, we can't return all data
			err = BufferError{bufferSize: len(p), dataSize: len(decrypted)}
			return
		}
	}

	return
}
