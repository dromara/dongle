// Package sm4 implements SM4 encryption and decryption with streaming support.
// It provides SM4 encryption and decryption operations using the standard
// SM4 algorithm with support for various cipher modes.
package sm4

import (
	stdCipher "crypto/cipher"
	"github.com/dromara/dongle/crypto/internal/sm4"
	"io"

	"github.com/dromara/dongle/crypto/cipher"
)

// StdEncrypter represents an SM4 encrypter for standard encryption operations.
type StdEncrypter struct {
	cipher cipher.Sm4Cipher // The cipher interface for encryption operations
	block  stdCipher.Block  // Pre-created cipher block for reuse
	Error  error            // Error field for storing encryption errors
}

// NewStdEncrypter creates a new SM4 encrypter with the specified cipher and key.
func NewStdEncrypter(c *cipher.Sm4Cipher) *StdEncrypter {
	e := &StdEncrypter{
		cipher: *c,
	}
	if len(c.Key) != sm4.KeySize {
		e.Error = KeySizeError(len(c.Key))
		return e
	}
	e.block = sm4.NewCipher(c.Key)
	return e
}

// Encrypt encrypts the given byte slice using SM4 encryption.
func (e *StdEncrypter) Encrypt(src []byte) (dst []byte, err error) {
	// Check for existing errors from initialization
	if e.Error != nil {
		err = e.Error
		return
	}

	// Return empty data for empty input
	if len(src) == 0 {
		return
	}

	dst, err = e.cipher.Encrypt(src, e.block)
	if err != nil {
		err = EncryptError{Err: err}
	}
	return
}

// StdDecrypter represents an SM4 decrypter for standard decryption operations.
type StdDecrypter struct {
	cipher cipher.Sm4Cipher // The cipher interface for decryption operations
	block  stdCipher.Block  // Pre-created cipher block for reuse
	Error  error            // Error field for storing decryption errors
}

// NewStdDecrypter creates a new SM4 decrypter with the specified cipher and key.
func NewStdDecrypter(c *cipher.Sm4Cipher) *StdDecrypter {
	d := &StdDecrypter{
		cipher: *c,
	}
	if len(c.Key) != sm4.KeySize {
		d.Error = KeySizeError(len(c.Key))
		return d
	}
	d.block = sm4.NewCipher(c.Key)
	return d
}

// Decrypt decrypts the given byte slice using SM4 decryption.
func (d *StdDecrypter) Decrypt(src []byte) (dst []byte, err error) {
	// Check for existing errors from initialization
	if d.Error != nil {
		err = d.Error
		return
	}

	// Return empty data for empty input
	if len(src) == 0 {
		return
	}

	dst, err = d.cipher.Decrypt(src, d.block)
	if err != nil {
		err = DecryptError{Err: err}
	}
	return
}

// StreamEncrypter represents a streaming SM4 encrypter that implements io.WriteCloser.
type StreamEncrypter struct {
	writer io.Writer        // Underlying writer for encrypted output
	cipher cipher.Sm4Cipher // The cipher interface for encryption operations
	buffer []byte           // Buffer for accumulating incomplete blocks
	block  stdCipher.Block  // Reused cipher block for better performance
	Error  error            // Error field for storing encryption errors
}

// NewStreamEncrypter creates a new streaming SM4 encrypter that writes encrypted data
// to the provided io.Writer. The encrypter uses the specified cipher interface
// and validates the key length for proper SM4 encryption.
func NewStreamEncrypter(w io.Writer, c *cipher.Sm4Cipher) io.WriteCloser {
	e := &StreamEncrypter{
		writer: w,
		cipher: *c,
		buffer: make([]byte, 0, sm4.BlockSize), // SM4 block size is 16 bytes
	}
	if len(c.Key) != sm4.KeySize {
		e.Error = KeySizeError(len(c.Key))
		return e
	}
	e.block = sm4.NewCipher(c.Key)
	return e
}

// Write implements the io.Writer interface for streaming SM4 encryption.
func (e *StreamEncrypter) Write(src []byte) (n int, err error) {
	if e.Error != nil {
		return 0, e.Error
	}
	if len(src) == 0 {
		return 0, nil
	}

	// Combine any leftover bytes from previous write with new data
	data := append(e.buffer, src...)
	e.buffer = nil // Clear buffer after combining

	// Use the cipher interface to encrypt data (maintains compatibility with tests)
	encrypted, err := e.cipher.Encrypt(data, e.block)
	if err != nil {
		return 0, EncryptError{Err: err}
	}

	// Write encrypted data to the underlying writer
	if _, err = e.writer.Write(encrypted); err != nil {
		return 0, err
	}

	return len(src), nil
}

// Close implements the io.Closer interface for the streaming SM4 encrypter.
func (e *StreamEncrypter) Close() error {
	if e.Error != nil {
		return e.Error
	}
	// Close the underlying writer if it implements io.Closer
	if closer, ok := e.writer.(io.Closer); ok {
		err := closer.Close()
		if err != nil {
			err = EncryptError{Err: err}
		}
		return err
	}
	return nil
}

// StreamDecrypter represents a streaming SM4 decrypter that implements io.Reader.
type StreamDecrypter struct {
	reader   io.Reader         // Underlying reader for encrypted input
	cipher   *cipher.Sm4Cipher // The cipher interface for decryption operations
	buffer   []byte            // Buffer for decrypted data
	position int               // Current position in the buffer
	block    stdCipher.Block   // Reused cipher block for better performance
	Error    error             // Error field for storing decryption errors
}

// NewStreamDecrypter creates a new streaming SM4 decrypter that reads encrypted data
// from the provided io.Reader. The decrypter uses the specified cipher interface
// and validates the key length for proper SM4 decryption.
func NewStreamDecrypter(r io.Reader, c *cipher.Sm4Cipher) io.Reader {
	d := &StreamDecrypter{
		reader:   r,
		cipher:   c,
		buffer:   nil, // Will be populated on first read
		position: 0,
	}
	if len(c.Key) != sm4.KeySize {
		d.Error = KeySizeError(len(c.Key))
		return d
	}
	d.block = sm4.NewCipher(c.Key)
	return d
}

// Read implements the io.Reader interface for streaming SM4 decryption.
func (d *StreamDecrypter) Read(dst []byte) (n int, err error) {
	if d.Error != nil {
		return 0, d.Error
	}

	// If we haven't decrypted the data yet, do it now
	if d.buffer == nil {
		// Read all encrypted data from the underlying reader
		encryptedData, err := io.ReadAll(d.reader)
		if err != nil {
			d.Error = ReadError{Err: err}
			return 0, d.Error
		}

		// If no data to decrypt, return EOF
		if len(encryptedData) == 0 {
			return 0, io.EOF
		}

		// Use the cipher interface to decrypt data (maintains compatibility with tests)
		decrypted, err := d.cipher.Decrypt(encryptedData, d.block)
		if err != nil {
			d.Error = DecryptError{Err: err}
			return 0, d.Error
		}

		d.buffer = decrypted
		d.position = 0
	}

	// If we've already returned all decrypted data, return EOF
	if d.position >= len(d.buffer) {
		return 0, io.EOF
	}

	// Copy as much decrypted data as possible to the provided buffer
	remainingData := d.buffer[d.position:]
	copied := copy(dst, remainingData)
	d.position += copied

	return copied, nil
}
