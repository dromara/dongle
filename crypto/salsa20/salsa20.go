// Package salsa20 implements Salsa20 encryption and decryption with streaming support.
// It provides Salsa20 encryption and decryption operations using the standard
// Salsa20 algorithm with support for 32-byte keys and 8-byte nonces.
package salsa20

import (
	"io"

	"github.com/dromara/dongle/crypto/cipher"
	"golang.org/x/crypto/salsa20"
)

// StdEncrypter represents a Salsa20 encrypter for standard encryption operations.
// It implements Salsa20 encryption using the standard Salsa20 algorithm with support
// for 32-byte keys and 8-byte nonces.
type StdEncrypter struct {
	cipher *cipher.Salsa20Cipher // The cipher interface for encryption operations
	Error  error                 // Error field for storing encryption errors
}

// NewStdEncrypter creates a new Salsa20 encrypter with the specified cipher and key.
// Validates the key length and nonce length, then initializes the encrypter for Salsa20 encryption operations.
// The key must be exactly 32 bytes and nonce must be exactly 8 bytes.
func NewStdEncrypter(c *cipher.Salsa20Cipher) *StdEncrypter {
	e := &StdEncrypter{
		cipher: c,
	}

	if len(c.Key) != 32 {
		e.Error = KeySizeError(len(c.Key))
		return e
	}

	if len(c.Nonce) != 8 {
		e.Error = NonceSizeError(len(c.Nonce))
		return e
	}

	return e
}

// Encrypt encrypts the given byte slice using Salsa20 encryption.
// Salsa20 is a stream cipher, so it can encrypt data of any length.
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

	// Create a copy of the key for salsa20.XORKeyStream
	var key [32]byte
	copy(key[:], e.cipher.Key)

	// Encrypt the data
	dst = make([]byte, len(src))
	salsa20.XORKeyStream(dst, src, e.cipher.Nonce, &key)

	return dst, nil
}

// StdDecrypter represents a Salsa20 decrypter for standard decryption operations.
// It implements Salsa20 decryption using the standard Salsa20 algorithm with support
// for 32-byte keys and 8-byte nonces.
type StdDecrypter struct {
	cipher *cipher.Salsa20Cipher // The cipher interface for decryption operations
	Error  error                 // Error field for storing decryption errors
}

// NewStdDecrypter creates a new Salsa20 decrypter with the specified cipher and key.
// Validates the key length and nonce length, then initializes the decrypter for Salsa20 decryption operations.
// The key must be exactly 32 bytes and nonce must be exactly 8 bytes.
func NewStdDecrypter(c *cipher.Salsa20Cipher) *StdDecrypter {
	d := &StdDecrypter{
		cipher: c,
	}

	if len(c.Key) != 32 {
		d.Error = KeySizeError(len(c.Key))
		return d
	}

	if len(c.Nonce) != 8 {
		d.Error = NonceSizeError(len(c.Nonce))
		return d
	}

	return d
}

// Decrypt decrypts the given byte slice using Salsa20 decryption.
// For Salsa20, decryption is the same as encryption.
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

	// Create a copy of the key for salsa20.XORKeyStream
	var key [32]byte
	copy(key[:], d.cipher.Key)

	// Decrypt the data (same as encryption for Salsa20)
	dst = make([]byte, len(src))
	salsa20.XORKeyStream(dst, src, d.cipher.Nonce, &key)

	return dst, nil
}

// StreamEncrypter represents a streaming Salsa20 encrypter that implements io.WriteCloser.
// It provides efficient encryption for large data streams by processing data
// in chunks and writing encrypted output to the underlying writer.
type StreamEncrypter struct {
	writer io.Writer             // Underlying writer for encrypted output
	cipher *cipher.Salsa20Cipher // The cipher interface for encryption operations
	Error  error                 // Error field for storing encryption errors
}

// NewStreamEncrypter creates a new streaming Salsa20 encrypter that writes encrypted data
// to the provided io.Writer. The encrypter uses the specified cipher interface
// and validates the key length and nonce length for proper Salsa20 encryption.
func NewStreamEncrypter(w io.Writer, c *cipher.Salsa20Cipher) io.WriteCloser {
	e := &StreamEncrypter{
		writer: w,
		cipher: c,
	}

	if len(c.Key) != 32 {
		e.Error = KeySizeError(len(c.Key))
		return e
	}

	if len(c.Nonce) != 8 {
		e.Error = NonceSizeError(len(c.Nonce))
		return e
	}

	return e
}

// Write implements io.Writer interface for streaming Salsa20 encryption.
// Salsa20 is a stream cipher, so it can encrypt data of any length.
func (e *StreamEncrypter) Write(p []byte) (n int, err error) {
	if e.Error != nil {
		return 0, e.Error
	}

	if len(p) == 0 {
		return 0, nil
	}

	// Create a copy of the key for salsa20.XORKeyStream
	var key [32]byte
	copy(key[:], e.cipher.Key)

	// Encrypt the data
	encrypted := make([]byte, len(p))
	salsa20.XORKeyStream(encrypted, p, e.cipher.Nonce, &key)

	// Write encrypted data to the underlying writer
	if _, err = e.writer.Write(encrypted); err != nil {
		return 0, WriteError{Err: err}
	}

	return len(p), nil
}

// Close implements io.Closer interface for streaming Salsa20 encryption.
// Closes the underlying writer if it implements io.Closer.
func (e *StreamEncrypter) Close() error {
	if e.Error != nil {
		return e.Error
	}

	// Close the underlying writer if it implements io.Closer
	if closer, ok := e.writer.(io.Closer); ok {
		return closer.Close()
	}
	return nil
}

// StreamDecrypter represents a streaming Salsa20 decrypter that implements io.Reader.
// It provides efficient decryption for large data streams by reading encrypted data
// from the underlying reader and decrypting it in chunks.
type StreamDecrypter struct {
	reader   io.Reader             // Underlying reader for encrypted input
	cipher   *cipher.Salsa20Cipher // The cipher interface for decryption operations
	buffer   []byte                // Buffer for decrypted data
	position int                   // Current position in the buffer
	Error    error                 // Error field for storing decryption errors
}

// NewStreamDecrypter creates a new streaming Salsa20 decrypter that reads encrypted data
// from the provided io.Reader. The decrypter uses the specified cipher interface
// and validates the key length and nonce length for proper Salsa20 decryption.
func NewStreamDecrypter(r io.Reader, c *cipher.Salsa20Cipher) io.Reader {
	d := &StreamDecrypter{
		reader:   r,
		cipher:   c,
		buffer:   nil, // Will be populated on first read
		position: 0,
	}

	if len(c.Key) != 32 {
		d.Error = KeySizeError(len(c.Key))
		return d
	}

	if len(c.Nonce) != 8 {
		d.Error = NonceSizeError(len(c.Nonce))
		return d
	}

	return d
}

// Read implements io.Reader interface for streaming Salsa20 decryption.
// On the first call, reads all encrypted data from the underlying reader and decrypts it.
// Subsequent calls return chunks of the decrypted data to maintain streaming interface.
func (d *StreamDecrypter) Read(p []byte) (n int, err error) {
	if d.Error != nil {
		return 0, d.Error
	}

	// If we haven't decrypted the data yet, do it now
	if d.buffer == nil {
		// Read all encrypted data from the underlying reader
		encryptedData, err := io.ReadAll(d.reader)
		if err != nil {
			return 0, ReadError{Err: err}
		}

		// If no data to decrypt, return EOF
		if len(encryptedData) == 0 {
			return 0, io.EOF
		}

		// Create a copy of the key for salsa20.XORKeyStream
		var key [32]byte
		copy(key[:], d.cipher.Key)

		// Decrypt all the data at once
		decrypted := make([]byte, len(encryptedData))
		salsa20.XORKeyStream(decrypted, encryptedData, d.cipher.Nonce, &key)

		d.buffer = decrypted
		d.position = 0
	}

	// If we've already returned all decrypted data, return EOF
	if d.position >= len(d.buffer) {
		return 0, io.EOF
	}

	// Copy as much decrypted data as possible to the provided buffer
	remainingData := d.buffer[d.position:]
	copied := copy(p, remainingData)
	d.position += copied

	return copied, nil
}
