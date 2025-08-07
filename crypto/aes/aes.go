// Package aes implements AES encryption and decryption with streaming support.
// It provides AES encryption and decryption operations using the standard
// AES algorithm with support for 128-bit, 192-bit, and 256-bit keys.
package aes

import (
	"crypto/aes"
	"io"

	"github.com/dromara/dongle/crypto/cipher"
)

// StdEncrypter represents an AES encrypter for standard encryption operations.
// It implements AES encryption using the standard AES algorithm with support
// for different key sizes and various cipher modes.
type StdEncrypter struct {
	cipher cipher.CipherInterface // The cipher interface for encryption operations
	key    []byte                 // The encryption key
	Error  error                  // Error field for storing encryption errors
}

// NewStdEncrypter creates a new AES encrypter with the specified cipher and key.
// Validates the key length and initializes the encrypter for AES encryption operations.
// The key must be 16, 24, or 32 bytes for AES-128, AES-192, or AES-256 respectively.
func NewStdEncrypter(c cipher.CipherInterface, key []byte) *StdEncrypter {
	e := &StdEncrypter{
		cipher: c,
		key:    key,
	}

	if len(key) != 16 && len(key) != 24 && len(key) != 32 {
		e.Error = KeySizeError(len(key))
	}

	return e
}

// Encrypt encrypts the given byte slice using AES encryption.
// Creates an AES cipher block and uses the configured cipher interface
// to perform the encryption operation with proper error handling.
func (e *StdEncrypter) Encrypt(src []byte) (dst []byte, err error) {
	// Check for existing errors from initialization
	if e.Error != nil {
		err = e.Error
		return
	}

	if len(src) == 0 {
		return
	}

	// Create AES cipher block using the provided key
	block, err := aes.NewCipher(e.key)
	if err == nil {
		// Use the configured cipher interface to perform the actual encryption
		// The cipher interface handles the specific encryption mode (CBC, CTR, ECB, etc.)
		dst, err = e.cipher.Encrypt(src, block)
		if err != nil {
			err = EncryptError{Err: err}
		}
	}
	return
}

// StdDecrypter represents an AES decrypter for standard decryption operations.
// It implements AES decryption using the standard AES algorithm with support
// for different key sizes and various cipher modes.
type StdDecrypter struct {
	cipher cipher.CipherInterface // The cipher interface for decryption operations
	key    []byte                 // The decryption key
	Error  error                  // Error field for storing decryption errors
}

// NewStdDecrypter creates a new AES decrypter with the specified cipher and key.
// Validates the key length and initializes the decrypter for AES decryption operations.
// The key must be 16, 24, or 32 bytes for AES-128, AES-192, or AES-256 respectively.
func NewStdDecrypter(c cipher.CipherInterface, key []byte) *StdDecrypter {
	d := &StdDecrypter{
		cipher: c,
		key:    key,
	}

	if len(key) != 16 && len(key) != 24 && len(key) != 32 {
		d.Error = KeySizeError(len(key))
	}
	return d
}

// Decrypt decrypts the given byte slice using AES decryption.
// Creates an AES cipher block and uses the configured cipher interface
// to perform the decryption operation with proper error handling.
func (d *StdDecrypter) Decrypt(src []byte) (dst []byte, err error) {
	// Check for existing errors from initialization
	if d.Error != nil {
		err = d.Error
		return
	}

	if len(src) == 0 {
		return
	}

	// Create AES cipher block using the provided key
	block, err := aes.NewCipher(d.key)
	if err == nil {
		// Use the configured cipher interface to perform the actual decryption
		// The cipher interface handles the specific decryption mode (CBC, CTR, ECB, etc.)
		dst, err = d.cipher.Decrypt(src, block)
		if err != nil {
			err = DecryptError{Err: err}
		}
	}
	return
}

// StreamEncrypter represents a streaming AES encrypter that implements io.WriteCloser.
// It provides efficient encryption for large data streams by processing data
// in chunks and writing encrypted output to the underlying writer.
type StreamEncrypter struct {
	writer io.Writer              // Underlying writer for encrypted output
	cipher cipher.CipherInterface // The cipher interface for encryption operations
	key    []byte                 // The encryption key
	Error  error                  // Error field for storing encryption errors
}

// NewStreamEncrypter creates a new streaming AES encrypter that writes encrypted data
// to the provided io.Writer. The encrypter uses the specified cipher interface
// and validates the key length for proper AES encryption.
func NewStreamEncrypter(w io.Writer, c cipher.CipherInterface, key []byte) io.WriteCloser {
	e := &StreamEncrypter{
		writer: w,
		cipher: c,
		key:    key,
	}

	if len(key) != 16 && len(key) != 24 && len(key) != 32 {
		e.Error = KeySizeError(len(key))
		return e
	}

	return e
}

// Write implements the io.Writer interface for streaming AES encryption.
// Encrypts the provided data and writes it to the underlying writer.
// Returns the number of bytes written and any error that occurred.
func (e *StreamEncrypter) Write(p []byte) (n int, err error) {
	// Check for existing errors from initialization
	if e.Error != nil {
		err = e.Error
		return
	}

	if len(p) == 0 {
		return
	}

	// Create AES cipher block using the provided key
	block, err := aes.NewCipher(e.key)
	var encrypted []byte
	if err == nil {
		// Encrypt the data using the configured cipher interface
		encrypted, err = e.cipher.Encrypt(p, block)
		if err != nil {
			err = EncryptError{Err: err}
			return
		}
	}

	// Write encrypted data to the underlying writer
	_, writeErr := e.writer.Write(encrypted)
	if writeErr != nil {
		return 0, writeErr
	}
	// Return the number of input bytes processed, not output bytes written
	return len(p), nil
}

// Close implements the io.Closer interface for the streaming AES encrypter.
// Closes the underlying writer if it implements io.Closer.
func (e *StreamEncrypter) Close() error {
	if closer, ok := e.writer.(io.Closer); ok {
		return closer.Close()
	}
	return nil
}

// StreamDecrypter represents a streaming AES decrypter that implements io.Reader.
// It provides efficient decryption for large data streams by processing data
// in chunks and reading decrypted output from the underlying reader.
type StreamDecrypter struct {
	reader io.Reader              // Underlying reader for encrypted input
	cipher cipher.CipherInterface // The cipher interface for decryption operations
	key    []byte                 // The decryption key
	Error  error                  // Error field for storing decryption errors
}

// NewStreamDecrypter creates a new streaming AES decrypter that reads encrypted data
// from the provided io.Reader. The decrypter uses the specified cipher interface
// and validates the key length for proper AES decryption.
func NewStreamDecrypter(r io.Reader, c cipher.CipherInterface, key []byte) io.Reader {
	d := &StreamDecrypter{
		reader: r,
		cipher: c,
		key:    key,
	}

	if len(key) != 16 && len(key) != 24 && len(key) != 32 {
		d.Error = KeySizeError(len(key))
		return d
	}

	return d
}

// Read implements the io.Reader interface for streaming AES decryption.
// Reads encrypted data from the underlying reader, decrypts it, and fills the provided buffer.
// Returns the number of bytes read and any error that occurred.
func (d *StreamDecrypter) Read(p []byte) (n int, err error) {
	// Check for existing errors from initialization
	if d.Error != nil {
		err = d.Error
		return
	}

	// Read encrypted data from the underlying reader
	// For true streaming, we would need to implement block-by-block reading
	encrypted, err := io.ReadAll(d.reader)
	if err != nil {
		err = ReadError{Err: err}
		return
	}

	if len(encrypted) == 0 {
		return 0, io.EOF
	}

	// Create AES cipher block using the provided key
	block, err := aes.NewCipher(d.key)
	if err == nil {
		var decrypted []byte
		// Decrypt the data using the configured cipher interface
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
