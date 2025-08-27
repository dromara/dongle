// Package triple_des implements Triple DES encryption and decryption with streaming support.
// It provides Triple DES encryption and decryption operations using the standard
// Triple DES algorithm with support for 16-byte and 24-byte keys.
package triple_des

import (
	"crypto/des"
	"io"

	"github.com/dromara/dongle/crypto/cipher"
)

// StdEncrypter represents a Triple DES encrypter for standard encryption operations.
// It implements Triple DES encryption using the standard Triple DES algorithm with support
// for 16-byte and 24-byte keys and various cipher modes.
type StdEncrypter struct {
	cipher *cipher.TripleDesCipher // The cipher interface for encryption operations
	Error  error                   // Error field for storing encryption errors
}

// NewStdEncrypter creates a new Triple DES encrypter with the specified cipher and key.
// Validates the key length and initializes the encrypter for Triple DES encryption operations.
// The key must be 16 or 24 bytes for Triple DES encryption.
func NewStdEncrypter(c *cipher.TripleDesCipher) *StdEncrypter {
	e := &StdEncrypter{
		cipher: c,
	}

	if len(c.Key) != 16 && len(c.Key) != 24 {
		e.Error = KeySizeError(len(c.Key))
	}

	return e
}

// Encrypt encrypts the given byte slice using Triple DES encryption.
// Creates a Triple DES cipher block and uses the configured cipher interface
// to perform the encryption operation with proper error handling.
func (e *StdEncrypter) Encrypt(src []byte) (dst []byte, err error) {
	// Check for existing errors from initialization
	if e.Error != nil {
		return nil, e.Error
	}

	// Create Triple DES cipher block using the provided key
	block, err := des.NewTripleDESCipher(e.cipher.Key)
	if err != nil {
		return nil, EncryptError{Err: err}
	}
	return e.cipher.Encrypt(src, block)
}

// StdDecrypter represents a Triple DES decrypter for standard decryption operations.
// It implements Triple DES decryption using the standard Triple DES algorithm with support
// for 16-byte and 24-byte keys and various cipher modes.
type StdDecrypter struct {
	cipher *cipher.TripleDesCipher // The cipher interface for decryption operations
	Error  error                   // Error field for storing decryption errors
}

// NewStdDecrypter creates a new Triple DES decrypter with the specified cipher and key.
// Validates the key length and initializes the decrypter for Triple DES decryption operations.
// The key must be 16 or 24 bytes for Triple DES decryption.
func NewStdDecrypter(c *cipher.TripleDesCipher) *StdDecrypter {
	d := &StdDecrypter{
		cipher: c,
	}

	if len(c.Key) != 16 && len(c.Key) != 24 {
		d.Error = KeySizeError(len(c.Key))
	}
	return d
}

// Decrypt decrypts the given byte slice using Triple DES decryption.
// Creates a Triple DES cipher block and uses the configured cipher interface
// to perform the decryption operation with proper error handling.
func (d *StdDecrypter) Decrypt(src []byte) (dst []byte, err error) {
	// Check for existing errors from initialization
	if d.Error != nil {
		return nil, d.Error
	}

	block, err := des.NewTripleDESCipher(d.cipher.Key)
	if err != nil {
		return nil, DecryptError{Err: err}
	}
	return d.cipher.Decrypt(src, block)
}

// StreamEncrypter represents a streaming Triple DES encrypter that implements io.WriteCloser.
// It provides efficient encryption for large data streams by processing data
// in chunks and writing encrypted output to the underlying writer.
type StreamEncrypter struct {
	writer io.Writer               // Underlying writer for encrypted output
	cipher *cipher.TripleDesCipher // The cipher interface for encryption operations
	Error  error                   // Error field for storing encryption errors
}

// NewStreamEncrypter creates a new streaming Triple DES encrypter that writes encrypted data
// to the provided io.Writer. The encrypter uses the specified cipher interface
// and validates the key length for proper Triple DES encryption.
func NewStreamEncrypter(w io.Writer, c *cipher.TripleDesCipher) io.WriteCloser {
	e := &StreamEncrypter{
		writer: w,
		cipher: c,
	}

	if len(c.Key) != 16 && len(c.Key) != 24 {
		e.Error = KeySizeError(len(c.Key))
		return e
	}

	return e
}

// Write implements the io.Writer interface for streaming Triple DES encryption.
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

	// Create Triple DES cipher block using the provided key
	block, err := des.NewTripleDESCipher(e.cipher.Key)
	if err != nil {
		return 0, EncryptError{Err: err}
	}

	// Use encrypt helper function to handle padding and encryption
	encrypted, err := e.cipher.Encrypt(p, block)
	if err == nil {
		// Write encrypted data to the underlying writer
		return e.writer.Write(encrypted)
	}
	return
}

// Close implements the io.Closer interface for the streaming Triple DES encrypter.
// Closes the underlying writer if it implements io.Closer.
func (e *StreamEncrypter) Close() error {
	if closer, ok := e.writer.(io.Closer); ok {
		return closer.Close()
	}
	return nil
}

// StreamDecrypter represents a streaming Triple DES decrypter that implements io.Reader.
// It provides efficient decryption for large data streams by processing data
// in chunks and reading decrypted output from the underlying reader.
type StreamDecrypter struct {
	reader io.Reader               // Underlying reader for encrypted input
	cipher *cipher.TripleDesCipher // The cipher interface for decryption operations
	Error  error                   // Error field for storing decryption errors
}

// NewStreamDecrypter creates a new streaming Triple DES decrypter that reads encrypted data
// from the provided io.Reader. The decrypter uses the specified cipher interface
// and validates the key length for proper Triple DES decryption.
func NewStreamDecrypter(r io.Reader, c *cipher.TripleDesCipher) io.Reader {
	d := &StreamDecrypter{
		reader: r,
		cipher: c,
	}

	if len(d.cipher.Key) != 16 && len(d.cipher.Key) != 24 {
		d.Error = KeySizeError(len(d.cipher.Key))
		return d
	}

	return d
}

// Read implements the io.Reader interface for streaming Triple DES decryption.
// Reads encrypted data from the underlying reader, decrypts it, and fills the provided buffer.
// Returns the number of bytes read and any error that occurred.
func (d *StreamDecrypter) Read(p []byte) (n int, err error) {
	// Check for existing errors from initialization
	if d.Error != nil {
		return 0, d.Error
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

	// Create Triple DES cipher block using the provided key
	block, err := des.NewTripleDESCipher(d.cipher.Key)
	if err != nil {
		return 0, DecryptError{Err: err}
	}

	decrypted, err := d.cipher.Decrypt(encrypted, block)
	if err != nil {
		return 0, err
	}

	// Copy decrypted data to the provided buffer
	n = copy(p, decrypted)
	if n < len(decrypted) {
		// Buffer is too small, we can't return all data
		err = BufferError{bufferSize: len(p), dataSize: len(decrypted)}
		return
	}
	return
}
