// Package des implements DES encryption and decryption with streaming support.
// It provides DES encryption and decryption operations using the standard
// DES algorithm with support for 64-bit keys.
package des

import (
	"crypto/des"
	"io"

	"github.com/dromara/dongle/crypto/cipher"
)

// StdEncrypter represents a DES encrypter for standard encryption operations.
// It implements DES encryption using the standard DES algorithm with support
// for 64-bit keys and various cipher modes.
type StdEncrypter struct {
	cipher cipher.CipherInterface // The cipher interface for encryption operations
	key    []byte                 // The encryption key
	Error  error                  // Error field for storing encryption errors
}

// NewStdEncrypter creates a new DES encrypter with the specified cipher and key.
// Validates the key length and initializes the encrypter for DES encryption operations.
// The key must be exactly 8 bytes for DES encryption.
func NewStdEncrypter(c cipher.CipherInterface, key []byte) *StdEncrypter {
	e := &StdEncrypter{
		cipher: c,
		key:    key,
	}

	if len(key) != 8 {
		e.Error = KeySizeError(len(key))
	}

	return e
}

// Encrypt encrypts the given byte slice using DES encryption.
// Creates a DES cipher block and uses the configured cipher interface
// to perform the encryption operation with proper error handling.
func (e *StdEncrypter) Encrypt(src []byte) (dst []byte, err error) {
	if e.Error != nil {
		err = e.Error
		return
	}
	if len(src) == 0 {
		return
	}

	// Create DES cipher block using the provided key
	block, err := des.NewCipher(e.key)
	if err == nil {
		// Use the configured cipher interface to perform the actual encryption
		dst, err = e.cipher.Encrypt(src, block)
		if err != nil {
			err = EncryptError{Err: err}
		}
	}
	return
}

// StdDecrypter represents a DES decrypter for standard decryption operations.
// It implements DES decryption using the standard DES algorithm with support
// for 64-bit keys and various cipher modes.
type StdDecrypter struct {
	cipher cipher.CipherInterface // The cipher interface for decryption operations
	key    []byte                 // The decryption key
	Error  error                  // Error field for storing decryption errors
}

// NewStdDecrypter creates a new DES decrypter with the specified cipher and key.
// Validates the key length and initializes the decrypter for DES decryption operations.
// The key must be exactly 8 bytes for DES decryption.
func NewStdDecrypter(c cipher.CipherInterface, key []byte) *StdDecrypter {
	d := &StdDecrypter{
		cipher: c,
		key:    key,
	}

	if len(key) != 8 {
		d.Error = KeySizeError(len(key))
	}

	return d
}

// Decrypt decrypts the given byte slice using DES decryption.
// Creates a DES cipher block and uses the configured cipher interface
// to perform the decryption operation with proper error handling.
func (d *StdDecrypter) Decrypt(src []byte) (dst []byte, err error) {
	if d.Error != nil {
		err = d.Error
		return
	}
	if len(src) == 0 {
		return
	}

	// Create DES cipher block using the provided key
	block, err := des.NewCipher(d.key)
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

// StreamEncrypter represents a DES encrypter for streaming encryption operations.
// It implements DES encryption using the standard DES algorithm with support
// for 64-bit keys and various cipher modes, providing streaming capabilities.
type StreamEncrypter struct {
	writer io.Writer              // Underlying writer for encrypted output
	cipher cipher.CipherInterface // The cipher interface for encryption operations
	key    []byte                 // The encryption key
	Error  error                  // Error field for storing encryption errors
}

// NewStreamEncrypter creates a new DES stream encrypter with the specified writer, cipher, and key.
// Validates the key length and initializes the encrypter for DES streaming encryption operations.
// The key must be exactly 8 bytes for DES encryption.
func NewStreamEncrypter(w io.Writer, c cipher.CipherInterface, key []byte) io.WriteCloser {
	e := &StreamEncrypter{
		writer: w,
		cipher: c,
		key:    key,
	}

	if len(key) != 8 {
		e.Error = KeySizeError(len(key))
	}

	return e
}

// Write implements the io.Writer interface for streaming DES encryption.
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

	// Create DES cipher block using the provided key
	// This step validates the key and creates the underlying cipher implementation
	block, err := des.NewCipher(e.key)
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
	return e.writer.Write(encrypted)
}

// Close implements the io.Closer interface for the DES stream encrypter.
// Closes the underlying writer if it implements io.Closer.
func (e *StreamEncrypter) Close() error {
	if closer, ok := e.writer.(io.Closer); ok {
		return closer.Close()
	}
	return nil
}

// StreamDecrypter represents a DES decrypter for streaming decryption operations.
// It implements DES decryption using the standard DES algorithm with support
// for 64-bit keys and various cipher modes, providing streaming capabilities.
type StreamDecrypter struct {
	reader io.Reader              // Underlying reader for encrypted input
	cipher cipher.CipherInterface // The cipher interface for decryption operations
	key    []byte                 // The decryption key
	Error  error                  // Error field for storing decryption errors
}

// NewStreamDecrypter creates a new DES stream decrypter with the specified reader, cipher, and key.
// Validates the key length and initializes the decrypter for DES streaming decryption operations.
// The key must be exactly 8 bytes for DES decryption.
func NewStreamDecrypter(r io.Reader, c cipher.CipherInterface, key []byte) io.Reader {
	d := &StreamDecrypter{
		reader: r,
		cipher: c,
		key:    key,
	}

	if len(key) != 8 {
		d.Error = KeySizeError(len(key))
	}

	return d
}

// Read implements the io.Reader interface for streaming DES decryption.
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

	// Create DES cipher block using the provided key
	block, err := des.NewCipher(d.key)
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
