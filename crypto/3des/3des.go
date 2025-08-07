package triple_des

import (
	"crypto/des"
	"io"

	"github.com/dromara/dongle/crypto/cipher"
)

// StdEncrypter represents a Triple DES encrypter for standard encryption operations.
// It implements Triple DES encryption using the standard Triple DES algorithm with support
// for 128-bit (16-byte) and 192-bit (24-byte) keys and various cipher modes.
type StdEncrypter struct {
	cipher cipher.CipherInterface // The cipher interface for encryption operations
	key    []byte                 // The encryption key
	Error  error                  // Error field for storing encryption errors
}

// NewStdEncrypter creates a new Triple DES encrypter with the specified cipher and key.
// Validates the key length and initializes the encrypter for Triple DES encryption operations.
// The key must be exactly 16 or 24 bytes for Triple DES encryption.
// For 16-byte keys, the implementation automatically expands them to 24 bytes
// using the pattern key1 + key2 + key1.
func NewStdEncrypter(c cipher.CipherInterface, key []byte) *StdEncrypter {
	e := &StdEncrypter{
		cipher: c,
		key:    key,
	}

	if len(key) != 16 && len(key) != 24 {
		e.Error = KeySizeError(len(key))
		return e
	}

	// For 16-byte keys, we need to expand to 24 bytes (key1 + key2 + key1)
	if len(key) == 16 {
		expandedKey := make([]byte, 24)
		copy(expandedKey[:8], key[:8])   // key1
		copy(expandedKey[8:16], key[8:]) // key2
		copy(expandedKey[16:], key[:8])  // key1 again
		e.key = expandedKey
	} else {
		e.key = key
	}

	return e
}

// Encrypt encrypts the given byte slice using Triple DES encryption.
// Creates a Triple DES cipher block and uses the configured cipher interface
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

	// Create Triple DES cipher block using the provided key
	block, err := des.NewTripleDESCipher(e.key)
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

// StdDecrypter represents a Triple DES decrypter for standard decryption operations.
// It implements Triple DES decryption using the standard Triple DES algorithm with support
// for 128-bit (16-byte) and 192-bit (24-byte) keys and various cipher modes.
type StdDecrypter struct {
	cipher cipher.CipherInterface // The cipher interface for decryption operations
	key    []byte                 // The decryption key
	Error  error                  // Error field for storing decryption errors
}

// NewStdDecrypter creates a new Triple DES decrypter with the specified cipher and key.
// Validates the key length and initializes the decrypter for Triple DES decryption operations.
// The key must be exactly 16 or 24 bytes for Triple DES decryption.
// For 16-byte keys, the implementation automatically expands them to 24 bytes
// using the pattern key1 + key2 + key1.
func NewStdDecrypter(c cipher.CipherInterface, key []byte) *StdDecrypter {
	d := &StdDecrypter{
		cipher: c,
		key:    key,
	}

	if len(key) != 16 && len(key) != 24 {
		d.Error = KeySizeError(len(key))
		return d
	}

	// For 16-byte keys, we need to expand to 24 bytes (key1 + key2 + key1)
	if len(key) == 16 {
		expandedKey := make([]byte, 24)
		copy(expandedKey[:8], key[:8])   // key1
		copy(expandedKey[8:16], key[8:]) // key2
		copy(expandedKey[16:], key[:8])  // key1 again
		d.key = expandedKey
	} else {
		d.key = key
	}

	return d
}

// Decrypt decrypts the given byte slice using Triple DES decryption.
// Creates a Triple DES cipher block and uses the configured cipher interface
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

	// Create Triple DES cipher block using the provided key
	// This step validates the key and creates the underlying cipher implementation
	block, err := des.NewTripleDESCipher(d.key)
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

// StreamEncrypter represents a Triple DES encrypter for streaming encryption operations.
// It implements Triple DES encryption using the standard Triple DES algorithm with support
// for 128-bit (16-byte) and 192-bit (24-byte) keys and various cipher modes, providing streaming capabilities.
type StreamEncrypter struct {
	writer io.Writer              // Underlying writer for encrypted output
	cipher cipher.CipherInterface // The cipher interface for encryption operations
	key    []byte                 // The encryption key
	Error  error                  // Error field for storing encryption errors
}

// NewStreamEncrypter creates a new Triple DES stream encrypter with the specified writer, cipher, and key.
// Validates the key length and initializes the encrypter for Triple DES streaming encryption operations.
// The key must be exactly 16 or 24 bytes for Triple DES encryption.
// For 16-byte keys, the implementation automatically expands them to 24 bytes
// using the pattern key1 + key2 + key1.
func NewStreamEncrypter(w io.Writer, c cipher.CipherInterface, key []byte) io.WriteCloser {
	e := &StreamEncrypter{
		writer: w,
		cipher: c,
		key:    key,
	}

	if len(key) != 16 && len(key) != 24 {
		e.Error = KeySizeError(len(key))
		return e
	}

	// For 16-byte keys, we need to expand to 24 bytes (key1 + key2 + key1)
	if len(key) == 16 {
		expandedKey := make([]byte, 24)
		copy(expandedKey[:8], key[:8])   // key1
		copy(expandedKey[8:16], key[8:]) // key2
		copy(expandedKey[16:], key[:8])  // key1 again
		e.key = expandedKey
	} else {
		e.key = key
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
	block, err := des.NewTripleDESCipher(e.key)
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

// Close implements the io.Closer interface for the Triple DES stream encrypter.
// Closes the underlying writer if it implements io.Closer.
func (e *StreamEncrypter) Close() error {
	if closer, ok := e.writer.(io.Closer); ok {
		return closer.Close()
	}
	return nil
}

// StreamDecrypter represents a Triple DES decrypter for streaming decryption operations.
// It implements Triple DES decryption using the standard Triple DES algorithm with support
// for 128-bit (16-byte) and 192-bit (24-byte) keys and various cipher modes, providing streaming capabilities.
type StreamDecrypter struct {
	reader io.Reader              // Underlying reader for encrypted input
	cipher cipher.CipherInterface // The cipher interface for decryption operations
	key    []byte                 // The decryption key
	Error  error                  // Error field for storing decryption errors
}

// NewStreamDecrypter creates a new Triple DES stream decrypter with the specified reader, cipher, and key.
// Validates the key length and initializes the decrypter for Triple DES streaming decryption operations.
// The key must be exactly 16 or 24 bytes for Triple DES decryption.
// For 16-byte keys, the implementation automatically expands them to 24 bytes
// using the pattern key1 + key2 + key1.
func NewStreamDecrypter(r io.Reader, c cipher.CipherInterface, key []byte) io.Reader {
	d := &StreamDecrypter{
		reader: r,
		cipher: c,
		key:    key,
	}

	if len(key) != 16 && len(key) != 24 {
		d.Error = KeySizeError(len(key))
		return d
	}

	// For 16-byte keys, we need to expand to 24 bytes (key1 + key2 + key1)
	if len(key) == 16 {
		expandedKey := make([]byte, 24)
		copy(expandedKey[:8], key[:8])   // key1
		copy(expandedKey[8:16], key[8:]) // key2
		copy(expandedKey[16:], key[:8])  // key1 again
		d.key = expandedKey
	} else {
		d.key = key
	}

	return d
}

// Read implements the io.Reader interface for streaming Triple DES decryption.
// Reads encrypted data from the underlying reader, decrypts it, and fills the provided buffer.
// Returns the number of bytes read and any error that occurred.
func (d *StreamDecrypter) Read(p []byte) (n int, err error) {
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

	// Create Triple DES cipher block using the provided key
	block, err := des.NewTripleDESCipher(d.key)
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
