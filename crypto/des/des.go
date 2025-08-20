// Package des implements DES encryption and decryption with streaming support.
// It provides DES encryption and decryption operations using the standard
// DES algorithm with support for 64-bit keys.
package des

import (
	stdcipher "crypto/cipher"
	"crypto/des"
	"io"

	"gitee.com/golang-package/dongle/crypto/cipher"
)

// StdEncrypter represents a DES encrypter for standard encryption operations.
// It implements DES encryption using the standard DES algorithm with support
// for 64-bit keys and various cipher modes.
type StdEncrypter struct {
	cipher cipher.DesCipher // The cipher interface for encryption operations
	Error  error            // Error field for storing encryption errors
}

// NewStdEncrypter creates a new DES encrypter with the specified cipher.
// Validates the key length and initializes the encrypter for DES encryption operations.
// The key must be exactly 8 bytes for DES encryption.
func NewStdEncrypter(c cipher.DesCipher) *StdEncrypter {
	e := &StdEncrypter{
		cipher: c,
	}

	if len(c.Key) != 8 {
		e.Error = KeySizeError(len(c.Key))
	}

	return e
}

// Encrypt encrypts the given byte slice using DES encryption.
// Creates a DES cipher block and uses the configured cipher interface
// to perform the encryption operation with proper error handling.
func (e *StdEncrypter) Encrypt(src []byte) (dst []byte, err error) {
	// Create DES cipher block using the provided key
	block, err := des.NewCipher(e.cipher.Key)
	if err != nil {
		return nil, EncryptError{Err: err}
	}

	return encrypt(e.cipher, src, block)
}

// StdDecrypter represents a DES decrypter for standard decryption operations.
// It implements DES decryption using the standard DES algorithm with support
// for 64-bit keys and various cipher modes.
type StdDecrypter struct {
	cipher cipher.DesCipher // The cipher interface for decryption operations
	Error  error            // Error field for storing decryption errors
}

// NewStdDecrypter creates a new DES decrypter with the specified cipher.
// Validates the key length and initializes the decrypter for DES decryption operations.
// The key must be exactly 8 bytes for DES decryption.
func NewStdDecrypter(c cipher.DesCipher) *StdDecrypter {
	d := &StdDecrypter{
		cipher: c,
	}

	if len(c.Key) != 8 {
		d.Error = KeySizeError(len(c.Key))
	}

	return d
}

// Decrypt decrypts the given byte slice using DES decryption.
// Creates a DES cipher block and uses the configured cipher interface
// to perform the decryption operation with proper error handling.
func (d *StdDecrypter) Decrypt(src []byte) (dst []byte, err error) {
	// Create DES cipher block using the provided key
	block, err := des.NewCipher(d.cipher.Key)
	if err != nil {
		return nil, DecryptError{Err: err}
	}

	return decrypt(d.cipher, src, block)
}

// StreamEncrypter represents a DES encrypter for streaming encryption operations.
// It implements DES encryption using the standard DES algorithm with support
// for 64-bit keys and various cipher modes, providing streaming capabilities.
type StreamEncrypter struct {
	writer io.Writer        // Underlying writer for encrypted output
	cipher cipher.DesCipher // The cipher interface for encryption operations
	Error  error            // Error field for storing encryption errors
}

// NewStreamEncrypter creates a new DES stream encrypter with the specified writer and cipher.
// Validates the key length and initializes the encrypter for DES streaming encryption operations.
// The key must be exactly 8 bytes for DES encryption.
func NewStreamEncrypter(w io.Writer, c cipher.DesCipher) io.WriteCloser {
	e := &StreamEncrypter{
		writer: w,
		cipher: c,
	}

	if len(c.Key) != 8 {
		e.Error = KeySizeError(len(c.Key))
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
	block, err := des.NewCipher(e.cipher.Key)
	if err != nil {
		return 0, EncryptError{Err: err}
	}

	// Encrypt the data using the configured cipher interface
	encrypted, err := encrypt(e.cipher, p, block)
	if err == nil {
		// Write encrypted data to the underlying writer
		return e.writer.Write(encrypted)
	}
	return
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
	reader io.Reader        // Underlying reader for encrypted input
	cipher cipher.DesCipher // The cipher interface for decryption operations
	Error  error            // Error field for storing decryption errors
}

// NewStreamDecrypter creates a new DES stream decrypter with the specified reader and cipher.
// Validates the key length and initializes the decrypter for DES streaming decryption operations.
// The key must be exactly 8 bytes for DES decryption.
func NewStreamDecrypter(r io.Reader, c cipher.DesCipher) io.Reader {
	d := &StreamDecrypter{
		reader: r,
		cipher: c,
	}

	if len(c.Key) != 8 {
		d.Error = KeySizeError(len(c.Key))
	}

	return d
}

// Read implements the io.Reader interface for streaming DES decryption.
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
		return 0, ReadError{Err: err}
	}

	if len(encrypted) == 0 {
		return 0, io.EOF
	}

	// Create DES cipher block using the provided key
	block, err := des.NewCipher(d.cipher.Key)

	// Decrypt the data using the configured cipher interface
	decrypted, err := decrypt(d.cipher, encrypted, block)
	if err != nil {
		return 0, DecryptError{Err: err}
	}

	// Copy decrypted data to the provided buffer
	n = copy(p, decrypted)
	if n < len(decrypted) {
		// Buffer is too small, we can't return all data
		return n, BufferError{bufferSize: len(p), dataSize: len(decrypted)}
	}

	return n, nil
}

func encrypt(c cipher.DesCipher, src []byte, block stdcipher.Block) (dst []byte, err error) {
	var paddedSrc []byte
	switch c.Padding {
	case cipher.No:
		paddedSrc = src
	case cipher.Zero:
		paddedSrc = cipher.NewZeroPadding(src, block.BlockSize())
	case cipher.PKCS5:
		paddedSrc = cipher.NewPKCS5Padding(src)
	case cipher.PKCS7:
		paddedSrc = cipher.NewPKCS7Padding(src, block.BlockSize())
	case cipher.AnsiX923:
		paddedSrc = cipher.NewAnsiX923Padding(src, block.BlockSize())
	case cipher.ISO97971:
		paddedSrc = cipher.NewISO97971Padding(src, block.BlockSize())
	case cipher.ISO10126:
		paddedSrc = cipher.NewISO10126Padding(src, block.BlockSize())
	case cipher.ISO78164:
		paddedSrc = cipher.NewISO78164Padding(src, block.BlockSize())
	case cipher.Bit:
		paddedSrc = cipher.NewBitPadding(src, block.BlockSize())
	}
	switch c.Block {
	case cipher.CBC:
		return cipher.NewCBCEncrypter(paddedSrc, c.IV, block)
	case cipher.CTR:
		return cipher.NewCTREncrypter(paddedSrc, c.IV, block)
	case cipher.ECB:
		return cipher.NewECBEncrypter(paddedSrc, block)
	case cipher.GCM:
		return cipher.NewGCMEncrypter(paddedSrc, c.Nonce, c.Aad, block)
	case cipher.CFB:
		return cipher.NewCFBEncrypter(paddedSrc, c.IV, block)
	case cipher.OFB:
		return cipher.NewOFBEncrypter(paddedSrc, c.IV, block)
	}
	return
}

func decrypt(c cipher.DesCipher, src []byte, block stdcipher.Block) (dst []byte, err error) {
	var decrypted []byte
	switch c.Block {
	case cipher.CBC:
		decrypted, err = cipher.NewCBCDecrypter(src, c.IV, block)
	case cipher.CTR:
		decrypted, err = cipher.NewCTRDecrypter(src, c.IV, block)
	case cipher.ECB:
		decrypted, err = cipher.NewECBDecrypter(src, block)
	case cipher.GCM:
		decrypted, err = cipher.NewGCMDecrypter(src, c.Nonce, c.Aad, block)
	case cipher.CFB:
		decrypted, err = cipher.NewCFBDecrypter(src, c.IV, block)
	case cipher.OFB:
		decrypted, err = cipher.NewOFBDecrypter(src, c.IV, block)
	}
	if err != nil {
		return nil, DecryptError{Err: err}
	}
	switch c.Padding {
	case cipher.No:
		dst = decrypted
	case cipher.Zero:
		dst = cipher.NewZeroUnPadding(decrypted)
	case cipher.PKCS5:
		dst = cipher.NewPKCS5UnPadding(decrypted)
	case cipher.PKCS7:
		dst = cipher.NewPKCS7UnPadding(decrypted)
	case cipher.AnsiX923:
		dst = cipher.NewAnsiX923UnPadding(decrypted)
	case cipher.ISO97971:
		dst = cipher.NewISO97971UnPadding(decrypted)
	case cipher.ISO10126:
		dst = cipher.NewISO10126UnPadding(decrypted)
	case cipher.ISO78164:
		dst = cipher.NewISO78164UnPadding(decrypted)
	case cipher.Bit:
		dst = cipher.NewBitUnPadding(decrypted)
	}
	return
}
