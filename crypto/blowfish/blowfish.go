// Package blowfish implements Blowfish encryption and decryption with streaming support.
// It provides Blowfish encryption and decryption operations using the standard
// Blowfish algorithm with support for variable key sizes from 32 to 448 bits.
package blowfish

import (
	stdcipher "crypto/cipher"
	"io"

	"golang.org/x/crypto/blowfish"

	"github.com/dromara/dongle/crypto/cipher"
)

// StdEncrypter represents a Blowfish encrypter for standard encryption operations.
// It implements Blowfish encryption using the standard Blowfish algorithm with support
// for different key sizes and various cipher modes.
type StdEncrypter struct {
	cipher cipher.BlowfishCipher // The cipher interface for encryption operations
	Error  error                 // Error field for storing encryption errors
}

// NewStdEncrypter creates a new Blowfish encrypter with the specified cipher and key.
// Validates the key length and initializes the encrypter for Blowfish encryption operations.
// The key must be between 32 and 448 bits (4 to 56 bytes).
func NewStdEncrypter(c cipher.BlowfishCipher) *StdEncrypter {
	e := &StdEncrypter{
		cipher: c,
	}

	if len(c.Key) < 4 || len(c.Key) > 56 {
		e.Error = KeySizeError(len(c.Key))
	}

	return e
}

// Encrypt encrypts the given byte slice using Blowfish encryption.
// Creates a Blowfish cipher block and uses the configured cipher interface
// to perform the encryption operation with proper error handling.
func (e *StdEncrypter) Encrypt(src []byte) (dst []byte, err error) {
	// Create Blowfish cipher block using the provided key
	block, err := blowfish.NewCipher(e.cipher.Key)
	if err != nil {
		return nil, EncryptError{Err: err}
	}

	return encrypt(e.cipher, src, block)
}

// StdDecrypter represents a Blowfish decrypter for standard decryption operations.
// It implements Blowfish decryption using the standard Blowfish algorithm with support
// for different key sizes and various cipher modes.
type StdDecrypter struct {
	cipher cipher.BlowfishCipher // The cipher interface for decryption operations
	Error  error                 // Error field for storing decryption errors
}

// NewStdDecrypter creates a new Blowfish decrypter with the specified cipher and key.
// Validates the key length and initializes the decrypter for Blowfish decryption operations.
// The key must be between 32 and 448 bits (4 to 56 bytes).
func NewStdDecrypter(c cipher.BlowfishCipher) *StdDecrypter {
	d := &StdDecrypter{
		cipher: c,
	}

	if len(c.Key) < 4 || len(c.Key) > 56 {
		d.Error = KeySizeError(len(c.Key))
	}
	return d
}

// Decrypt decrypts the given byte slice using Blowfish decryption.
// Creates a Blowfish cipher block and uses the configured cipher interface
// to perform the decryption operation with proper error handling.
func (d *StdDecrypter) Decrypt(src []byte) (dst []byte, err error) {
	// Create Blowfish cipher block using the provided key
	block, err := blowfish.NewCipher(d.cipher.Key)
	if err != nil {
		return nil, DecryptError{Err: err}
	}

	return decrypt(d.cipher, src, block)
}

// StreamEncrypter represents a streaming Blowfish encrypter that implements io.WriteCloser.
// It provides efficient encryption for large data streams by processing data
// in chunks and writing encrypted output to the underlying writer.
type StreamEncrypter struct {
	writer io.Writer             // Underlying writer for encrypted output
	cipher cipher.BlowfishCipher // The cipher interface for encryption operations
	Error  error                 // Error field for storing encryption errors
}

// NewStreamEncrypter creates a new streaming Blowfish encrypter that writes encrypted data
// to the provided io.Writer. The encrypter uses the specified cipher interface
// and validates the key length for proper Blowfish encryption.
func NewStreamEncrypter(w io.Writer, c cipher.BlowfishCipher) io.WriteCloser {
	e := &StreamEncrypter{
		writer: w,
		cipher: c,
	}

	if len(c.Key) < 4 || len(c.Key) > 56 {
		e.Error = KeySizeError(len(c.Key))
		return e
	}

	return e
}

// Write implements the io.Writer interface for streaming Blowfish encryption.
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

	// Create Blowfish cipher block using the provided key
	block, err := blowfish.NewCipher(e.cipher.Key)
	if err != nil {
		return 0, EncryptError{Err: err}
	}

	// Use encrypt helper function to handle padding and encryption
	encrypted, err := encrypt(e.cipher, p, block)

	if err == nil {
		return e.writer.Write(encrypted)
	}

	return
}

// Close implements the io.Closer interface for the Blowfish stream encrypter.
// Closes the underlying writer if it implements io.Closer.
func (e *StreamEncrypter) Close() error {
	if closer, ok := e.writer.(io.Closer); ok {
		return closer.Close()
	}
	return nil
}

// StreamDecrypter represents a streaming Blowfish decrypter that implements io.Reader.
// It provides efficient decryption for large data streams by processing data
// in chunks and reading decrypted output from the underlying reader.
type StreamDecrypter struct {
	reader io.Reader             // Underlying reader for encrypted input
	cipher cipher.BlowfishCipher // The cipher interface for decryption operations
	Error  error                 // Error field for storing decryption errors
}

// NewStreamDecrypter creates a new streaming Blowfish decrypter that reads encrypted data
// from the provided io.Reader. The decrypter uses the specified cipher interface
// and validates the key length for proper Blowfish decryption.
func NewStreamDecrypter(r io.Reader, c cipher.BlowfishCipher) io.Reader {
	d := &StreamDecrypter{
		reader: r,
		cipher: c,
	}

	if len(c.Key) < 4 || len(c.Key) > 56 {
		d.Error = KeySizeError(len(c.Key))
		return d
	}

	return d
}

// Read implements the io.Reader interface for streaming Blowfish decryption.
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

	// Create Blowfish cipher block using the provided key
	block, err := blowfish.NewCipher(d.cipher.Key)
	if err != nil {
		return 0, DecryptError{Err: err}
	}

	unpadded, err := decrypt(d.cipher, encrypted, block)
	if err != nil {
		return 0, err
	}

	// Copy decrypted data to the provided buffer
	n = copy(p, unpadded)
	if n < len(unpadded) {
		// Buffer is too small, we can't return all data
		err = BufferError{bufferSize: len(p), dataSize: len(unpadded)}
		return
	}
	return
}

func encrypt(c cipher.BlowfishCipher, src []byte, block stdcipher.Block) (dst []byte, err error) {
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

func decrypt(c cipher.BlowfishCipher, src []byte, block stdcipher.Block) (dst []byte, err error) {
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
