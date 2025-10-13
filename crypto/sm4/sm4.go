// Package sm4 implements SM4 encryption and decryption with streaming support.
// It provides SM4 encryption and decryption operations using the standard
// SM4 algorithm with support for various cipher modes.
package sm4

import (
	stdCipher "crypto/cipher"
	"encoding/binary"
	"io"

	"github.com/dromara/dongle/crypto/cipher"
)

const (
	// BlockSize is the SM4 block size in bytes.
	BlockSize = 16
	// KeySize is the SM4 key size in bytes.
	KeySize = 16
)

// sm4Cipher implements the cipher.Block interface for SM4.
type sm4Cipher struct {
	key [KeySize]byte
}

// NewCipher creates a new SM4 cipher with the given key.
// The key must be exactly 16 bytes (128 bits).
func NewCipher(key []byte) (stdCipher.Block, error) {
	if len(key) != KeySize {
		return nil, KeySizeError(len(key))
	}

	c := &sm4Cipher{}
	copy(c.key[:], key)
	return c, nil
}

// BlockSize returns the SM4 block size.
func (c *sm4Cipher) BlockSize() int {
	return BlockSize
}

// Encrypt encrypts the first block in src into dst.
// Dst and src must overlap entirely or not at all.
func (c *sm4Cipher) Encrypt(dst, src []byte) {
	if len(src) < BlockSize {
		panic("sm4: input not full block")
	}
	if len(dst) < BlockSize {
		panic("sm4: output not full block")
	}

	// Convert input to 4 32-bit words
	var x [4]uint32
	x[0] = binary.BigEndian.Uint32(src[0:4])
	x[1] = binary.BigEndian.Uint32(src[4:8])
	x[2] = binary.BigEndian.Uint32(src[8:12])
	x[3] = binary.BigEndian.Uint32(src[12:16])

	encrypt(&x, &c.key)

	// Convert output back to bytes
	binary.BigEndian.PutUint32(dst[0:4], x[0])
	binary.BigEndian.PutUint32(dst[4:8], x[1])
	binary.BigEndian.PutUint32(dst[8:12], x[2])
	binary.BigEndian.PutUint32(dst[12:16], x[3])
}

// Decrypt decrypts the first block in src into dst.
// Dst and src must overlap entirely or not at all.
func (c *sm4Cipher) Decrypt(dst, src []byte) {
	if len(src) < BlockSize {
		panic("crypto/sm4: input not full block")
	}
	if len(dst) < BlockSize {
		panic("crypto/sm4: output not full block")
	}

	// Convert input to 4 32-bit words
	var x [4]uint32
	x[0] = binary.BigEndian.Uint32(src[0:4])
	x[1] = binary.BigEndian.Uint32(src[4:8])
	x[2] = binary.BigEndian.Uint32(src[8:12])
	x[3] = binary.BigEndian.Uint32(src[12:16])

	decrypt(&x, &c.key)

	// Convert output back to bytes
	binary.BigEndian.PutUint32(dst[0:4], x[0])
	binary.BigEndian.PutUint32(dst[4:8], x[1])
	binary.BigEndian.PutUint32(dst[8:12], x[2])
	binary.BigEndian.PutUint32(dst[12:16], x[3])
}

// StdEncrypter represents an SM4 encrypter for standard encryption operations.
type StdEncrypter struct {
	cipher *cipher.Sm4Cipher // The cipher interface for encryption operations
	block  stdCipher.Block   // Pre-created cipher block for reuse
	Error  error             // Error field for storing encryption errors
}

// NewStdEncrypter creates a new SM4 encrypter with the specified cipher and key.
func NewStdEncrypter(c *cipher.Sm4Cipher) *StdEncrypter {
	e := &StdEncrypter{
		cipher: c,
	}
	if len(c.Key) != KeySize {
		e.Error = KeySizeError(len(c.Key))
		return e
	}
	e.block, e.Error = NewCipher(c.Key)
	return e
}

// Encrypt encrypts the given byte slice using SM4 encryption.
func (e *StdEncrypter) Encrypt(src []byte) (dst []byte, err error) {
	if e.Error != nil {
		return nil, e.Error
	}
	if len(src) == 0 {
		return []byte{}, nil
	}
	dst, err = e.cipher.Encrypt(src, e.block)
	if err != nil {
		err = EncryptError{Err: err}
	}
	return
}

// StdDecrypter represents an SM4 decrypter for standard decryption operations.
type StdDecrypter struct {
	cipher *cipher.Sm4Cipher // The cipher interface for decryption operations
	block  stdCipher.Block   // Pre-created cipher block for reuse
	Error  error             // Error field for storing decryption errors
}

// NewStdDecrypter creates a new SM4 decrypter with the specified cipher and key.
func NewStdDecrypter(c *cipher.Sm4Cipher) *StdDecrypter {
	d := &StdDecrypter{
		cipher: c,
	}
	if len(c.Key) != KeySize {
		d.Error = KeySizeError(len(c.Key))
		return d
	}
	d.block, d.Error = NewCipher(c.Key)
	return d
}

// Decrypt decrypts the given byte slice using SM4 decryption.
func (d *StdDecrypter) Decrypt(src []byte) (dst []byte, err error) {
	if d.Error != nil {
		return nil, d.Error
	}
	if len(src) == 0 {
		return []byte{}, nil
	}
	dst, err = d.cipher.Decrypt(src, d.block)
	if err != nil {
		err = DecryptError{Err: err}
	}
	return
}

// StreamEncrypter represents a streaming SM4 encrypter that implements io.WriteCloser.
type StreamEncrypter struct {
	writer io.Writer         // Underlying writer for encrypted output
	cipher *cipher.Sm4Cipher // The cipher interface for encryption operations
	buffer []byte            // Buffer for accumulating incomplete blocks
	block  stdCipher.Block   // Reused cipher block for better performance
	Error  error             // Error field for storing encryption errors
}

// NewStreamEncrypter creates a new streaming SM4 encrypter that writes encrypted data
// to the provided io.Writer. The encrypter uses the specified cipher interface
// and validates the key length for proper SM4 encryption.
func NewStreamEncrypter(w io.Writer, c *cipher.Sm4Cipher) io.WriteCloser {
	e := &StreamEncrypter{
		writer: w,
		cipher: c,
		buffer: make([]byte, 0, BlockSize), // SM4 block size is 16 bytes
	}
	if len(c.Key) != KeySize {
		e.Error = KeySizeError(len(c.Key))
		return e
	}
	e.block, e.Error = NewCipher(c.Key)
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
	reader    io.Reader         // Underlying reader for encrypted input
	cipher    *cipher.Sm4Cipher // The cipher interface for decryption operations
	decrypted []byte            // All decrypted data
	pos       int               // Current position in the decrypted data
	block     stdCipher.Block   // Reused cipher block for better performance
	Error     error             // Error field for storing decryption errors
}

// NewStreamDecrypter creates a new streaming SM4 decrypter that reads encrypted data
// from the provided io.Reader. The decrypter uses the specified cipher interface
// and validates the key length for proper SM4 decryption.
func NewStreamDecrypter(r io.Reader, c *cipher.Sm4Cipher) io.Reader {
	d := &StreamDecrypter{
		reader:    r,
		cipher:    c,
		decrypted: nil, // Will be populated on first read
		pos:       0,
	}
	if len(c.Key) != KeySize {
		d.Error = KeySizeError(len(c.Key))
		return d
	}
	d.block, d.Error = NewCipher(c.Key)
	return d
}

// Read implements the io.Reader interface for streaming SM4 decryption.
func (d *StreamDecrypter) Read(dst []byte) (n int, err error) {
	if d.Error != nil {
		return 0, d.Error
	}

	// If we haven't decrypted the data yet, do it now
	if d.decrypted == nil {
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

		d.decrypted = decrypted
		d.pos = 0
	}

	// If we've already returned all decrypted data, return EOF
	if d.pos >= len(d.decrypted) {
		return 0, io.EOF
	}

	// Copy as much decrypted data as possible to the provided buffer
	remainingData := d.decrypted[d.pos:]
	copied := copy(dst, remainingData)
	d.pos += copied

	return copied, nil
}

// s-box (according to GB/T 32907-2016)
var sBox = [256]byte{
	0xd6, 0x90, 0xe9, 0xfe, 0xcc, 0xe1, 0x3d, 0xb7, 0x16, 0xb6, 0x14, 0xc2, 0x28, 0xfb, 0x2c, 0x05,
	0x2b, 0x67, 0x9a, 0x76, 0x2a, 0xbe, 0x04, 0xc3, 0xaa, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99,
	0x9c, 0x42, 0x50, 0xf4, 0x91, 0xef, 0x98, 0x7a, 0x33, 0x54, 0x0b, 0x43, 0xed, 0xcf, 0xac, 0x62,
	0xe4, 0xb3, 0x1c, 0xa9, 0xc9, 0x08, 0xe8, 0x95, 0x80, 0xdf, 0x94, 0xfa, 0x75, 0x8f, 0x3f, 0xa6,
	0x47, 0x07, 0xa7, 0xfc, 0xf3, 0x73, 0x17, 0xba, 0x83, 0x59, 0x3c, 0x19, 0xe6, 0x85, 0x4f, 0xa8,
	0x68, 0x6b, 0x81, 0xb2, 0x71, 0x64, 0xda, 0x8b, 0xf8, 0xeb, 0x0f, 0x4b, 0x70, 0x56, 0x9d, 0x35,
	0x1e, 0x24, 0x0e, 0x5e, 0x63, 0x58, 0xd1, 0xa2, 0x25, 0x22, 0x7c, 0x3b, 0x01, 0x21, 0x78, 0x87,
	0xd4, 0x00, 0x46, 0x57, 0x9f, 0xd3, 0x27, 0x52, 0x4c, 0x36, 0x02, 0xe7, 0xa0, 0xc4, 0xc8, 0x9e,
	0xea, 0xbf, 0x8a, 0xd2, 0x40, 0xc7, 0x38, 0xb5, 0xa3, 0xf7, 0xf2, 0xce, 0xf9, 0x61, 0x15, 0xa1,
	0xe0, 0xae, 0x5d, 0xa4, 0x9b, 0x34, 0x1a, 0x55, 0xad, 0x93, 0x32, 0x30, 0xf5, 0x8c, 0xb1, 0xe3,
	0x1d, 0xf6, 0xe2, 0x2e, 0x82, 0x66, 0xca, 0x60, 0xc0, 0x29, 0x23, 0xab, 0x0d, 0x53, 0x4e, 0x6f,
	0xd5, 0xdb, 0x37, 0x45, 0xde, 0xfd, 0x8e, 0x2f, 0x03, 0xff, 0x6a, 0x72, 0x6d, 0x6c, 0x5b, 0x51,
	0x8d, 0x1b, 0xaf, 0x92, 0xbb, 0xdd, 0xbc, 0x7f, 0x11, 0xd9, 0x5c, 0x41, 0x1f, 0x10, 0x5a, 0xd8,
	0x0a, 0xc1, 0x31, 0x88, 0xa5, 0xcd, 0x7b, 0xbd, 0x2d, 0x74, 0xd0, 0x12, 0xb8, 0xe5, 0xb4, 0xb0,
	0x89, 0x69, 0x97, 0x4a, 0x0c, 0x96, 0x77, 0x7e, 0x65, 0xb9, 0xf1, 0x09, 0xc5, 0x6e, 0xc6, 0x84,
	0x18, 0xf0, 0x7d, 0xec, 0x3a, 0xdc, 0x4d, 0x20, 0x79, 0xee, 0x5f, 0x3e, 0xd7, 0xcb, 0x39, 0x48,
}

// round constants
var ck = [32]uint32{
	0x00070e15, 0x1c232a31, 0x383f464d, 0x545b6269,
	0x70777e85, 0x8c939aa1, 0xa8afb6bd, 0xc4cbd2d9,
	0xe0e7eef5, 0xfc030a11, 0x181f262d, 0x343b4249,
	0x50575e65, 0x6c737a81, 0x888f969d, 0xa4abb2b9,
	0xc0c7ced5, 0xdce3eaf1, 0xf8ff060d, 0x141b2229,
	0x30373e45, 0x4c535a61, 0x686f767d, 0x848b9299,
	0xa0a7aeb5, 0xbcc3cad1, 0xd8dfe6ed, 0xf4fb0209,
	0x10171e25, 0x2c333a41, 0x484f565d, 0x646b7279,
}

// sBoxTransform performs the s-box substitution (a.k.a. tau transformation)
func sBoxTransform(a uint32) uint32 {
	return uint32(sBox[a>>24&0xff])<<24 |
		uint32(sBox[a>>16&0xff])<<16 |
		uint32(sBox[a>>8&0xff])<<8 |
		uint32(sBox[a&0xff])
}

// L transformation
func lTransform(b uint32) uint32 {
	return b ^ rotateLeft(b, 2) ^ rotateLeft(b, 10) ^ rotateLeft(b, 18) ^ rotateLeft(b, 24)
}

// L` transformation
func lPrimeTransform(b uint32) uint32 {
	return b ^ rotateLeft(b, 13) ^ rotateLeft(b, 23)
}

// rotateLeft performs a 32-bit left rotation
func rotateLeft(x uint32, n uint) uint32 {
	return (x << n) | (x >> (32 - n))
}

// T transformation
func tTransform(x uint32) uint32 {
	return lTransform(sBoxTransform(x))
}

// expands the SM4 key into round keys
func expandKey(key *[KeySize]byte) [32]uint32 {
	var mk [4]uint32
	var rk [32]uint32

	// Convert key to 4 32-bit words
	mk[0] = binary.BigEndian.Uint32(key[0:4])
	mk[1] = binary.BigEndian.Uint32(key[4:8])
	mk[2] = binary.BigEndian.Uint32(key[8:12])
	mk[3] = binary.BigEndian.Uint32(key[12:16])

	// Initial transformation (FK)
	mk[0] ^= 0xa3b1bac6
	mk[1] ^= 0x56aa3350
	mk[2] ^= 0x677d9197
	mk[3] ^= 0xb27022dc

	// Generate round keys
	for i := 0; i < 32; i++ {
		temp := mk[1] ^ mk[2] ^ mk[3] ^ ck[i]
		temp = sBoxTransform(temp)
		mk[0] ^= lPrimeTransform(temp)
		rk[i] = mk[0]
		// Rotate the registers
		mk[0], mk[1], mk[2], mk[3] = mk[1], mk[2], mk[3], mk[0]
	}

	return rk
}

func encrypt(x *[4]uint32, key *[KeySize]byte) {
	rk := expandKey(key)

	// 32 rounds of encryption
	for i := 0; i < 32; i++ {
		t := x[1] ^ x[2] ^ x[3] ^ rk[i]
		t = lTransform(sBoxTransform(t))
		newVal := x[0] ^ t
		// Shift window and append new value
		x[0], x[1], x[2], x[3] = x[1], x[2], x[3], newVal
	}

	// Final swap
	x[0], x[3] = x[3], x[0]
	x[1], x[2] = x[2], x[1]
}

func decrypt(x *[4]uint32, key *[KeySize]byte) {
	rk := expandKey(key)

	// 32 rounds of decryption (using round keys in reverse order)
	for i := 31; i >= 0; i-- {
		t := x[1] ^ x[2] ^ x[3] ^ rk[i]
		t = lTransform(sBoxTransform(t))
		newVal := x[0] ^ t
		// Shift window and append new value
		x[0], x[1], x[2], x[3] = x[1], x[2], x[3], newVal
	}

	// Final swap
	x[0], x[3] = x[3], x[0]
	x[1], x[2] = x[2], x[1]
}
