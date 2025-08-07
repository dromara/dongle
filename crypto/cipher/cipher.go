// Package cipher provides implementations of various block cipher modes of operation
// including CBC, CTR, ECB, GCM, OFB, and CFB. Each cipher mode implements the
// CipherInterface for consistent encryption and decryption operations.
package cipher

import (
	"crypto/cipher"
)

// CBCCipher implements Cipher Block Chaining (CBC) mode of operation.
// CBC mode encrypts each block of plaintext by XORing it with the previous
// ciphertext block before applying the block cipher algorithm.
type CBCCipher struct {
	padding PaddingMode // The padding mode used for data that doesn't fit block boundaries
	key     []byte      // The encryption/decryption key
	iv      []byte      // Initialization vector for CBC mode
}

// NewCBCCipher creates a new CBC cipher instance with PKCS7 padding as default
func NewCBCCipher() *CBCCipher {
	return &CBCCipher{
		padding: PKCS7,
	}
}

// SetPadding sets the padding mode for the CBC cipher
func (c *CBCCipher) SetPadding(padding PaddingMode) {
	c.padding = padding
}

// SetKey sets the encryption/decryption key for the CBC cipher
func (c *CBCCipher) SetKey(key []byte) {
	c.key = key
}

// GetKey returns the current encryption/decryption key
func (c *CBCCipher) GetKey() []byte {
	return c.key
}

// SetIV sets the initialization vector for CBC mode
func (c *CBCCipher) SetIV(iv []byte) {
	c.iv = iv
}

// Encrypt encrypts the source data using CBC mode with the specified block cipher.
// The data is first padded according to the padding mode, then encrypted using
// CBC mode with the initialization vector.
func (c *CBCCipher) Encrypt(src []byte, cipherBlock cipher.Block) (dst []byte, err error) {
	blockSize := cipherBlock.BlockSize()

	src = padding(src, c.padding, blockSize)

	if len(src)%blockSize != 0 {
		return nil, InvalidSrcError{mode: CBC, src: src, size: blockSize}
	}

	return newCBCEncrypter(src, c.iv, cipherBlock)
}

// Decrypt decrypts the source data using CBC mode with the specified block cipher.
// The data is first decrypted using CBC mode, then unpadded according to the padding mode.
func (c *CBCCipher) Decrypt(src []byte, cipherBlock cipher.Block) (dst []byte, err error) {
	if len(src) == 0 {
		return
	}

	blockSize := cipherBlock.BlockSize()

	if len(src)%blockSize != 0 {
		return nil, InvalidSrcError{mode: CBC, src: src, size: blockSize}
	}

	dst, err = newCBCDecrypter(src, c.iv, cipherBlock)
	if err != nil {
		return
	}
	// Remove padding from decrypted data
	dst = unpadding(dst, c.padding)
	return
}

// CTRCipher implements Counter (CTR) mode of operation.
// CTR mode transforms a block cipher into a stream cipher by encrypting
// a counter value and XORing the result with the plaintext.
type CTRCipher struct {
	key []byte // The encryption/decryption key
	iv  []byte // Initialization vector (nonce) for CTR mode
}

// NewCTRCipher creates a new CTR cipher instance
func NewCTRCipher() *CTRCipher {
	return &CTRCipher{}
}

// SetKey sets the encryption/decryption key for the CTR cipher
func (c *CTRCipher) SetKey(key []byte) {
	c.key = key
}

// GetKey returns the current encryption/decryption key
func (c *CTRCipher) GetKey() []byte {
	return c.key
}

// SetIV sets the initialization vector (nonce) for CTR mode
func (c *CTRCipher) SetIV(iv []byte) {
	c.iv = iv
}

// Encrypt encrypts the source data using CTR mode with the specified block cipher.
// CTR mode doesn't require padding as it operates as a stream cipher.
func (c *CTRCipher) Encrypt(src []byte, cipherBlock cipher.Block) (dst []byte, err error) {
	if len(src) == 0 {
		return
	}
	return newCTREncrypter(src, c.iv, cipherBlock)
}

// Decrypt decrypts the source data using CTR mode with the specified block cipher.
// In CTR mode, decryption is identical to encryption.
func (c *CTRCipher) Decrypt(src []byte, cipherBlock cipher.Block) (dst []byte, err error) {
	if len(src) == 0 {
		return
	}
	return newCTRDecrypter(src, c.iv, cipherBlock)
}

// ECBCipher implements Electronic Codebook (ECB) mode of operation.
// ECB mode encrypts each block of plaintext independently using the same key.
// Note: ECB mode is generally not recommended for secure applications due to
// its vulnerability to pattern analysis.
type ECBCipher struct {
	padding PaddingMode // The padding mode used for data that doesn't fit block boundaries
	key     []byte      // The encryption/decryption key
}

// NewECBCipher creates a new ECB cipher instance with PKCS7 padding as default
func NewECBCipher() *ECBCipher {
	return &ECBCipher{
		padding: PKCS7,
	}
}

// SetPadding sets the padding mode for the ECB cipher
func (c *ECBCipher) SetPadding(padding PaddingMode) {
	c.padding = padding
}

// SetKey sets the encryption/decryption key for the ECB cipher
func (c *ECBCipher) SetKey(key []byte) {
	c.key = key
}

// GetKey returns the current encryption/decryption key
func (c *ECBCipher) GetKey() []byte {
	return c.key
}

// Encrypt encrypts the source data using ECB mode with the specified block cipher.
// The data is first padded according to the padding mode, then each block is
// encrypted independently.
func (c *ECBCipher) Encrypt(src []byte, cipherBlock cipher.Block) (dst []byte, err error) {
	blockSize := cipherBlock.BlockSize()
	// Apply padding to ensure data length is a multiple of block size
	src = padding(src, c.padding, blockSize)
	if len(src)%blockSize != 0 {
		return nil, InvalidSrcError{mode: ECB, src: src, size: blockSize}
	}
	return newECBEncrypter(src, cipherBlock)
}

// Decrypt decrypts the source data using ECB mode with the specified block cipher.
// Each block is decrypted independently, then padding is removed.
func (c *ECBCipher) Decrypt(src []byte, cipherBlock cipher.Block) (dst []byte, err error) {
	if len(src) == 0 {
		return
	}
	blockSize := cipherBlock.BlockSize()
	if len(src)%blockSize != 0 {
		return nil, InvalidSrcError{mode: ECB, src: src, size: blockSize}
	}
	dst, err = newECBDecrypter(src, cipherBlock)
	// Remove padding from decrypted data
	dst = unpadding(dst, c.padding)
	return
}

// GCMCipher implements Galois/Counter Mode (GCM) of operation.
// GCM is an authenticated encryption mode that provides both confidentiality
// and authenticity. It combines CTR mode encryption with a Galois field
// multiplication for authentication.
type GCMCipher struct {
	key   []byte // The encryption/decryption key
	nonce []byte // Nonce (number used once) for GCM mode
	aad   []byte // Additional authenticated data
}

// NewGCMCipher creates a new GCM cipher instance
func NewGCMCipher() *GCMCipher {
	return &GCMCipher{}
}

// SetKey sets the encryption/decryption key for the GCM cipher
func (c *GCMCipher) SetKey(key []byte) {
	c.key = key
}

// GetKey returns the current encryption/decryption key
func (c *GCMCipher) GetKey() []byte {
	return c.key
}

// SetNonce sets the nonce (number used once) for GCM mode
func (c *GCMCipher) SetNonce(nonce []byte) {
	c.nonce = nonce
}

// SetAAD sets the additional authenticated data for GCM mode
func (c *GCMCipher) SetAAD(aad []byte) {
	c.aad = aad
}

// Encrypt encrypts the source data using GCM mode with the specified block cipher.
// GCM provides both encryption and authentication in a single operation.
func (c *GCMCipher) Encrypt(src []byte, cipherBlock cipher.Block) (dst []byte, err error) {
	return newGCMEncrypter(src, c.nonce, c.aad, cipherBlock)
}

// Decrypt decrypts the source data using GCM mode with the specified block cipher.
// GCM verifies the authentication tag during decryption.
func (c *GCMCipher) Decrypt(src []byte, cipherBlock cipher.Block) (dst []byte, err error) {
	if len(src) == 0 {
		return
	}
	return newGCMDecrypter(src, c.nonce, c.aad, cipherBlock)
}

// OFBCipher implements Output Feedback (OFB) mode of operation.
// OFB mode transforms a block cipher into a stream cipher by repeatedly
// encrypting the initialization vector and using the output as a keystream.
type OFBCipher struct {
	key []byte // The encryption/decryption key
	iv  []byte // Initialization vector for OFB mode
}

// NewOFBCipher creates a new OFB cipher instance
func NewOFBCipher() *OFBCipher {
	return &OFBCipher{}
}

// SetKey sets the encryption/decryption key for the OFB cipher
func (c *OFBCipher) SetKey(key []byte) {
	c.key = key
}

// GetKey returns the current encryption/decryption key
func (c *OFBCipher) GetKey() []byte {
	return c.key
}

// SetIV sets the initialization vector for OFB mode
func (c *OFBCipher) SetIV(iv []byte) {
	c.iv = iv
}

// Encrypt encrypts the source data using OFB mode with the specified block cipher.
// OFB mode doesn't require padding as it operates as a stream cipher.
func (c *OFBCipher) Encrypt(src []byte, cipherBlock cipher.Block) (dst []byte, err error) {
	if len(src) == 0 {
		return
	}
	return newOFBEncrypter(src, c.iv, cipherBlock)
}

// Decrypt decrypts the source data using OFB mode with the specified block cipher.
// In OFB mode, decryption is identical to encryption.
func (c *OFBCipher) Decrypt(src []byte, cipherBlock cipher.Block) (dst []byte, err error) {
	if len(src) == 0 {
		return
	}
	return newOFBDecrypter(src, c.iv, cipherBlock)
}

// CFBCipher implements Cipher Feedback (CFB) mode of operation.
// CFB mode transforms a block cipher into a stream cipher by encrypting
// the previous ciphertext block and XORing the result with the plaintext.
type CFBCipher struct {
	key []byte // The encryption/decryption key
	iv  []byte // Initialization vector for CFB mode
}

// NewCFBCipher creates a new CFB cipher instance
func NewCFBCipher() *CFBCipher {
	return &CFBCipher{}
}

// SetKey sets the encryption/decryption key for the CFB cipher
func (c *CFBCipher) SetKey(key []byte) {
	c.key = key
}

// GetKey returns the current encryption/decryption key
func (c *CFBCipher) GetKey() []byte {
	return c.key
}

// SetIV sets the initialization vector for CFB mode
func (c *CFBCipher) SetIV(iv []byte) {
	c.iv = iv
}

// Encrypt encrypts the source data using CFB mode with the specified block cipher.
// CFB mode doesn't require padding as it operates as a stream cipher.
func (c *CFBCipher) Encrypt(src []byte, cipherBlock cipher.Block) (dst []byte, err error) {
	if len(src) == 0 {
		return
	}
	return newCFBEncrypter(src, c.iv, cipherBlock)
}

// Decrypt decrypts the source data using CFB mode with the specified block cipher.
// In CFB mode, decryption is identical to encryption.
func (c *CFBCipher) Decrypt(src []byte, cipherBlock cipher.Block) (dst []byte, err error) {
	if len(src) == 0 {
		return
	}
	return newCFBDecrypter(src, c.iv, cipherBlock)
}
