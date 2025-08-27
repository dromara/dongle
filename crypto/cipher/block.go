package cipher

import (
	"crypto/cipher"
)

// BlockMode represents the different block cipher modes of operation
type BlockMode string

// Supported block cipher modes
const (
	CBC BlockMode = "CBC" // Cipher Block Chaining mode
	ECB BlockMode = "ECB" // Electronic Codebook mode
	CTR BlockMode = "CTR" // Counter mode
	GCM BlockMode = "GCM" // Galois/Counter Mode
	CFB BlockMode = "CFB" // Cipher Feedback mode
	OFB BlockMode = "OFB" // Output Feedback mode
)

// newCBCEncrypter encrypts data using Cipher Block Chaining (CBC) mode.
// CBC mode encrypts each block of plaintext by XORing it with the previous
// ciphertext block before applying the block cipher algorithm.
func newCBCEncrypter(src, iv []byte, block cipher.Block) (dst []byte, err error) {
	// Note: Empty src should have been padded before reaching this function
	// So we don't need to check for empty src here

	if len(iv) == 0 {
		return nil, EmptyIVError{mode: CBC}
	}

	if block == nil {
		return nil, NilBlockError{mode: CBC}
	}

	blockSize := block.BlockSize()
	if len(iv) != blockSize {
		return nil, InvalidIVError{mode: CBC, iv: iv, size: blockSize}
	}

	if len(src)%blockSize != 0 {
		return nil, InvalidSrcError{mode: CBC, src: src, size: blockSize}
	}

	// Perform CBC encryption using the standard library implementation
	dst = make([]byte, len(src))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(dst, src)
	return dst, nil
}

// newCBCDecrypter decrypts data using Cipher Block Chaining (CBC) mode.
// CBC decryption reverses the encryption process by applying the block cipher
// and then XORing with the previous ciphertext block.
func newCBCDecrypter(src, iv []byte, block cipher.Block) (dst []byte, err error) {
	// Validate input parameters
	// Note: Empty src should have been padded before reaching this function
	// So we don't need to check for empty src here

	if len(iv) == 0 {
		return nil, EmptyIVError{mode: CBC}
	}

	if block == nil {
		return nil, NilBlockError{mode: CBC}
	}

	blockSize := block.BlockSize()
	if len(iv) != blockSize {
		return nil, InvalidIVError{mode: CBC, iv: iv, size: blockSize}
	}

	if len(src)%blockSize != 0 {
		return nil, InvalidSrcError{mode: CBC, src: src, size: blockSize}
	}

	// Perform CBC decryption using the standard library implementation
	dst = make([]byte, len(src))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(dst, src)
	return dst, nil
}

// newCTREncrypter encrypts data using Counter (CTR) mode.
// CTR mode transforms a block cipher into a stream cipher by encrypting
// a counter value and XORing the result with the plaintext.
func newCTREncrypter(src, iv []byte, block cipher.Block) (dst []byte, err error) {
	// Validate input parameters
	// Note: Empty src should have been padded before reaching this function
	// So we don't need to check for empty src here

	if len(iv) == 0 {
		return nil, EmptyIVError{mode: CTR}
	}

	if block == nil {
		return nil, NilBlockError{mode: CTR}
	}

	// Handle nonce for CTR mode
	// If IV is 12 bytes (nonce), pad it to 16 bytes with zeros
	// This matches Python's pycryptodome behavior
	ctrIV := iv
	if len(iv) == 12 {
		ctrIV = make([]byte, 16)
		copy(ctrIV, iv)
		// The remaining 4 bytes are set to zero (counter starts at 0)
	}

	// Perform CTR encryption using the standard library implementation
	dst = make([]byte, len(src))
	cipher.NewCTR(block, ctrIV).XORKeyStream(dst, src)
	return dst, nil
}

// newCTRDecrypter decrypts data using Counter (CTR) mode.
// In CTR mode, decryption is identical to encryption since it's a stream cipher.
func newCTRDecrypter(src, iv []byte, block cipher.Block) (dst []byte, err error) {
	// Validate input parameters
	// Note: Empty src should have been padded before reaching this function
	// So we don't need to check for empty src here

	if len(iv) == 0 {
		return nil, EmptyIVError{mode: CTR}
	}

	if block == nil {
		return nil, NilBlockError{mode: CTR}
	}

	// Handle nonce for CTR mode
	// If IV is 12 bytes (nonce), pad it to 16 bytes with zeros
	// This matches Python's pycryptodome behavior
	ctrIV := iv
	if len(iv) == 12 {
		ctrIV = make([]byte, 16)
		copy(ctrIV, iv)
		// The remaining 4 bytes are set to zero (counter starts at 0)
	}

	// Perform CTR decryption using the standard library implementation
	dst = make([]byte, len(src))
	cipher.NewCTR(block, ctrIV).XORKeyStream(dst, src)
	return dst, nil
}

// newECBEncrypter encrypts data using Electronic Codebook (ECB) mode.
// ECB mode encrypts each block of plaintext independently using the same key.
// Note: ECB mode is generally not recommended for secure applications due to
// its vulnerability to pattern analysis.
func newECBEncrypter(src []byte, block cipher.Block) (dst []byte, err error) {
	// Validate input parameters
	// Note: Empty src should have been padded before reaching this function
	// So we don't need to check for empty src here

	if block == nil {
		return nil, NilBlockError{mode: ECB}
	}

	blockSize := block.BlockSize()
	if len(src)%blockSize != 0 {
		return nil, InvalidSrcError{mode: ECB, src: src, size: blockSize}
	}

	// Perform ECB encryption - encrypt each block independently
	dst = make([]byte, len(src))
	for i := 0; i < len(src); i += blockSize {
		block.Encrypt(dst[i:i+blockSize], src[i:i+blockSize])
	}
	return dst, nil
}

// newECBDecrypter decrypts data using Electronic Codebook (ECB) mode.
// ECB decryption decrypts each block independently.
func newECBDecrypter(src []byte, block cipher.Block) (dst []byte, err error) {
	// Validate input parameters
	// Note: Empty src should have been padded before reaching this function
	// So we don't need to check for empty src here

	if block == nil {
		return nil, NilBlockError{mode: ECB}
	}

	blockSize := block.BlockSize()
	if len(src)%blockSize != 0 {
		return nil, InvalidSrcError{mode: ECB, src: src, size: blockSize}
	}

	// Perform ECB decryption - decrypt each block independently
	dst = make([]byte, len(src))
	for i := 0; i < len(src); i += blockSize {
		block.Decrypt(dst[i:i+blockSize], src[i:i+blockSize])
	}
	return dst, nil
}

// newGCMEncrypter encrypts data using Galois/Counter Mode (GCM).
// GCM is an authenticated encryption mode that provides both confidentiality
// and authenticity. It combines CTR mode encryption with a Galois field
// multiplication for authentication.
func newGCMEncrypter(src, nonce, aad []byte, block cipher.Block) (dst []byte, err error) {
	// Validate input parameters
	// Note: Empty src should have been padded before reaching this function
	// So we don't need to check for empty src here

	if block == nil {
		return nil, NilBlockError{mode: GCM}
	}

	if len(nonce) == 0 {
		return nil, EmptyNonceError{mode: GCM}
	}

	// Create GCM cipher from the underlying block cipher
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, CreateCipherError{mode: GCM, err: err}
	}

	// Perform GCM encryption with authentication
	dst = gcm.Seal(nil, nonce, src, aad)
	return dst, nil
}

// newGCMDecrypter decrypts data using Galois/Counter Mode (GCM).
// GCM decryption verifies the authentication tag before decrypting the data.
func newGCMDecrypter(src, nonce, aad []byte, block cipher.Block) (dst []byte, err error) {
	// Validate input parameters
	// Note: Empty src should have been padded before reaching this function
	// So we don't need to check for empty src here

	if block == nil {
		return nil, NilBlockError{mode: GCM}
	}

	if len(nonce) == 0 {
		return nil, EmptyNonceError{mode: GCM}
	}

	// Create GCM cipher from the underlying block cipher
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, CreateCipherError{mode: GCM, err: err}
	}

	// Perform GCM decryption with authentication verification
	dst, err = gcm.Open(nil, nonce, src, aad)
	if err != nil {
		return nil, CreateCipherError{mode: GCM, err: err}
	}

	return dst, nil
}

// newCFBEncrypter encrypts data using Cipher Feedback (CFB) mode.
// CFB mode transforms a block cipher into a stream cipher by encrypting
// the previous ciphertext block and XORing the result with the plaintext.
func newCFBEncrypter(src, iv []byte, block cipher.Block) (dst []byte, err error) {
	// Validate input parameters
	// Note: Empty src should have been padded before reaching this function
	// So we don't need to check for empty src here

	if len(iv) == 0 {
		return nil, EmptyIVError{mode: CFB}
	}

	if block == nil {
		return nil, NilBlockError{mode: CFB}
	}

	blockSize := block.BlockSize()
	if len(iv) != blockSize {
		return nil, InvalidIVError{mode: CFB, iv: iv, size: blockSize}
	}

	// CFB mode doesn't require source data to be a multiple of block size
	// It can handle any data length

	// Perform CFB encryption using the standard library implementation
	dst = make([]byte, len(src))
	cipher.NewCFBEncrypter(block, iv).XORKeyStream(dst, src)
	return dst, nil
}

// newCFBDecrypter decrypts data using Cipher Feedback (CFB) mode.
// In CFB mode, decryption is identical to encryption since it's a stream cipher.
func newCFBDecrypter(src, iv []byte, block cipher.Block) (dst []byte, err error) {
	// Validate input parameters
	// Note: Empty src should have been padded before reaching this function
	// So we don't need to check for empty src here

	if len(iv) == 0 {
		return nil, EmptyIVError{mode: CFB}
	}

	if block == nil {
		return nil, NilBlockError{mode: CFB}
	}

	blockSize := block.BlockSize()
	if len(iv) != blockSize {
		return nil, InvalidIVError{mode: CFB, iv: iv, size: blockSize}
	}

	// CFB mode doesn't require source data to be a multiple of block size
	// It can handle any data length

	// Perform CFB decryption using the standard library implementation
	dst = make([]byte, len(src))
	cipher.NewCFBDecrypter(block, iv).XORKeyStream(dst, src)
	return dst, nil
}

// newOFBEncrypter encrypts data using Output Feedback (OFB) mode.
// OFB mode transforms a block cipher into a stream cipher by repeatedly
// encrypting the initialization vector and using the output as a keystream.
func newOFBEncrypter(src, iv []byte, block cipher.Block) (dst []byte, err error) {
	// Validate input parameters
	// Note: Empty src should have been padded before reaching this function
	// So we don't need to check for empty src here

	if len(iv) == 0 {
		return nil, EmptyIVError{mode: OFB}
	}

	if block == nil {
		return nil, NilBlockError{mode: OFB}
	}

	blockSize := block.BlockSize()
	if len(iv) != blockSize {
		return nil, InvalidIVError{mode: OFB, iv: iv, size: blockSize}
	}

	// OFB mode doesn't require source data to be a multiple of block size
	// It can handle any data length

	// Perform OFB encryption using the standard library implementation
	dst = make([]byte, len(src))
	cipher.NewOFB(block, iv).XORKeyStream(dst, src)
	return dst, nil
}

// newOFBDecrypter decrypts data using Output Feedback (OFB) mode.
// In OFB mode, decryption is identical to encryption since it's a stream cipher.
func newOFBDecrypter(src, iv []byte, block cipher.Block) (dst []byte, err error) {
	// Validate input parameters
	// Note: Empty src should have been padded before reaching this function
	// So we don't need to check for empty src here

	if len(iv) == 0 {
		return nil, EmptyIVError{mode: OFB}
	}

	if block == nil {
		return nil, NilBlockError{mode: OFB}
	}

	blockSize := block.BlockSize()
	if len(iv) != blockSize {
		return nil, InvalidIVError{mode: OFB, iv: iv, size: blockSize}
	}

	// OFB mode doesn't require source data to be a multiple of block size
	// It can handle any data length

	// Perform OFB decryption using the standard library implementation
	dst = make([]byte, len(src))
	cipher.NewOFB(block, iv).XORKeyStream(dst, src)
	return dst, nil
}
