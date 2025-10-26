package cipher

import (
	"crypto/cipher"
)

// BlockMode defines a BlockMode type.
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

// NewCBCEncrypter encrypts data using Cipher Block Chaining (CBC) mode.
// CBC mode encrypts each block of plaintext by XORing it with the previous
// ciphertext block before applying the block cipher algorithm.
func NewCBCEncrypter(src, iv []byte, block cipher.Block) (dst []byte, err error) {
	blockSize := block.BlockSize()
	if len(src)%blockSize != 0 {
		return dst, InvalidPlaintextError{mode: CBC, src: src, size: blockSize}
	}
	if len(iv) == 0 {
		return dst, EmptyIVError{mode: CBC}
	}
	if len(iv) != blockSize {
		return dst, InvalidIVError{mode: CBC, iv: iv, size: blockSize}
	}

	// Perform CBC encryption using the standard library implementation
	dst = make([]byte, len(src))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(dst, src)
	return
}

// NewCBCDecrypter decrypts data using Cipher Block Chaining (CBC) mode.
// CBC decryption reverses the encryption process by applying the block cipher
// and then XORing with the previous ciphertext block.
func NewCBCDecrypter(src, iv []byte, block cipher.Block) (dst []byte, err error) {
	blockSize := block.BlockSize()
	if len(src)%blockSize != 0 {
		return dst, InvalidCiphertextError{mode: CBC, src: src, size: blockSize}
	}
	if len(iv) == 0 {
		return dst, EmptyIVError{mode: CBC}
	}
	if len(iv) != blockSize {
		return dst, InvalidIVError{mode: CBC, iv: iv, size: blockSize}
	}

	// Perform CBC decryption using the standard library implementation
	dst = make([]byte, len(src))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(dst, src)
	return
}

// NewECBEncrypter encrypts data using Electronic Codebook (ECB) mode.
// ECB mode encrypts each block of plaintext independently using the same key.
// Note: ECB mode is generally not recommended for secure applications due to
// its vulnerability to pattern analysis.
func NewECBEncrypter(src []byte, block cipher.Block) (dst []byte, err error) {
	blockSize := block.BlockSize()
	if len(src)%blockSize != 0 {
		return dst, InvalidPlaintextError{mode: ECB, src: src, size: blockSize}
	}

	// Perform ECB encryption - encrypt each block independently
	dst = make([]byte, len(src))
	for i := 0; i < len(src); i += blockSize {
		block.Encrypt(dst[i:i+blockSize], src[i:i+blockSize])
	}
	return
}

// NewECBDecrypter decrypts data using Electronic Codebook (ECB) mode.
// ECB decryption decrypts each block independently.
func NewECBDecrypter(src []byte, block cipher.Block) (dst []byte, err error) {
	blockSize := block.BlockSize()
	if len(src)%blockSize != 0 {
		return dst, InvalidCiphertextError{mode: ECB, src: src, size: blockSize}
	}

	// Perform ECB decryption - decrypt each block independently
	dst = make([]byte, len(src))
	for i := 0; i < len(src); i += blockSize {
		block.Decrypt(dst[i:i+blockSize], src[i:i+blockSize])
	}
	return
}

// NewCTREncrypter encrypts data using Counter (CTR) mode.
// CTR mode transforms a block cipher into a stream cipher by encrypting
// a counter value and XORing the result with the plaintext.
func NewCTREncrypter(src, iv []byte, block cipher.Block) (dst []byte, err error) {
	if len(iv) == 0 {
		return dst, EmptyIVError{mode: CTR}
	}

	blockSize := block.BlockSize()
	if len(iv) != blockSize {
		return dst, InvalidIVError{mode: CTR, iv: iv, size: blockSize}
	}

	// Perform CTR encryption using the standard library implementation
	dst = make([]byte, len(src))
	cipher.NewCTR(block, iv).XORKeyStream(dst, src)
	return
}

// NewCTRDecrypter decrypts data using Counter (CTR) mode.
// In CTR mode, decryption is identical to encryption since it's a stream cipher.
func NewCTRDecrypter(src, iv []byte, block cipher.Block) (dst []byte, err error) {
	if len(iv) == 0 {
		return dst, EmptyIVError{mode: CTR}
	}

	blockSize := block.BlockSize()
	if len(iv) != blockSize {
		return dst, InvalidIVError{mode: CTR, iv: iv, size: blockSize}
	}

	// Perform CTR decryption using the standard library implementation
	dst = make([]byte, len(src))
	cipher.NewCTR(block, iv).XORKeyStream(dst, src)
	return
}

// NewGCMEncrypter encrypts data using Galois/Counter Mode (GCM).
// GCM is an authenticated encryption mode that provides both confidentiality
// and authenticity. It combines CTR mode encryption with a Galois field
// multiplication for authentication.
func NewGCMEncrypter(src, nonce, aad []byte, block cipher.Block) (dst []byte, err error) {
	if len(nonce) == 0 {
		return dst, EmptyNonceError{mode: GCM}
	}

	// Create GCM cipher from the underlying block cipher
	var gcm cipher.AEAD
	if len(nonce) == 12 {
		// Use standard GCM for 12-byte nonce (optimal performance)
		gcm, err = cipher.NewGCM(block)
	} else {
		// Use custom nonce size for other lengths
		gcm, err = cipher.NewGCMWithNonceSize(block, len(nonce))
	}
	if err != nil {
		return dst, CreateCipherError{mode: GCM, err: err}
	}

	// Perform GCM encryption with authentication
	dst = gcm.Seal(nil, nonce, src, aad)
	return
}

// NewGCMDecrypter decrypts data using Galois/Counter Mode (GCM).
// GCM decryption verifies the authentication tag before decrypting the data.
func NewGCMDecrypter(src, nonce, aad []byte, block cipher.Block) (dst []byte, err error) {
	if len(nonce) == 0 {
		return dst, EmptyNonceError{mode: GCM}
	}

	// Create GCM cipher from the underlying block cipher
	var gcm cipher.AEAD
	if len(nonce) == 12 {
		// Use standard GCM for 12-byte nonce (optimal performance)
		gcm, err = cipher.NewGCM(block)
	} else {
		// Use custom nonce size for other lengths
		gcm, err = cipher.NewGCMWithNonceSize(block, len(nonce))
	}
	if err != nil {
		return dst, CreateCipherError{mode: GCM, err: err}
	}

	// Perform GCM decryption with authentication verification
	return gcm.Open(nil, nonce, src, aad)
}

// NewCFBEncrypter encrypts data using Cipher Feedback (CFB) mode.
// CFB mode transforms a block cipher into a stream cipher by encrypting
// the previous ciphertext block and XORing the result with the plaintext.
func NewCFBEncrypter(src, iv []byte, block cipher.Block) (dst []byte, err error) {
	if len(iv) == 0 {
		return dst, EmptyIVError{mode: CFB}
	}

	blockSize := block.BlockSize()
	if len(iv) != blockSize {
		return dst, InvalidIVError{mode: CFB, iv: iv, size: blockSize}
	}

	// Perform CFB encryption using the standard library implementation
	dst = make([]byte, len(src))
	cipher.NewCFBEncrypter(block, iv).XORKeyStream(dst, src)
	return
}

// NewCFBDecrypter decrypts data using Cipher Feedback (CFB) mode.
// In CFB mode, decryption is identical to encryption since it's a stream cipher.
func NewCFBDecrypter(src, iv []byte, block cipher.Block) (dst []byte, err error) {
	if len(iv) == 0 {
		return dst, EmptyIVError{mode: CFB}
	}

	blockSize := block.BlockSize()
	if len(iv) != blockSize {
		return dst, InvalidIVError{mode: CFB, iv: iv, size: blockSize}
	}

	// Perform CFB decryption using the standard library implementation
	dst = make([]byte, len(src))
	cipher.NewCFBDecrypter(block, iv).XORKeyStream(dst, src)
	return
}

// NewOFBEncrypter encrypts data using Output Feedback (OFB) mode.
// OFB mode transforms a block cipher into a stream cipher by repeatedly
// encrypting the initialization vector and using the output as a keystream.
func NewOFBEncrypter(src, iv []byte, block cipher.Block) (dst []byte, err error) {
	if len(iv) == 0 {
		return dst, EmptyIVError{mode: OFB}
	}

	blockSize := block.BlockSize()
	if len(iv) != blockSize {
		return dst, InvalidIVError{mode: OFB, iv: iv, size: blockSize}
	}

	// Perform OFB encryption using the standard library implementation
	dst = make([]byte, len(src))
	cipher.NewOFB(block, iv).XORKeyStream(dst, src)
	return
}

// NewOFBDecrypter decrypts data using Output Feedback (OFB) mode.
// In OFB mode, decryption is identical to encryption since it's a stream cipher.
func NewOFBDecrypter(src, iv []byte, block cipher.Block) (dst []byte, err error) {
	if len(iv) == 0 {
		return dst, EmptyIVError{mode: OFB}
	}

	blockSize := block.BlockSize()
	if len(iv) != blockSize {
		return dst, InvalidIVError{mode: OFB, iv: iv, size: blockSize}
	}

	// Perform OFB decryption using the standard library implementation
	dst = make([]byte, len(src))
	cipher.NewOFB(block, iv).XORKeyStream(dst, src)
	return
}
