package cipher

import (
	"crypto/aes"
	stdcipher "crypto/cipher"
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestCBCMode tests CBC (Cipher Block Chaining) mode encryption and decryption
func TestCBCMode(t *testing.T) {
	t.Run("CBC encryption success", func(t *testing.T) {
		block, err := aes.NewCipher([]byte("1234567890123456"))
		assert.Nil(t, err)

		plaintext := []byte("Hello, World! This is a test message for CBC mode.")
		iv := make([]byte, aes.BlockSize)
		_, err = rand.Read(iv)
		assert.Nil(t, err)

		// Pad plaintext to block size
		paddedText := padToBlockSize(plaintext, aes.BlockSize)

		encrypted, err := newCBCEncrypter(paddedText, iv, block)
		assert.Nil(t, err)
		assert.NotNil(t, encrypted)
		assert.Equal(t, len(paddedText), len(encrypted))
	})

	t.Run("CBC decryption success", func(t *testing.T) {
		block, err := aes.NewCipher([]byte("1234567890123456"))
		assert.Nil(t, err)

		plaintext := []byte("Hello, World! This is a test message for CBC mode.")
		iv := make([]byte, aes.BlockSize)
		_, err = rand.Read(iv)
		assert.Nil(t, err)

		// Pad plaintext to block size
		paddedText := padToBlockSize(plaintext, aes.BlockSize)

		encrypted, err := newCBCEncrypter(paddedText, iv, block)
		assert.Nil(t, err)

		decrypted, err := newCBCDecrypter(encrypted, iv, block)
		assert.Nil(t, err)
		assert.Equal(t, paddedText, decrypted)
	})

	t.Run("CBC encryption with empty IV", func(t *testing.T) {
		block, err := aes.NewCipher([]byte("1234567890123456"))
		assert.Nil(t, err)

		plaintext := []byte("Hello, World!")
		paddedText := padToBlockSize(plaintext, aes.BlockSize)

		_, err = newCBCEncrypter(paddedText, []byte{}, block)
		assert.Error(t, err)
		assert.IsType(t, EmptyIVError{}, err)
	})

	t.Run("CBC encryption with nil block", func(t *testing.T) {
		plaintext := []byte("Hello, World!")
		paddedText := padToBlockSize(plaintext, aes.BlockSize)
		iv := make([]byte, aes.BlockSize)

		_, err := newCBCEncrypter(paddedText, iv, nil)
		assert.Error(t, err)
		assert.IsType(t, NilBlockError{}, err)
	})

	t.Run("CBC encryption with invalid IV length", func(t *testing.T) {
		block, err := aes.NewCipher([]byte("1234567890123456"))
		assert.Nil(t, err)

		plaintext := []byte("Hello, World!")
		paddedText := padToBlockSize(plaintext, aes.BlockSize)
		iv := []byte("short") // Too short

		_, err = newCBCEncrypter(paddedText, iv, block)
		assert.Error(t, err)
		assert.IsType(t, InvalidIVError{}, err)
	})

	t.Run("CBC encryption with invalid source length", func(t *testing.T) {
		block, err := aes.NewCipher([]byte("1234567890123456"))
		assert.Nil(t, err)

		plaintext := []byte("Hello") // Not padded to block size
		iv := make([]byte, aes.BlockSize)

		_, err = newCBCEncrypter(plaintext, iv, block)
		assert.Error(t, err)
		assert.IsType(t, InvalidSrcError{}, err)
	})

	t.Run("CBC decryption with empty IV", func(t *testing.T) {
		block, err := aes.NewCipher([]byte("1234567890123456"))
		assert.Nil(t, err)

		plaintext := []byte("Hello, World!")
		paddedText := padToBlockSize(plaintext, aes.BlockSize)

		_, err = newCBCDecrypter(paddedText, []byte{}, block)
		assert.Error(t, err)
		assert.IsType(t, EmptyIVError{}, err)
	})

	t.Run("CBC decryption with nil block", func(t *testing.T) {
		plaintext := []byte("Hello, World!")
		paddedText := padToBlockSize(plaintext, aes.BlockSize)
		iv := make([]byte, aes.BlockSize)

		_, err := newCBCDecrypter(paddedText, iv, nil)
		assert.Error(t, err)
		assert.IsType(t, NilBlockError{}, err)
	})

	t.Run("CBC decryption with invalid IV length", func(t *testing.T) {
		block, err := aes.NewCipher([]byte("1234567890123456"))
		assert.Nil(t, err)

		plaintext := []byte("Hello, World!")
		paddedText := padToBlockSize(plaintext, aes.BlockSize)
		iv := []byte("short") // Too short

		_, err = newCBCDecrypter(paddedText, iv, block)
		assert.Error(t, err)
		assert.IsType(t, InvalidIVError{}, err)
	})

	t.Run("CBC decryption with invalid source length", func(t *testing.T) {
		block, err := aes.NewCipher([]byte("1234567890123456"))
		assert.Nil(t, err)

		plaintext := []byte("Hello") // Not padded to block size
		iv := make([]byte, aes.BlockSize)

		_, err = newCBCDecrypter(plaintext, iv, block)
		assert.Error(t, err)
		assert.IsType(t, InvalidSrcError{}, err)
	})
}

// TestCTRMode tests CTR (Counter) mode encryption and decryption
func TestCTRMode(t *testing.T) {
	t.Run("CTR encryption success", func(t *testing.T) {
		block, err := aes.NewCipher([]byte("1234567890123456"))
		assert.Nil(t, err)

		plaintext := []byte("Hello, World! This is a test message for CTR mode.")
		iv := make([]byte, aes.BlockSize)
		_, err = rand.Read(iv)
		assert.Nil(t, err)

		encrypted, err := newCTREncrypter(plaintext, iv, block)
		assert.Nil(t, err)
		assert.NotNil(t, encrypted)
		assert.Equal(t, len(plaintext), len(encrypted))
	})

	t.Run("CTR decryption success", func(t *testing.T) {
		block, err := aes.NewCipher([]byte("1234567890123456"))
		assert.Nil(t, err)

		plaintext := []byte("Hello, World! This is a test message for CTR mode.")
		iv := make([]byte, aes.BlockSize)
		_, err = rand.Read(iv)
		assert.Nil(t, err)

		encrypted, err := newCTREncrypter(plaintext, iv, block)
		assert.Nil(t, err)

		decrypted, err := newCTRDecrypter(encrypted, iv, block)
		assert.Nil(t, err)
		assert.Equal(t, plaintext, decrypted)
	})

	t.Run("CTR encryption with empty IV", func(t *testing.T) {
		block, err := aes.NewCipher([]byte("1234567890123456"))
		assert.Nil(t, err)

		plaintext := []byte("Hello, World!")

		_, err = newCTREncrypter(plaintext, []byte{}, block)
		assert.Error(t, err)
		assert.IsType(t, EmptyIVError{}, err)
	})

	t.Run("CTR encryption with nil block", func(t *testing.T) {
		plaintext := []byte("Hello, World!")
		iv := make([]byte, aes.BlockSize)

		_, err := newCTREncrypter(plaintext, iv, nil)
		assert.Error(t, err)
		assert.IsType(t, NilBlockError{}, err)
	})

	t.Run("CTR with 12-byte nonce", func(t *testing.T) {
		block, err := aes.NewCipher([]byte("1234567890123456"))
		assert.Nil(t, err)

		plaintext := []byte("Hello, World!")
		nonce := make([]byte, 12) // 12-byte nonce
		_, err = rand.Read(nonce)
		assert.Nil(t, err)

		encrypted, err := newCTREncrypter(plaintext, nonce, block)
		assert.Nil(t, err)
		assert.NotNil(t, encrypted)

		decrypted, err := newCTRDecrypter(encrypted, nonce, block)
		assert.Nil(t, err)
		assert.Equal(t, plaintext, decrypted)
	})

	t.Run("CTR decryption with empty IV", func(t *testing.T) {
		block, err := aes.NewCipher([]byte("1234567890123456"))
		assert.Nil(t, err)

		plaintext := []byte("Hello, World!")

		_, err = newCTRDecrypter(plaintext, []byte{}, block)
		assert.Error(t, err)
		assert.IsType(t, EmptyIVError{}, err)
	})

	t.Run("CTR decryption with nil block", func(t *testing.T) {
		plaintext := []byte("Hello, World!")
		iv := make([]byte, aes.BlockSize)

		_, err := newCTRDecrypter(plaintext, iv, nil)
		assert.Error(t, err)
		assert.IsType(t, NilBlockError{}, err)
	})
}

// TestECBMode tests ECB (Electronic Codebook) mode encryption and decryption
func TestECBMode(t *testing.T) {
	t.Run("ECB encryption success", func(t *testing.T) {
		block, err := aes.NewCipher([]byte("1234567890123456"))
		assert.Nil(t, err)

		plaintext := []byte("Hello, World! This is a test message for ECB mode.")
		paddedText := padToBlockSize(plaintext, aes.BlockSize)

		encrypted, err := newECBEncrypter(paddedText, block)
		assert.Nil(t, err)
		assert.NotNil(t, encrypted)
		assert.Equal(t, len(paddedText), len(encrypted))
	})

	t.Run("ECB decryption success", func(t *testing.T) {
		block, err := aes.NewCipher([]byte("1234567890123456"))
		assert.Nil(t, err)

		plaintext := []byte("Hello, World! This is a test message for ECB mode.")
		paddedText := padToBlockSize(plaintext, aes.BlockSize)

		encrypted, err := newECBEncrypter(paddedText, block)
		assert.Nil(t, err)

		decrypted, err := newECBDecrypter(encrypted, block)
		assert.Nil(t, err)
		assert.Equal(t, paddedText, decrypted)
	})

	t.Run("ECB encryption with nil block", func(t *testing.T) {
		plaintext := []byte("Hello, World!")
		paddedText := padToBlockSize(plaintext, aes.BlockSize)

		_, err := newECBEncrypter(paddedText, nil)
		assert.Error(t, err)
		assert.IsType(t, NilBlockError{}, err)
	})

	t.Run("ECB encryption with invalid source length", func(t *testing.T) {
		block, err := aes.NewCipher([]byte("1234567890123456"))
		assert.Nil(t, err)

		plaintext := []byte("Hello") // Not padded to block size

		_, err = newECBEncrypter(plaintext, block)
		assert.Error(t, err)
		assert.IsType(t, InvalidSrcError{}, err)
	})

	t.Run("ECB decryption with nil block", func(t *testing.T) {
		plaintext := []byte("Hello, World!")
		paddedText := padToBlockSize(plaintext, aes.BlockSize)

		_, err := newECBDecrypter(paddedText, nil)
		assert.Error(t, err)
		assert.IsType(t, NilBlockError{}, err)
	})

	t.Run("ECB decryption with invalid source length", func(t *testing.T) {
		block, err := aes.NewCipher([]byte("1234567890123456"))
		assert.Nil(t, err)

		plaintext := []byte("Hello") // Not padded to block size

		_, err = newECBDecrypter(plaintext, block)
		assert.Error(t, err)
		assert.IsType(t, InvalidSrcError{}, err)
	})
}

// TestGCMMode tests GCM (Galois/Counter Mode) encryption and decryption
func TestGCMMode(t *testing.T) {
	t.Run("GCM encryption success", func(t *testing.T) {
		block, err := aes.NewCipher([]byte("1234567890123456"))
		assert.Nil(t, err)

		plaintext := []byte("Hello, World! This is a test message for GCM mode.")
		nonce := make([]byte, 12) // GCM standard nonce size
		_, err = rand.Read(nonce)
		assert.Nil(t, err)

		aad := []byte("Additional authenticated data")

		encrypted, err := newGCMEncrypter(plaintext, nonce, aad, block)
		assert.Nil(t, err)
		assert.NotNil(t, encrypted)
		assert.Greater(t, len(encrypted), len(plaintext)) // GCM adds authentication tag
	})

	t.Run("GCM decryption success", func(t *testing.T) {
		block, err := aes.NewCipher([]byte("1234567890123456"))
		assert.Nil(t, err)

		plaintext := []byte("Hello, World! This is a test message for GCM mode.")
		nonce := make([]byte, 12)
		_, err = rand.Read(nonce)
		assert.Nil(t, err)

		aad := []byte("Additional authenticated data")

		encrypted, err := newGCMEncrypter(plaintext, nonce, aad, block)
		assert.Nil(t, err)

		decrypted, err := newGCMDecrypter(encrypted, nonce, aad, block)
		assert.Nil(t, err)
		assert.Equal(t, plaintext, decrypted)
	})

	t.Run("GCM encryption with empty nonce", func(t *testing.T) {
		block, err := aes.NewCipher([]byte("1234567890123456"))
		assert.Nil(t, err)

		plaintext := []byte("Hello, World!")
		aad := []byte("AAD")

		_, err = newGCMEncrypter(plaintext, []byte{}, aad, block)
		assert.Error(t, err)
		assert.IsType(t, EmptyNonceError{}, err)
	})

	t.Run("GCM encryption with nil block", func(t *testing.T) {
		plaintext := []byte("Hello, World!")
		nonce := make([]byte, 12)
		aad := []byte("AAD")

		_, err := newGCMEncrypter(plaintext, nonce, aad, nil)
		assert.Error(t, err)
		assert.IsType(t, NilBlockError{}, err)
	})

	t.Run("GCM with empty AAD", func(t *testing.T) {
		block, err := aes.NewCipher([]byte("1234567890123456"))
		assert.Nil(t, err)

		plaintext := []byte("Hello, World!")
		nonce := make([]byte, 12)
		_, err = rand.Read(nonce)
		assert.Nil(t, err)

		encrypted, err := newGCMEncrypter(plaintext, nonce, []byte{}, block)
		assert.Nil(t, err)
		assert.NotNil(t, encrypted)

		decrypted, err := newGCMDecrypter(encrypted, nonce, []byte{}, block)
		assert.Nil(t, err)
		assert.Equal(t, plaintext, decrypted)
	})

	t.Run("GCM decryption with empty nonce", func(t *testing.T) {
		block, err := aes.NewCipher([]byte("1234567890123456"))
		assert.Nil(t, err)

		plaintext := []byte("Hello, World!")
		aad := []byte("AAD")

		_, err = newGCMDecrypter(plaintext, []byte{}, aad, block)
		assert.Error(t, err)
		assert.IsType(t, EmptyNonceError{}, err)
	})

	t.Run("GCM decryption with nil block", func(t *testing.T) {
		plaintext := []byte("Hello, World!")
		nonce := make([]byte, 12)
		aad := []byte("AAD")

		_, err := newGCMDecrypter(plaintext, nonce, aad, nil)
		assert.Error(t, err)
		assert.IsType(t, NilBlockError{}, err)
	})

	t.Run("GCM decryption with invalid ciphertext", func(t *testing.T) {
		block, err := aes.NewCipher([]byte("1234567890123456"))
		assert.Nil(t, err)

		// Create invalid ciphertext (too short for GCM)
		invalidCiphertext := []byte("invalid")
		nonce := make([]byte, 12)
		_, err = rand.Read(nonce)
		assert.Nil(t, err)

		aad := []byte("AAD")

		_, err = newGCMDecrypter(invalidCiphertext, nonce, aad, block)
		assert.Error(t, err)
		assert.IsType(t, CreateCipherError{}, err)
	})

	t.Run("GCM decryption with tampered ciphertext", func(t *testing.T) {
		block, err := aes.NewCipher([]byte("1234567890123456"))
		assert.Nil(t, err)

		plaintext := []byte("Hello, World!")
		nonce := make([]byte, 12)
		_, err = rand.Read(nonce)
		assert.Nil(t, err)

		aad := []byte("AAD")

		encrypted, err := newGCMEncrypter(plaintext, nonce, aad, block)
		assert.Nil(t, err)

		// Tamper with the ciphertext
		encrypted[0] ^= 1

		_, err = newGCMDecrypter(encrypted, nonce, aad, block)
		assert.Error(t, err)
		assert.IsType(t, CreateCipherError{}, err)
	})

	t.Run("GCM decryption with wrong nonce", func(t *testing.T) {
		block, err := aes.NewCipher([]byte("1234567890123456"))
		assert.Nil(t, err)

		plaintext := []byte("Hello, World!")
		nonce := make([]byte, 12)
		_, err = rand.Read(nonce)
		assert.Nil(t, err)

		aad := []byte("AAD")

		encrypted, err := newGCMEncrypter(plaintext, nonce, aad, block)
		assert.Nil(t, err)

		// Use different nonce for decryption
		wrongNonce := make([]byte, 12)
		_, err = rand.Read(wrongNonce)
		assert.Nil(t, err)

		_, err = newGCMDecrypter(encrypted, wrongNonce, aad, block)
		assert.Error(t, err)
		assert.IsType(t, CreateCipherError{}, err)
	})

	t.Run("GCM decryption with wrong AAD", func(t *testing.T) {
		block, err := aes.NewCipher([]byte("1234567890123456"))
		assert.Nil(t, err)

		plaintext := []byte("Hello, World!")
		nonce := make([]byte, 12)
		_, err = rand.Read(nonce)
		assert.Nil(t, err)

		aad := []byte("AAD")

		encrypted, err := newGCMEncrypter(plaintext, nonce, aad, block)
		assert.Nil(t, err)

		// Use different AAD for decryption
		wrongAAD := []byte("WRONG_AAD")

		_, err = newGCMDecrypter(encrypted, nonce, wrongAAD, block)
		assert.Error(t, err)
		assert.IsType(t, CreateCipherError{}, err)
	})

	t.Run("GCM encryption with unsupported block cipher", func(t *testing.T) {
		// Create a block that will cause GCM creation to fail
		// We'll use a block with invalid block size to trigger the error
		invalidBlock := &mockGCMBlock{blockSize: 8} // GCM requires 16-byte blocks

		plaintext := []byte("Hello, World!")
		nonce := make([]byte, 12)
		_, err := rand.Read(nonce)
		assert.Nil(t, err)

		aad := []byte("AAD")

		_, err = newGCMEncrypter(plaintext, nonce, aad, invalidBlock)
		assert.Error(t, err)
		assert.IsType(t, CreateCipherError{}, err)
	})

	t.Run("GCM decryption with unsupported block cipher", func(t *testing.T) {
		// Create a block that will cause GCM creation to fail
		invalidBlock := &mockGCMBlock{blockSize: 8} // GCM requires 16-byte blocks

		plaintext := []byte("Hello, World!")
		nonce := make([]byte, 12)
		_, err := rand.Read(nonce)
		assert.Nil(t, err)

		aad := []byte("AAD")

		_, err = newGCMDecrypter(plaintext, nonce, aad, invalidBlock)
		assert.Error(t, err)
		assert.IsType(t, CreateCipherError{}, err)
	})
}

// TestCFBMode tests CFB (Cipher Feedback) mode encryption and decryption
func TestCFBMode(t *testing.T) {
	t.Run("CFB encryption success", func(t *testing.T) {
		block, err := aes.NewCipher([]byte("1234567890123456"))
		assert.Nil(t, err)

		plaintext := []byte("Hello, World! This is a test message for CFB mode.")
		iv := make([]byte, aes.BlockSize)
		_, err = rand.Read(iv)
		assert.Nil(t, err)

		encrypted, err := newCFBEncrypter(plaintext, iv, block)
		assert.Nil(t, err)
		assert.NotNil(t, encrypted)
		assert.Equal(t, len(plaintext), len(encrypted))
	})

	t.Run("CFB decryption success", func(t *testing.T) {
		block, err := aes.NewCipher([]byte("1234567890123456"))
		assert.Nil(t, err)

		plaintext := []byte("Hello, World! This is a test message for CFB mode.")
		iv := make([]byte, aes.BlockSize)
		_, err = rand.Read(iv)
		assert.Nil(t, err)

		encrypted, err := newCFBEncrypter(plaintext, iv, block)
		assert.Nil(t, err)

		decrypted, err := newCFBDecrypter(encrypted, iv, block)
		assert.Nil(t, err)
		assert.Equal(t, plaintext, decrypted)
	})

	t.Run("CFB encryption with empty IV", func(t *testing.T) {
		block, err := aes.NewCipher([]byte("1234567890123456"))
		assert.Nil(t, err)

		plaintext := []byte("Hello, World!")

		_, err = newCFBEncrypter(plaintext, []byte{}, block)
		assert.Error(t, err)
		assert.IsType(t, EmptyIVError{}, err)
	})

	t.Run("CFB encryption with nil block", func(t *testing.T) {
		plaintext := []byte("Hello, World!")
		iv := make([]byte, aes.BlockSize)

		_, err := newCFBEncrypter(plaintext, iv, nil)
		assert.Error(t, err)
		assert.IsType(t, NilBlockError{}, err)
	})

	t.Run("CFB encryption with invalid IV length", func(t *testing.T) {
		block, err := aes.NewCipher([]byte("1234567890123456"))
		assert.Nil(t, err)

		plaintext := []byte("Hello, World!")
		iv := []byte("short") // Too short

		_, err = newCFBEncrypter(plaintext, iv, block)
		assert.Error(t, err)
		assert.IsType(t, InvalidIVError{}, err)
	})

	t.Run("CFB decryption with empty IV", func(t *testing.T) {
		block, err := aes.NewCipher([]byte("1234567890123456"))
		assert.Nil(t, err)

		plaintext := []byte("Hello, World!")

		_, err = newCFBDecrypter(plaintext, []byte{}, block)
		assert.Error(t, err)
		assert.IsType(t, EmptyIVError{}, err)
	})

	t.Run("CFB decryption with nil block", func(t *testing.T) {
		plaintext := []byte("Hello, World!")
		iv := make([]byte, aes.BlockSize)

		_, err := newCFBDecrypter(plaintext, iv, nil)
		assert.Error(t, err)
		assert.IsType(t, NilBlockError{}, err)
	})

	t.Run("CFB decryption with invalid IV length", func(t *testing.T) {
		block, err := aes.NewCipher([]byte("1234567890123456"))
		assert.Nil(t, err)

		plaintext := []byte("Hello, World!")
		iv := []byte("short") // Too short

		_, err = newCFBDecrypter(plaintext, iv, block)
		assert.Error(t, err)
		assert.IsType(t, InvalidIVError{}, err)
	})
}

// TestOFBMode tests OFB (Output Feedback) mode encryption and decryption
func TestOFBMode(t *testing.T) {
	t.Run("OFB encryption success", func(t *testing.T) {
		block, err := aes.NewCipher([]byte("1234567890123456"))
		assert.Nil(t, err)

		plaintext := []byte("Hello, World! This is a test message for OFB mode.")
		iv := make([]byte, aes.BlockSize)
		_, err = rand.Read(iv)
		assert.Nil(t, err)

		encrypted, err := newOFBEncrypter(plaintext, iv, block)
		assert.Nil(t, err)
		assert.NotNil(t, encrypted)
		assert.Equal(t, len(plaintext), len(encrypted))
	})

	t.Run("OFB decryption success", func(t *testing.T) {
		block, err := aes.NewCipher([]byte("1234567890123456"))
		assert.Nil(t, err)

		plaintext := []byte("Hello, World! This is a test message for OFB mode.")
		iv := make([]byte, aes.BlockSize)
		_, err = rand.Read(iv)
		assert.Nil(t, err)

		encrypted, err := newOFBEncrypter(plaintext, iv, block)
		assert.Nil(t, err)

		decrypted, err := newOFBDecrypter(encrypted, iv, block)
		assert.Nil(t, err)
		assert.Equal(t, plaintext, decrypted)
	})

	t.Run("OFB encryption with empty IV", func(t *testing.T) {
		block, err := aes.NewCipher([]byte("1234567890123456"))
		assert.Nil(t, err)

		plaintext := []byte("Hello, World!")

		_, err = newOFBEncrypter(plaintext, []byte{}, block)
		assert.Error(t, err)
		assert.IsType(t, EmptyIVError{}, err)
	})

	t.Run("OFB encryption with nil block", func(t *testing.T) {
		plaintext := []byte("Hello, World!")
		iv := make([]byte, aes.BlockSize)

		_, err := newOFBEncrypter(plaintext, iv, nil)
		assert.Error(t, err)
		assert.IsType(t, NilBlockError{}, err)
	})

	t.Run("OFB encryption with invalid IV length", func(t *testing.T) {
		block, err := aes.NewCipher([]byte("1234567890123456"))
		assert.Nil(t, err)

		plaintext := []byte("Hello, World!")
		iv := []byte("short") // Too short

		_, err = newOFBEncrypter(plaintext, iv, block)
		assert.Error(t, err)
		assert.IsType(t, InvalidIVError{}, err)
	})

	t.Run("OFB decryption with empty IV", func(t *testing.T) {
		block, err := aes.NewCipher([]byte("1234567890123456"))
		assert.Nil(t, err)

		plaintext := []byte("Hello, World!")

		_, err = newOFBDecrypter(plaintext, []byte{}, block)
		assert.Error(t, err)
		assert.IsType(t, EmptyIVError{}, err)
	})

	t.Run("OFB decryption with nil block", func(t *testing.T) {
		plaintext := []byte("Hello, World!")
		iv := make([]byte, aes.BlockSize)

		_, err := newOFBDecrypter(plaintext, iv, nil)
		assert.Error(t, err)
		assert.IsType(t, NilBlockError{}, err)
	})

	t.Run("OFB decryption with invalid IV length", func(t *testing.T) {
		block, err := aes.NewCipher([]byte("1234567890123456"))
		assert.Nil(t, err)

		plaintext := []byte("Hello, World!")
		iv := []byte("short") // Too short

		_, err = newOFBDecrypter(plaintext, iv, block)
		assert.Error(t, err)
		assert.IsType(t, InvalidIVError{}, err)
	})
}

// TestErrorTypes tests the error types and their messages
func TestErrorTypes(t *testing.T) {
	t.Run("EmptyIVError", func(t *testing.T) {
		err := EmptyIVError{mode: CBC}
		assert.Equal(t, "cbc: iv cannot be empty", err.Error())
	})

	t.Run("NilBlockError", func(t *testing.T) {
		err := NilBlockError{mode: CTR}
		assert.Equal(t, "ctr: cipher block cannot be nil", err.Error())
	})

	t.Run("InvalidIVError", func(t *testing.T) {
		err := InvalidIVError{mode: GCM, iv: []byte("short"), size: 16}
		assert.Equal(t, "gcm: iv length 5 must equal block size 16", err.Error())
	})

	t.Run("EmptyNonceError", func(t *testing.T) {
		err := EmptyNonceError{mode: GCM}
		assert.Equal(t, "gcm: nonce cannot be empty", err.Error())
	})

	t.Run("InvalidSrcError", func(t *testing.T) {
		err := InvalidSrcError{mode: ECB, src: []byte("short"), size: 16}
		assert.Equal(t, "ecb: src length 5 must be a multiple of block size 16", err.Error())
	})

	t.Run("CreateCipherError", func(t *testing.T) {
		originalErr := assert.AnError
		err := CreateCipherError{mode: CFB, err: originalErr}
		assert.Contains(t, err.Error(), "cfb: failed to create cipher:")
		assert.Contains(t, err.Error(), "assert.AnError")
	})
}

// TestBlockModes tests the BlockMode constants
func TestBlockModes(t *testing.T) {
	t.Run("CBC mode", func(t *testing.T) {
		assert.Equal(t, BlockMode("cbc"), CBC)
	})

	t.Run("CTR mode", func(t *testing.T) {
		assert.Equal(t, BlockMode("ctr"), CTR)
	})

	t.Run("ECB mode", func(t *testing.T) {
		assert.Equal(t, BlockMode("ecb"), ECB)
	})

	t.Run("GCM mode", func(t *testing.T) {
		assert.Equal(t, BlockMode("gcm"), GCM)
	})

	t.Run("CFB mode", func(t *testing.T) {
		assert.Equal(t, BlockMode("cfb"), CFB)
	})

	t.Run("OFB mode", func(t *testing.T) {
		assert.Equal(t, BlockMode("ofb"), OFB)
	})
}

// TestEdgeCases tests edge cases for all modes
func TestEdgeCases(t *testing.T) {
	t.Run("empty plaintext", func(t *testing.T) {
		block, err := aes.NewCipher([]byte("1234567890123456"))
		assert.Nil(t, err)

		// Test CBC with empty plaintext
		iv := make([]byte, aes.BlockSize)
		_, err = rand.Read(iv)
		assert.Nil(t, err)

		encrypted, err := newCBCEncrypter([]byte{}, iv, block)
		assert.Nil(t, err)
		assert.Equal(t, []byte{}, encrypted)

		decrypted, err := newCBCDecrypter(encrypted, iv, block)
		assert.Nil(t, err)
		assert.Equal(t, []byte{}, decrypted)
	})

	t.Run("single block", func(t *testing.T) {
		block, err := aes.NewCipher([]byte("1234567890123456"))
		assert.Nil(t, err)

		// Create exactly one block of data
		plaintext := make([]byte, aes.BlockSize)
		for i := range plaintext {
			plaintext[i] = byte(i)
		}

		iv := make([]byte, aes.BlockSize)
		_, err = rand.Read(iv)
		assert.Nil(t, err)

		encrypted, err := newCBCEncrypter(plaintext, iv, block)
		assert.Nil(t, err)
		assert.Equal(t, aes.BlockSize, len(encrypted))

		decrypted, err := newCBCDecrypter(encrypted, iv, block)
		assert.Nil(t, err)
		assert.Equal(t, plaintext, decrypted)
	})

	t.Run("multiple blocks", func(t *testing.T) {
		block, err := aes.NewCipher([]byte("1234567890123456"))
		assert.Nil(t, err)

		// Create multiple blocks of data
		plaintext := make([]byte, aes.BlockSize*3)
		for i := range plaintext {
			plaintext[i] = byte(i)
		}

		iv := make([]byte, aes.BlockSize)
		_, err = rand.Read(iv)
		assert.Nil(t, err)

		encrypted, err := newCBCEncrypter(plaintext, iv, block)
		assert.Nil(t, err)
		assert.Equal(t, len(plaintext), len(encrypted))

		decrypted, err := newCBCDecrypter(encrypted, iv, block)
		assert.Nil(t, err)
		assert.Equal(t, plaintext, decrypted)
	})
}

// TestRoundTrip tests round-trip encryption/decryption for all modes
func TestRoundTrip(t *testing.T) {
	testCases := []struct {
		name string
		mode BlockMode
		test func(t *testing.T, block stdcipher.Block)
	}{
		{"CBC round trip", CBC, testCBCRoundTrip},
		{"CTR round trip", CTR, testCTRRoundTrip},
		{"ECB round trip", ECB, testECBRoundTrip},
		{"GCM round trip", GCM, testGCMRoundTrip},
		{"CFB round trip", CFB, testCFBRoundTrip},
		{"OFB round trip", OFB, testOFBRoundTrip},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			block, err := aes.NewCipher([]byte("1234567890123456"))
			assert.Nil(t, err)
			tc.test(t, block)
		})
	}
}

func testCBCRoundTrip(t *testing.T, block stdcipher.Block) {
	plaintext := []byte("Hello, World! This is a test message for round trip testing.")
	paddedText := padToBlockSize(plaintext, aes.BlockSize)

	iv := make([]byte, aes.BlockSize)
	_, err := rand.Read(iv)
	assert.Nil(t, err)

	encrypted, err := newCBCEncrypter(paddedText, iv, block)
	assert.Nil(t, err)

	decrypted, err := newCBCDecrypter(encrypted, iv, block)
	assert.Nil(t, err)
	assert.Equal(t, paddedText, decrypted)
}

func testCTRRoundTrip(t *testing.T, block stdcipher.Block) {
	plaintext := []byte("Hello, World! This is a test message for round trip testing.")

	iv := make([]byte, aes.BlockSize)
	_, err := rand.Read(iv)
	assert.Nil(t, err)

	encrypted, err := newCTREncrypter(plaintext, iv, block)
	assert.Nil(t, err)

	decrypted, err := newCTRDecrypter(encrypted, iv, block)
	assert.Nil(t, err)
	assert.Equal(t, plaintext, decrypted)
}

func testECBRoundTrip(t *testing.T, block stdcipher.Block) {
	plaintext := []byte("Hello, World! This is a test message for round trip testing.")
	paddedText := padToBlockSize(plaintext, aes.BlockSize)

	encrypted, err := newECBEncrypter(paddedText, block)
	assert.Nil(t, err)

	decrypted, err := newECBDecrypter(encrypted, block)
	assert.Nil(t, err)
	assert.Equal(t, paddedText, decrypted)
}

func testGCMRoundTrip(t *testing.T, block stdcipher.Block) {
	plaintext := []byte("Hello, World! This is a test message for round trip testing.")
	nonce := make([]byte, 12)
	_, err := rand.Read(nonce)
	assert.Nil(t, err)

	aad := []byte("Additional authenticated data")

	encrypted, err := newGCMEncrypter(plaintext, nonce, aad, block)
	assert.Nil(t, err)

	decrypted, err := newGCMDecrypter(encrypted, nonce, aad, block)
	assert.Nil(t, err)
	assert.Equal(t, plaintext, decrypted)
}

func testCFBRoundTrip(t *testing.T, block stdcipher.Block) {
	plaintext := []byte("Hello, World! This is a test message for round trip testing.")

	iv := make([]byte, aes.BlockSize)
	_, err := rand.Read(iv)
	assert.Nil(t, err)

	encrypted, err := newCFBEncrypter(plaintext, iv, block)
	assert.Nil(t, err)

	decrypted, err := newCFBDecrypter(encrypted, iv, block)
	assert.Nil(t, err)
	assert.Equal(t, plaintext, decrypted)
}

func testOFBRoundTrip(t *testing.T, block stdcipher.Block) {
	plaintext := []byte("Hello, World! This is a test message for round trip testing.")

	iv := make([]byte, aes.BlockSize)
	_, err := rand.Read(iv)
	assert.Nil(t, err)

	encrypted, err := newOFBEncrypter(plaintext, iv, block)
	assert.Nil(t, err)

	decrypted, err := newOFBDecrypter(encrypted, iv, block)
	assert.Nil(t, err)
	assert.Equal(t, plaintext, decrypted)
}

// Helper function to pad data to block size
func padToBlockSize(data []byte, blockSize int) []byte {
	if len(data) == 0 {
		return data
	}

	padding := blockSize - (len(data) % blockSize)
	if padding == blockSize {
		return data
	}

	padded := make([]byte, len(data)+padding)
	copy(padded, data)

	// PKCS7 padding
	for i := len(data); i < len(padded); i++ {
		padded[i] = byte(padding)
	}

	return padded
}

type mockGCMBlock struct {
	blockSize int
}

func (m *mockGCMBlock) BlockSize() int {
	return m.blockSize
}

func (m *mockGCMBlock) Encrypt(dst, src []byte) {
	// This will cause GCM creation to fail because it's not a valid AES block
	panic("mock GCM block - should not be called")
}

func (m *mockGCMBlock) Decrypt(dst, src []byte) {
	// This will cause GCM creation to fail because it's not a valid AES block
	panic("mock GCM block - should not be called")
}
