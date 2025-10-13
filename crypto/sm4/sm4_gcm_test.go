package sm4

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"testing"

	"github.com/dromara/dongle/crypto/cipher"
	"github.com/stretchr/testify/assert"
)

type gcmTestCase struct {
	plaintext        []byte
	key              []byte
	nonce            []byte
	aad              []byte
	hexCiphertext    string
	base64Ciphertext string
}

var gcmTestCases = []gcmTestCase{
	{
		plaintext:        []byte("hello world"),
		key:              []byte("1234567890123456"),
		nonce:            []byte("123456789012"),
		aad:              []byte("authenticated data"),
		hexCiphertext:    "840033e62ed95a0c8fcf483a8987bfc60c0ae4103b2887e3d4e62c",
		base64Ciphertext: "hAAz5i7ZWgyPz0g6iYe/xgwK5BA7KIfj1OYs",
	},
	{
		plaintext:        []byte("hello world, this is a test message for SM4 GCM mode"),
		key:              []byte("1234567890123456"),
		nonce:            []byte("123456789012"),
		aad:              []byte("authenticated data"),
		hexCiphertext:    "840033e62ed95a0c8fcf48b135a6865ae50bf674d6e6b1f2f4b67ac4e24fafd3d2b4e964ef891311a2c3731f3557b08c4a98ed6dc1dcaf14e99a37c64c314b11e3c0aa84",
		base64Ciphertext: "hAAz5i7ZWgyPz0ixNaaGWuUL9nTW5rHy9LZ6xOJPr9PStOlk74kTEaLDcx81V7CMSpjtbcHcrxTpmjfGTDFLEePAqoQ=",
	},
	{
		plaintext:        []byte(""),
		key:              []byte("1234567890123456"),
		nonce:            []byte("123456789012"),
		aad:              []byte("authenticated data"),
		hexCiphertext:    "", // GCM with empty plaintext in Go returns empty ciphertext
		base64Ciphertext: "",
	},
}

func TestGCMStdEncryption(t *testing.T) {
	for i, tc := range gcmTestCases {
		t.Run(fmt.Sprintf("test_case_%d", i), func(t *testing.T) {
			// Create cipher
			c := cipher.NewSm4Cipher(cipher.GCM)
			c.SetKey(tc.key)
			c.SetNonce(tc.nonce)
			c.SetAAD(tc.aad)
			c.SetPadding(cipher.No)

			// Test std encryption
			encrypter := NewStdEncrypter(c)
			encrypted, err := encrypter.Encrypt(tc.plaintext)

			assert.NoError(t, err)

			// Verify against expected values
			if tc.hexCiphertext != "" {
				expected, err := hex.DecodeString(tc.hexCiphertext)
				assert.NoError(t, err)
				assert.Equal(t, expected, encrypted)
			}
			if tc.base64Ciphertext != "" {
				expected, err := base64.StdEncoding.DecodeString(tc.base64Ciphertext)
				assert.NoError(t, err)
				assert.Equal(t, expected, encrypted)
			}
		})
	}
}

func TestGCMStdDecryption(t *testing.T) {
	for i, tc := range gcmTestCases {
		t.Run(fmt.Sprintf("test_case_%d", i), func(t *testing.T) {
			// Create cipher
			c := cipher.NewSm4Cipher(cipher.GCM)
			c.SetKey(tc.key)
			c.SetNonce(tc.nonce)
			c.SetAAD(tc.aad)
			c.SetPadding(cipher.No)

			// Test decryption from hex
			if tc.hexCiphertext != "" {
				expected, _ := hex.DecodeString(tc.hexCiphertext)
				decrypter := NewStdDecrypter(c)
				decrypted, err := decrypter.Decrypt(expected)
				assert.NoError(t, err)
				assert.Equal(t, tc.plaintext, decrypted)
			}

			// Test decryption from base64
			if tc.base64Ciphertext != "" {
				expected, _ := base64.StdEncoding.DecodeString(tc.base64Ciphertext)
				decrypter := NewStdDecrypter(c)
				decrypted, err := decrypter.Decrypt(expected)
				assert.NoError(t, err)
				assert.Equal(t, tc.plaintext, decrypted)
			}
		})
	}
}

func TestGCMStreamEncryption(t *testing.T) {
	for i, tc := range gcmTestCases {
		t.Run(fmt.Sprintf("test_case_%d", i), func(t *testing.T) {
			// Create cipher
			c := cipher.NewSm4Cipher(cipher.GCM)
			c.SetKey(tc.key)
			c.SetNonce(tc.nonce)
			c.SetAAD(tc.aad)
			c.SetPadding(cipher.No)

			// Test stream encryption
			var buf bytes.Buffer
			encrypter := NewStreamEncrypter(&buf, c)
			_, err := encrypter.Write(tc.plaintext)
			assert.NoError(t, err)

			err = encrypter.Close()
			assert.NoError(t, err)

			// Verify we got encrypted output
			encrypted := buf.Bytes()

			// Verify against expected values
			if tc.hexCiphertext != "" {
				expected, _ := hex.DecodeString(tc.hexCiphertext)
				assert.Equal(t, expected, encrypted)
			}
			if tc.base64Ciphertext != "" {
				expected, _ := base64.StdEncoding.DecodeString(tc.base64Ciphertext)
				assert.Equal(t, expected, encrypted)
			}
		})
	}
}

func TestGCMStreamDecryption(t *testing.T) {
	for i, tc := range gcmTestCases {
		t.Run(fmt.Sprintf("test_case_%d", i), func(t *testing.T) {
			// Create cipher
			c := cipher.NewSm4Cipher(cipher.GCM)
			c.SetKey(tc.key)
			c.SetNonce(tc.nonce)
			c.SetAAD(tc.aad)
			c.SetPadding(cipher.No)

			// Test decryption from hex
			if tc.hexCiphertext != "" {
				expected, _ := hex.DecodeString(tc.hexCiphertext)
				buf := bytes.NewBuffer(expected)
				decrypter := NewStreamDecrypter(buf, c)
				decrypted, err := io.ReadAll(decrypter)
				assert.NoError(t, err)
				assert.Equal(t, tc.plaintext, decrypted)
			}

			// Test decryption from base64
			if tc.base64Ciphertext != "" {
				expected, _ := base64.StdEncoding.DecodeString(tc.base64Ciphertext)
				buf := bytes.NewBuffer(expected)
				decrypter := NewStreamDecrypter(buf, c)
				decrypted, err := io.ReadAll(decrypter)
				assert.NoError(t, err)
				assert.Equal(t, tc.plaintext, decrypted)
			}
		})
	}
}

// TestSM4GCMErrorHandling tests error handling in SM4 GCM mode
func TestSM4GCMErrorHandling(t *testing.T) {
	t.Run("GCM encryption with invalid key size", func(t *testing.T) {
		// Create SM4 cipher with GCM mode and invalid key
		c := cipher.NewSm4Cipher(cipher.GCM)
		c.SetKey([]byte("invalid")) // Invalid key size
		c.SetNonce([]byte("123456789012"))
		c.SetAAD([]byte("authenticated data"))
		c.SetPadding(cipher.No)

		// Create encrypter
		encrypter := NewStdEncrypter(c)
		assert.NotNil(t, encrypter.Error, "Encrypter should have an error due to invalid key size")
		assert.IsType(t, KeySizeError(0), encrypter.Error, "Error should be KeySizeError")

		// Try to encrypt - should fail
		ciphertext, err := encrypter.Encrypt([]byte("hello world"))
		assert.Nil(t, ciphertext, "Ciphertext should be nil when encrypter has error")
		assert.Equal(t, encrypter.Error, err, "Error should match the encrypter's error")
	})

	t.Run("GCM decryption with invalid key size", func(t *testing.T) {
		// Create SM4 cipher with GCM mode and invalid key
		c := cipher.NewSm4Cipher(cipher.GCM)
		c.SetKey([]byte("invalid")) // Invalid key size
		c.SetNonce([]byte("123456789012"))
		c.SetAAD([]byte("authenticated data"))
		c.SetPadding(cipher.No)

		// Create decrypter
		decrypter := NewStdDecrypter(c)
		assert.NotNil(t, decrypter.Error, "Decrypter should have an error due to invalid key size")
		assert.IsType(t, KeySizeError(0), decrypter.Error, "Error should be KeySizeError")

		// Try to decrypt - should fail
		decrypted, err := decrypter.Decrypt([]byte("hello world"))
		assert.Nil(t, decrypted, "Decrypted text should be nil when decrypter has error")
		assert.Equal(t, decrypter.Error, err, "Error should match the decrypter's error")
	})

	t.Run("GCM encryption with empty nonce", func(t *testing.T) {
		// Create SM4 cipher with GCM mode and empty nonce
		c := cipher.NewSm4Cipher(cipher.GCM)
		c.SetKey([]byte("1234567890123456"))
		c.SetNonce([]byte{}) // Empty nonce
		c.SetAAD([]byte("authenticated data"))
		c.SetPadding(cipher.No)

		// Create encrypter
		encrypter := NewStdEncrypter(c)
		// Override the block to bypass NewCipher validation
		block, _ := NewCipher([]byte("1234567890123456"))
		encrypter.block = block

		// Try to encrypt - should fail
		ciphertext, err := encrypter.Encrypt([]byte("hello world"))
		assert.Nil(t, ciphertext, "Ciphertext should be nil when encrypter encounters error")
		assert.IsType(t, EncryptError{}, err, "Error should be EncryptError")
	})

	t.Run("GCM decryption with empty nonce", func(t *testing.T) {
		// Create SM4 cipher with GCM mode and empty nonce
		c := cipher.NewSm4Cipher(cipher.GCM)
		c.SetKey([]byte("1234567890123456"))
		c.SetNonce([]byte{}) // Empty nonce
		c.SetAAD([]byte("authenticated data"))
		c.SetPadding(cipher.No)

		// Create decrypter
		decrypter := NewStdDecrypter(c)
		// Override the block to bypass NewCipher validation
		block, _ := NewCipher([]byte("1234567890123456"))
		decrypter.block = block

		// Try to decrypt - should fail
		decrypted, err := decrypter.Decrypt([]byte("hello world"))
		assert.Nil(t, decrypted, "Decrypted text should be nil when decrypter encounters error")
		assert.IsType(t, DecryptError{}, err, "Error should be DecryptError")
	})

	t.Run("GCM decryption with tampered ciphertext", func(t *testing.T) {
		// Create SM4 cipher with GCM mode
		c := cipher.NewSm4Cipher(cipher.GCM)
		c.SetKey([]byte("1234567890123456"))
		c.SetNonce([]byte("123456789012"))
		c.SetAAD([]byte("authenticated data"))
		c.SetPadding(cipher.No)

		// Create encrypter
		encrypter := NewStdEncrypter(c)
		assert.Nil(t, encrypter.Error, "Encrypter should be created without error")

		// Encrypt plaintext
		ciphertext, err := encrypter.Encrypt([]byte("hello world"))
		assert.NoError(t, err, "Encryption should not fail")

		// Tamper with ciphertext
		tampered := make([]byte, len(ciphertext))
		copy(tampered, ciphertext)
		if len(tampered) > 0 {
			tampered[0] ^= 0xFF // Flip some bits
		}

		// Create decrypter with same parameters
		d := cipher.NewSm4Cipher(cipher.GCM)
		d.SetKey([]byte("1234567890123456"))
		d.SetNonce([]byte("123456789012"))
		d.SetAAD([]byte("authenticated data"))
		d.SetPadding(cipher.No)

		// Create decrypter
		decrypter := NewStdDecrypter(d)
		assert.Nil(t, decrypter.Error, "Decrypter should be created without error")

		// Try to decrypt tampered ciphertext - should fail
		decrypted, err := decrypter.Decrypt(tampered)
		assert.Error(t, err, "Decryption should fail with tampered ciphertext")
		assert.Nil(t, decrypted, "Decrypted text should be nil when decryption fails")
	})

	t.Run("GCM decryption with wrong AAD", func(t *testing.T) {
		// Create SM4 cipher with GCM mode
		c := cipher.NewSm4Cipher(cipher.GCM)
		c.SetKey([]byte("1234567890123456"))
		c.SetNonce([]byte("123456789012"))
		c.SetAAD([]byte("authenticated data"))
		c.SetPadding(cipher.No)

		// Create encrypter
		encrypter := NewStdEncrypter(c)
		assert.Nil(t, encrypter.Error, "Encrypter should be created without error")

		// Encrypt plaintext
		ciphertext, err := encrypter.Encrypt([]byte("hello world"))
		assert.NoError(t, err, "Encryption should not fail")

		// Create decrypter with wrong AAD
		d := cipher.NewSm4Cipher(cipher.GCM)
		d.SetKey([]byte("1234567890123456"))
		d.SetNonce([]byte("123456789012"))
		d.SetAAD([]byte("wrong aad")) // Wrong AAD
		d.SetPadding(cipher.No)

		// Create decrypter
		decrypter := NewStdDecrypter(d)
		assert.Nil(t, decrypter.Error, "Decrypter should be created without error")

		// Try to decrypt with wrong AAD - should fail
		decrypted, err := decrypter.Decrypt(ciphertext)
		assert.Error(t, err, "Decryption should fail with wrong AAD")
		assert.Nil(t, decrypted, "Decrypted text should be nil when decryption fails")
	})
}
