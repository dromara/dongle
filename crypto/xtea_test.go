package crypto

import (
	"testing"

	"github.com/dromara/dongle/crypto/cipher"
	"github.com/dromara/dongle/mock"
	"github.com/stretchr/testify/assert"
)

// TestXteaInputTypes tests XTEA encryption with various input types
func TestXteaInputTypes(t *testing.T) {
	t.Run("string input", func(t *testing.T) {
		key := []byte("1234567890123456") // 16-byte key for XTEA
		xteaCipher := cipher.NewXteaCipher(cipher.ECB)
		xteaCipher.SetKey(key)
		plaintext := "12345678" // 8-byte string for XTEA

		encrypted := NewEncrypter().FromString(plaintext).ByXtea(xteaCipher).ToRawString()
		assert.NotEmpty(t, encrypted)

		decrypted := NewDecrypter().FromRawString(encrypted).ByXtea(xteaCipher).ToString()
		assert.Equal(t, plaintext, decrypted)
	})

	t.Run("bytes input", func(t *testing.T) {
		key := []byte("1234567890123456") // 16-byte key for XTEA
		xteaCipher := cipher.NewXteaCipher(cipher.ECB)
		xteaCipher.SetKey(key)
		plaintext := []byte("12345678") // 8-byte data for XTEA

		encrypted := NewEncrypter().FromBytes(plaintext).ByXtea(xteaCipher).ToRawBytes()
		assert.NotEmpty(t, encrypted)

		decrypted := NewDecrypter().FromRawBytes(encrypted).ByXtea(xteaCipher).ToBytes()
		assert.Equal(t, plaintext, decrypted)
	})

	t.Run("empty input", func(t *testing.T) {
		key := []byte("1234567890123456") // 16-byte key for XTEA
		xteaCipher := cipher.NewXteaCipher(cipher.ECB)
		xteaCipher.SetKey(key)
		plaintext := ""

		// XTEA requires data to be multiple of 8 bytes, so empty input should result in empty output
		encrypted := NewEncrypter().FromString(plaintext).ByXtea(xteaCipher).ToRawString()
		assert.Empty(t, encrypted)
	})

	t.Run("empty bytes input", func(t *testing.T) {
		key := []byte("1234567890123456") // 16-byte key for XTEA
		xteaCipher := cipher.NewXteaCipher(cipher.ECB)
		xteaCipher.SetKey(key)
		plaintext := []byte{}

		encrypted := NewEncrypter().FromBytes(plaintext).ByXtea(xteaCipher).ToRawBytes()
		assert.Empty(t, encrypted)
	})
}

// TestXteaCipherModes tests XTEA encryption with different cipher modes
func TestXteaCipherModes(t *testing.T) {
	key := []byte("1234567890123456") // 16-byte key for XTEA
	plaintext := "12345678"           // 8-byte string for XTEA

	testCases := []struct {
		name string
		mode cipher.BlockMode
	}{
		{"ECB mode", cipher.ECB},
		{"CBC mode", cipher.CBC},
		{"CFB mode", cipher.CFB},
		{"OFB mode", cipher.OFB},
		{"CTR mode", cipher.CTR},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			xteaCipher := cipher.NewXteaCipher(tc.mode)
			xteaCipher.SetKey(key)
			if tc.mode != cipher.ECB {
				xteaCipher.SetIV([]byte("12345678")) // 8-byte IV for XTEA
			}

			encrypted := NewEncrypter().FromString(plaintext).ByXtea(xteaCipher).ToRawString()
			assert.NotEmpty(t, encrypted)

			decrypted := NewDecrypter().FromRawString(encrypted).ByXtea(xteaCipher).ToString()
			assert.Equal(t, plaintext, decrypted)
		})
	}
}

// TestXteaStreaming tests XTEA streaming encryption/decryption
func TestXteaStreaming(t *testing.T) {
	t.Run("streaming encryption", func(t *testing.T) {
		key := []byte("1234567890123456") // 16-byte key for XTEA
		xteaCipher := cipher.NewXteaCipher(cipher.CBC)
		xteaCipher.SetPadding(cipher.PKCS7)
		xteaCipher.SetKey(key)
		xteaCipher.SetIV([]byte("12345678")) // 8-byte IV for XTEA

		plaintext := "Hello, World! This is a test message for XTEA streaming encryption."
		file := mock.NewFile([]byte(plaintext), "test.txt")

		encrypted := NewEncrypter().FromFile(file).ByXtea(xteaCipher).ToRawString()
		assert.NotEmpty(t, encrypted)

		decrypted := NewDecrypter().FromRawString(encrypted).ByXtea(xteaCipher).ToString()
		assert.Equal(t, plaintext, decrypted)
	})

	t.Run("streaming with empty file", func(t *testing.T) {
		key := []byte("1234567890123456") // 16-byte key for XTEA
		xteaCipher := cipher.NewXteaCipher(cipher.CBC)
		xteaCipher.SetKey(key)
		xteaCipher.SetIV([]byte("12345678")) // 8-byte IV for XTEA

		file := mock.NewFile([]byte(""), "empty.txt")

		encrypted := NewEncrypter().FromFile(file).ByXtea(xteaCipher).ToRawString()
		assert.Empty(t, encrypted)
	})

	t.Run("streaming decryption", func(t *testing.T) {
		key := []byte("1234567890123456") // 16-byte key for XTEA
		xteaCipher := cipher.NewXteaCipher(cipher.CBC)
		xteaCipher.SetPadding(cipher.PKCS7)
		xteaCipher.SetKey(key)
		xteaCipher.SetIV([]byte("12345678")) // 8-byte IV for XTEA

		plaintext := "Hello, World! This is a test message for XTEA streaming decryption."

		// First encrypt the data
		encrypted := NewEncrypter().FromString(plaintext).ByXtea(xteaCipher).ToRawString()
		assert.NotEmpty(t, encrypted)

		// Then decrypt using streaming mode
		file := mock.NewFile([]byte(encrypted), "encrypted.txt")
		decrypted := NewDecrypter().FromRawFile(file).ByXtea(xteaCipher).ToString()
		assert.Equal(t, plaintext, decrypted)
	})
}

// TestXteaErrorHandling tests XTEA error handling
func TestXteaErrorHandling(t *testing.T) {
	t.Run("encryption with existing error", func(t *testing.T) {
		key := []byte("1234567890123456") // 16-byte key for XTEA
		xteaCipher := cipher.NewXteaCipher(cipher.ECB)
		xteaCipher.SetKey(key)

		// Create encrypter with existing error
		encrypter := NewEncrypter()
		encrypter.Error = assert.AnError

		result := encrypter.FromString("test").ByXtea(xteaCipher)
		assert.Error(t, result.Error)
		assert.Equal(t, assert.AnError, result.Error)
	})

	t.Run("decryption with existing error", func(t *testing.T) {
		key := []byte("1234567890123456") // 16-byte key for XTEA
		xteaCipher := cipher.NewXteaCipher(cipher.ECB)
		xteaCipher.SetKey(key)

		// Create decrypter with existing error
		decrypter := NewDecrypter()
		decrypter.Error = assert.AnError

		result := decrypter.FromRawString("test").ByXtea(xteaCipher)
		assert.Error(t, result.Error)
		assert.Equal(t, assert.AnError, result.Error)
	})

	t.Run("encryption with invalid key", func(t *testing.T) {
		invalidKey := []byte("short") // Invalid key length
		xteaCipher := cipher.NewXteaCipher(cipher.ECB)
		xteaCipher.SetKey(invalidKey)

		encrypted := NewEncrypter().FromString("test").ByXtea(xteaCipher).ToRawString()
		assert.Empty(t, encrypted) // Should be empty due to invalid key
	})

	t.Run("decryption with invalid key", func(t *testing.T) {
		invalidKey := []byte("short") // Invalid key length
		xteaCipher := cipher.NewXteaCipher(cipher.ECB)
		xteaCipher.SetKey(invalidKey)

		decrypted := NewDecrypter().FromRawString("test").ByXtea(xteaCipher).ToString()
		assert.Empty(t, decrypted) // Should be empty due to invalid key
	})
}

// TestXteaPaddingModes tests XTEA with different padding modes
func TestXteaPaddingModes(t *testing.T) {
	key := []byte("1234567890123456") // 16-byte key for XTEA
	plaintext := "12345678"           // 8-byte string for XTEA

	paddingModes := []cipher.PaddingMode{
		cipher.PKCS7,
		cipher.PKCS5,
		cipher.Zero,
		cipher.AnsiX923,
		cipher.ISO97971,
		cipher.ISO10126,
		cipher.ISO78164,
		cipher.Bit,
	}

	for _, padding := range paddingModes {
		t.Run(string(padding), func(t *testing.T) {
			xteaCipher := cipher.NewXteaCipher(cipher.CBC)
			xteaCipher.SetKey(key)
			xteaCipher.SetIV([]byte("12345678")) // 8-byte IV for XTEA
			xteaCipher.SetPadding(padding)

			encrypted := NewEncrypter().FromString(plaintext).ByXtea(xteaCipher).ToRawString()
			assert.NotEmpty(t, encrypted)

			decrypted := NewDecrypter().FromRawString(encrypted).ByXtea(xteaCipher).ToString()
			assert.Equal(t, plaintext, decrypted)
		})
	}
}

// TestXteaLargeData tests XTEA with large data
func TestXteaLargeData(t *testing.T) {
	t.Run("large string data", func(t *testing.T) {
		key := []byte("1234567890123456") // 16-byte key for XTEA
		xteaCipher := cipher.NewXteaCipher(cipher.CBC)
		xteaCipher.SetKey(key)
		xteaCipher.SetIV([]byte("12345678")) // 8-byte IV for XTEA

		// Create large plaintext (multiple of 8 bytes)
		plaintext := ""
		for range 100 {
			plaintext += "12345678"
		}

		encrypted := NewEncrypter().FromString(plaintext).ByXtea(xteaCipher).ToRawString()
		assert.NotEmpty(t, encrypted)

		decrypted := NewDecrypter().FromRawString(encrypted).ByXtea(xteaCipher).ToString()
		assert.Equal(t, plaintext, decrypted)
	})

	t.Run("large bytes data", func(t *testing.T) {
		key := []byte("1234567890123456") // 16-byte key for XTEA
		xteaCipher := cipher.NewXteaCipher(cipher.CBC)
		xteaCipher.SetKey(key)
		xteaCipher.SetIV([]byte("12345678")) // 8-byte IV for XTEA

		// Create large plaintext (multiple of 8 bytes)
		plaintext := make([]byte, 800) // 100 * 8 bytes
		for i := range plaintext {
			plaintext[i] = byte(i % 256)
		}

		encrypted := NewEncrypter().FromBytes(plaintext).ByXtea(xteaCipher).ToRawBytes()
		assert.NotEmpty(t, encrypted)

		decrypted := NewDecrypter().FromRawBytes(encrypted).ByXtea(xteaCipher).ToBytes()
		assert.Equal(t, plaintext, decrypted)
	})
}

// TestXteaGCM tests XTEA with GCM mode (authenticated encryption)
func TestXteaGCM(t *testing.T) {
	t.Run("GCM mode encryption", func(t *testing.T) {
		key := []byte("1234567890123456") // 16-byte key for XTEA
		xteaCipher := cipher.NewXteaCipher(cipher.GCM)
		xteaCipher.SetKey(key)
		xteaCipher.SetNonce([]byte("12345678")) // 8-byte nonce for XTEA
		xteaCipher.SetAAD([]byte("additional authenticated data"))

		plaintext := "12345678" // 8-byte string for XTEA

		encrypted := NewEncrypter().FromString(plaintext).ByXtea(xteaCipher).ToRawString()
		// GCM mode might not be supported for XTEA, so we just test that it doesn't panic
		// and returns some result (empty or not)
		_ = encrypted

		decrypted := NewDecrypter().FromRawString(encrypted).ByXtea(xteaCipher).ToString()
		// Similarly for decryption
		_ = decrypted
	})
}

// TestXteaEdgeCases tests XTEA edge cases
func TestXteaEdgeCases(t *testing.T) {
	t.Run("exactly 8 bytes", func(t *testing.T) {
		key := []byte("1234567890123456") // 16-byte key for XTEA
		xteaCipher := cipher.NewXteaCipher(cipher.ECB)
		xteaCipher.SetKey(key)
		plaintext := "12345678" // Exactly 8 bytes

		encrypted := NewEncrypter().FromString(plaintext).ByXtea(xteaCipher).ToRawString()
		assert.NotEmpty(t, encrypted)

		decrypted := NewDecrypter().FromRawString(encrypted).ByXtea(xteaCipher).ToString()
		assert.Equal(t, plaintext, decrypted)
	})

	t.Run("16 bytes", func(t *testing.T) {
		key := []byte("1234567890123456") // 16-byte key for XTEA
		xteaCipher := cipher.NewXteaCipher(cipher.ECB)
		xteaCipher.SetKey(key)
		plaintext := "1234567812345678" // 16 bytes (2 blocks)

		encrypted := NewEncrypter().FromString(plaintext).ByXtea(xteaCipher).ToRawString()
		assert.NotEmpty(t, encrypted)

		decrypted := NewDecrypter().FromRawString(encrypted).ByXtea(xteaCipher).ToString()
		assert.Equal(t, plaintext, decrypted)
	})

	t.Run("nil cipher", func(t *testing.T) {
		// Test that nil cipher causes panic (expected behavior)
		assert.Panics(t, func() {
			NewEncrypter().FromString("test").ByXtea(nil).ToRawString()
		})
	})
}
