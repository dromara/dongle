package crypto

import (
	"strings"
	"testing"

	"github.com/dromara/dongle/crypto/cipher"
	"github.com/stretchr/testify/assert"
)

// Test data constants
var (
	chaCha20Key   = []byte("dongle1234567890abcdef123456789x") // 32 bytes
	chaCha20Nonce = []byte("123456789012")                     // 12 bytes
	chaCha20Data  = []byte("hello world from chacha20")
)

func TestEncrypter_ByChaCha20(t *testing.T) {
	t.Run("standard_encryption", func(t *testing.T) {
		c := cipher.NewChaCha20Cipher()
		c.SetKey(chaCha20Key)
		c.SetNonce(chaCha20Nonce)

		encrypted := NewEncrypter().FromBytes(chaCha20Data).ByChaCha20(c).ToRawBytes()

		assert.NotEmpty(t, encrypted)
		assert.NotEqual(t, chaCha20Data, encrypted) // Should be different after encryption
	})

	t.Run("encryption_with_file_reader", func(t *testing.T) {
		c := cipher.NewChaCha20Cipher()
		c.SetKey(chaCha20Key)
		c.SetNonce(chaCha20Nonce)

		// Test streaming encryption with file reader
		file := strings.NewReader(string(chaCha20Data))
		e := NewEncrypter()
		e.reader = file // Set reader directly for stream processing
		encrypted := e.ByChaCha20(c).ToRawBytes()

		assert.NotEmpty(t, encrypted)
		assert.NotEqual(t, chaCha20Data, encrypted)
	})

	t.Run("encryption_with_existing_error", func(t *testing.T) {
		c := cipher.NewChaCha20Cipher()
		c.SetKey(chaCha20Key)
		c.SetNonce(chaCha20Nonce)

		// Create encrypter with existing error
		e := NewEncrypter()
		e.Error = assert.AnError // Set an error first
		result := e.ByChaCha20(c)

		assert.Equal(t, assert.AnError, result.Error)
		assert.Empty(t, result.ToRawBytes())
	})

	t.Run("encryption_with_empty_file_reader", func(t *testing.T) {
		c := cipher.NewChaCha20Cipher()
		c.SetKey(chaCha20Key)
		c.SetNonce(chaCha20Nonce)

		// Test streaming encryption with empty file reader
		emptyReader := strings.NewReader("")
		e := NewEncrypter()
		e.reader = emptyReader // Set reader directly for stream processing
		encrypted := e.ByChaCha20(c).ToRawBytes()

		assert.Empty(t, encrypted)
	})

	t.Run("standard_decryption", func(t *testing.T) {
		c := cipher.NewChaCha20Cipher()
		c.SetKey(chaCha20Key)
		c.SetNonce(chaCha20Nonce)

		// First encrypt
		encrypted := NewEncrypter().FromBytes(chaCha20Data).ByChaCha20(c).ToRawBytes()
		assert.NotEmpty(t, encrypted)

		// Then decrypt with fresh cipher (ChaCha20 is a stream cipher, needs fresh state)
		c2 := cipher.NewChaCha20Cipher()
		c2.SetKey(chaCha20Key)
		c2.SetNonce(chaCha20Nonce)

		decrypted := NewDecrypter().FromRawBytes(encrypted).ByChaCha20(c2).ToBytes()
		assert.Equal(t, chaCha20Data, decrypted)
	})

	t.Run("string_encryption_decryption", func(t *testing.T) {
		c1 := cipher.NewChaCha20Cipher()
		c1.SetKey(chaCha20Key)
		c1.SetNonce(chaCha20Nonce)

		plaintext := string(chaCha20Data)
		encrypted := NewEncrypter().FromString(plaintext).ByChaCha20(c1).ToRawString()
		assert.NotEmpty(t, encrypted)
		assert.NotEqual(t, plaintext, encrypted)

		// Decrypt with fresh cipher
		c2 := cipher.NewChaCha20Cipher()
		c2.SetKey(chaCha20Key)
		c2.SetNonce(chaCha20Nonce)

		decrypted := NewDecrypter().FromRawString(encrypted).ByChaCha20(c2).ToString()
		assert.Equal(t, plaintext, decrypted)
	})

	t.Run("encryption_with_invalid_key", func(t *testing.T) {
		c := cipher.NewChaCha20Cipher()
		c.SetKey([]byte("short")) // Invalid key size
		c.SetNonce(chaCha20Nonce)

		encrypted := NewEncrypter().FromBytes(chaCha20Data).ByChaCha20(c).ToRawBytes()
		assert.Empty(t, encrypted) // Should be empty due to error
	})

	t.Run("encryption_with_invalid_nonce", func(t *testing.T) {
		c := cipher.NewChaCha20Cipher()
		c.SetKey(chaCha20Key)
		c.SetNonce([]byte("short")) // Invalid nonce size

		encrypted := NewEncrypter().FromBytes(chaCha20Data).ByChaCha20(c).ToRawBytes()
		assert.Empty(t, encrypted) // Should be empty due to error
	})

	t.Run("empty_data", func(t *testing.T) {
		c := cipher.NewChaCha20Cipher()
		c.SetKey(chaCha20Key)
		c.SetNonce(chaCha20Nonce)

		encrypted := NewEncrypter().FromBytes([]byte{}).ByChaCha20(c).ToRawBytes()
		assert.Empty(t, encrypted) // ChaCha20 with empty data returns empty

		// Test with empty string
		encryptedStr := NewEncrypter().FromString("").ByChaCha20(c).ToRawString()
		assert.Empty(t, encryptedStr)

		// Test empty data decryption
		decrypted := NewDecrypter().FromRawBytes([]byte{}).ByChaCha20(c).ToBytes()
		assert.Empty(t, decrypted)

		// Test decryption of empty string
		decryptedStr := NewDecrypter().FromRawString("").ByChaCha20(c).ToString()
		assert.Empty(t, decryptedStr)
	})

	t.Run("decryption_with_invalid_key", func(t *testing.T) {
		c := cipher.NewChaCha20Cipher()
		c.SetKey([]byte("short")) // Invalid key size
		c.SetNonce(chaCha20Nonce)

		decrypted := NewDecrypter().FromRawBytes(chaCha20Data).ByChaCha20(c).ToBytes()
		assert.Empty(t, decrypted) // Should be empty due to error
	})

	t.Run("decryption_with_invalid_nonce", func(t *testing.T) {
		c := cipher.NewChaCha20Cipher()
		c.SetKey(chaCha20Key)
		c.SetNonce([]byte("short")) // Invalid nonce size

		decrypted := NewDecrypter().FromRawBytes(chaCha20Data).ByChaCha20(c).ToBytes()
		assert.Empty(t, decrypted) // Should be empty due to error
	})

	t.Run("decryption_with_file_reader", func(t *testing.T) {
		c1 := cipher.NewChaCha20Cipher()
		c1.SetKey(chaCha20Key)
		c1.SetNonce(chaCha20Nonce)

		// First encrypt the data
		encrypted := NewEncrypter().FromBytes(chaCha20Data).ByChaCha20(c1).ToRawBytes()
		assert.NotEmpty(t, encrypted)

		// Create a reader from the encrypted data
		reader := strings.NewReader(string(encrypted))

		// Test streaming decryption with file reader
		c2 := cipher.NewChaCha20Cipher()
		c2.SetKey(chaCha20Key)
		c2.SetNonce(chaCha20Nonce)

		d := NewDecrypter()
		d.reader = reader // Set reader directly for stream processing
		decrypted := d.ByChaCha20(c2).ToBytes()
		assert.Equal(t, chaCha20Data, decrypted)
	})

	t.Run("decryption_with_existing_error", func(t *testing.T) {
		c := cipher.NewChaCha20Cipher()
		c.SetKey(chaCha20Key)
		c.SetNonce(chaCha20Nonce)

		// Create decrypter with existing error
		d := NewDecrypter()
		d.Error = assert.AnError // Set an error first
		result := d.ByChaCha20(c)

		assert.Equal(t, assert.AnError, result.Error)
		assert.Empty(t, result.ToBytes())
	})

	t.Run("decryption_with_empty_file_reader", func(t *testing.T) {
		c := cipher.NewChaCha20Cipher()
		c.SetKey(chaCha20Key)
		c.SetNonce(chaCha20Nonce)

		// Test streaming decryption with empty file reader
		emptyReader := strings.NewReader("")
		d := NewDecrypter()
		d.reader = emptyReader // Set reader directly for stream processing
		decrypted := d.ByChaCha20(c).ToBytes()

		assert.Empty(t, decrypted)
	})
}
