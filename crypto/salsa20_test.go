package crypto

import (
	"strings"
	"testing"

	"github.com/dromara/dongle/crypto/cipher"
	"github.com/stretchr/testify/assert"
)

// Test data constants
var (
	salsa20Key   = []byte("dongle1234567890abcdef123456789x") // 32 bytes
	salsa20Nonce = []byte("12345678")                         // 8 bytes
	salsa20Data  = []byte("hello world from salsa20")
)

func TestEncrypter_BySalsa20(t *testing.T) {
	t.Run("standard_encryption", func(t *testing.T) {
		c := cipher.NewSalsa20Cipher()
		c.SetKey(salsa20Key)
		c.SetNonce(salsa20Nonce)

		encrypted := NewEncrypter().FromBytes(salsa20Data).BySalsa20(c).ToRawBytes()

		assert.NotEmpty(t, encrypted)
		assert.NotEqual(t, salsa20Data, encrypted) // Should be different after encryption
	})

	t.Run("encryption_with_file_reader", func(t *testing.T) {
		c := cipher.NewSalsa20Cipher()
		c.SetKey(salsa20Key)
		c.SetNonce(salsa20Nonce)

		// Test streaming encryption with file reader
		file := strings.NewReader(string(salsa20Data))
		e := NewEncrypter()
		e.reader = file // Set reader directly for stream processing
		encrypted := e.BySalsa20(c).ToRawBytes()

		assert.NotEmpty(t, encrypted)
		assert.NotEqual(t, salsa20Data, encrypted)
	})

	t.Run("encryption_with_existing_error", func(t *testing.T) {
		c := cipher.NewSalsa20Cipher()
		c.SetKey(salsa20Key)
		c.SetNonce(salsa20Nonce)

		// Create encrypter with existing error
		e := NewEncrypter()
		e.Error = assert.AnError // Set an error first
		result := e.BySalsa20(c)

		assert.Equal(t, assert.AnError, result.Error)
		assert.Empty(t, result.ToRawBytes())
	})

	t.Run("encryption_with_empty_file_reader", func(t *testing.T) {
		c := cipher.NewSalsa20Cipher()
		c.SetKey(salsa20Key)
		c.SetNonce(salsa20Nonce)

		// Test streaming encryption with empty file reader
		emptyReader := strings.NewReader("")
		e := NewEncrypter()
		e.reader = emptyReader // Set reader directly for stream processing
		encrypted := e.BySalsa20(c).ToRawBytes()

		assert.Empty(t, encrypted)
	})

	t.Run("standard_decryption", func(t *testing.T) {
		c := cipher.NewSalsa20Cipher()
		c.SetKey(salsa20Key)
		c.SetNonce(salsa20Nonce)

		// First encrypt
		encrypted := NewEncrypter().FromBytes(salsa20Data).BySalsa20(c).ToRawBytes()
		assert.NotEmpty(t, encrypted)

		// Then decrypt with fresh cipher (Salsa20 is a stream cipher, needs fresh state)
		c2 := cipher.NewSalsa20Cipher()
		c2.SetKey(salsa20Key)
		c2.SetNonce(salsa20Nonce)

		decrypted := NewDecrypter().FromRawBytes(encrypted).BySalsa20(c2).ToBytes()
		assert.Equal(t, salsa20Data, decrypted)
	})

	t.Run("string_encryption_decryption", func(t *testing.T) {
		c1 := cipher.NewSalsa20Cipher()
		c1.SetKey(salsa20Key)
		c1.SetNonce(salsa20Nonce)

		plaintext := string(salsa20Data)
		encrypted := NewEncrypter().FromString(plaintext).BySalsa20(c1).ToRawString()
		assert.NotEmpty(t, encrypted)
		assert.NotEqual(t, plaintext, encrypted)

		// Decrypt with fresh cipher
		c2 := cipher.NewSalsa20Cipher()
		c2.SetKey(salsa20Key)
		c2.SetNonce(salsa20Nonce)

		decrypted := NewDecrypter().FromRawString(encrypted).BySalsa20(c2).ToString()
		assert.Equal(t, plaintext, decrypted)
	})

	t.Run("encryption_with_invalid_key", func(t *testing.T) {
		c := cipher.NewSalsa20Cipher()
		c.SetKey([]byte("short")) // Invalid key size
		c.SetNonce(salsa20Nonce)

		encrypted := NewEncrypter().FromBytes(salsa20Data).BySalsa20(c).ToRawBytes()
		assert.Empty(t, encrypted) // Should be empty due to error
	})

	t.Run("encryption_with_invalid_nonce", func(t *testing.T) {
		c := cipher.NewSalsa20Cipher()
		c.SetKey(salsa20Key)
		c.SetNonce([]byte("short")) // Invalid nonce size

		encrypted := NewEncrypter().FromBytes(salsa20Data).BySalsa20(c).ToRawBytes()
		assert.Empty(t, encrypted) // Should be empty due to error
	})

	t.Run("empty_data", func(t *testing.T) {
		c := cipher.NewSalsa20Cipher()
		c.SetKey(salsa20Key)
		c.SetNonce(salsa20Nonce)

		encrypted := NewEncrypter().FromBytes([]byte{}).BySalsa20(c).ToRawBytes()
		assert.Empty(t, encrypted) // Salsa20 with empty data returns empty

		// Test with empty string
		encryptedStr := NewEncrypter().FromString("").BySalsa20(c).ToRawString()
		assert.Empty(t, encryptedStr)

		// Test empty data decryption
		decrypted := NewDecrypter().FromRawBytes([]byte{}).BySalsa20(c).ToBytes()
		assert.Empty(t, decrypted)

		// Test decryption of empty string
		decryptedStr := NewDecrypter().FromRawString("").BySalsa20(c).ToString()
		assert.Empty(t, decryptedStr)
	})

	t.Run("decryption_with_invalid_key", func(t *testing.T) {
		c := cipher.NewSalsa20Cipher()
		c.SetKey([]byte("short")) // Invalid key size
		c.SetNonce(salsa20Nonce)

		decrypted := NewDecrypter().FromRawBytes(salsa20Data).BySalsa20(c).ToBytes()
		assert.Empty(t, decrypted) // Should be empty due to error
	})

	t.Run("decryption_with_invalid_nonce", func(t *testing.T) {
		c := cipher.NewSalsa20Cipher()
		c.SetKey(salsa20Key)
		c.SetNonce([]byte("short")) // Invalid nonce size

		decrypted := NewDecrypter().FromRawBytes(salsa20Data).BySalsa20(c).ToBytes()
		assert.Empty(t, decrypted) // Should be empty due to error
	})

	t.Run("decryption_with_file_reader", func(t *testing.T) {
		c1 := cipher.NewSalsa20Cipher()
		c1.SetKey(salsa20Key)
		c1.SetNonce(salsa20Nonce)

		// First encrypt the data
		encrypted := NewEncrypter().FromBytes(salsa20Data).BySalsa20(c1).ToRawBytes()
		assert.NotEmpty(t, encrypted)

		// Create a reader from the encrypted data
		reader := strings.NewReader(string(encrypted))

		// Test streaming decryption with file reader
		c2 := cipher.NewSalsa20Cipher()
		c2.SetKey(salsa20Key)
		c2.SetNonce(salsa20Nonce)

		d := NewDecrypter()
		d.reader = reader // Set reader directly for stream processing
		decrypted := d.BySalsa20(c2).ToBytes()
		assert.Equal(t, salsa20Data, decrypted)
	})

	t.Run("decryption_with_existing_error", func(t *testing.T) {
		c := cipher.NewSalsa20Cipher()
		c.SetKey(salsa20Key)
		c.SetNonce(salsa20Nonce)

		// Create decrypter with existing error
		d := NewDecrypter()
		d.Error = assert.AnError // Set an error first
		result := d.BySalsa20(c)

		assert.Equal(t, assert.AnError, result.Error)
		assert.Empty(t, result.ToBytes())
	})

	t.Run("decryption_with_empty_file_reader", func(t *testing.T) {
		c := cipher.NewSalsa20Cipher()
		c.SetKey(salsa20Key)
		c.SetNonce(salsa20Nonce)

		// Test streaming decryption with empty file reader
		emptyReader := strings.NewReader("")
		d := NewDecrypter()
		d.reader = emptyReader // Set reader directly for stream processing
		decrypted := d.BySalsa20(c).ToBytes()

		assert.Empty(t, decrypted)
	})

	t.Run("encryption_with_nil_src", func(t *testing.T) {
		c := cipher.NewSalsa20Cipher()
		c.SetKey(salsa20Key)
		c.SetNonce(salsa20Nonce)

		// Test with nil src and no reader
		e := NewEncrypter()
		e.src = nil
		e.reader = nil
		result := e.BySalsa20(c)

		assert.Nil(t, result.Error)
		assert.Empty(t, result.ToRawBytes())
	})

	t.Run("decryption_with_nil_src", func(t *testing.T) {
		c := cipher.NewSalsa20Cipher()
		c.SetKey(salsa20Key)
		c.SetNonce(salsa20Nonce)

		// Test with nil src and no reader
		d := NewDecrypter()
		d.src = nil
		d.reader = nil
		result := d.BySalsa20(c)

		assert.Nil(t, result.Error)
		assert.Empty(t, result.ToBytes())
	})

	t.Run("encryption_with_empty_src_and_no_reader", func(t *testing.T) {
		c := cipher.NewSalsa20Cipher()
		c.SetKey(salsa20Key)
		c.SetNonce(salsa20Nonce)

		// Test with empty src and no reader
		e := NewEncrypter()
		e.src = []byte{}
		e.reader = nil
		result := e.BySalsa20(c)

		assert.Nil(t, result.Error)
		assert.Empty(t, result.ToRawBytes())
	})

	t.Run("decryption_with_empty_src_and_no_reader", func(t *testing.T) {
		c := cipher.NewSalsa20Cipher()
		c.SetKey(salsa20Key)
		c.SetNonce(salsa20Nonce)

		// Test with empty src and no reader
		d := NewDecrypter()
		d.src = []byte{}
		d.reader = nil
		result := d.BySalsa20(c)

		assert.Nil(t, result.Error)
		assert.Empty(t, result.ToBytes())
	})

	t.Run("encryption_with_reader_set_streaming_branch", func(t *testing.T) {
		c := cipher.NewSalsa20Cipher()
		c.SetKey(salsa20Key)
		c.SetNonce(salsa20Nonce)

		// Test streaming encryption branch
		file := strings.NewReader(string(salsa20Data))
		e := NewEncrypter()
		e.reader = file
		result := e.BySalsa20(c)

		assert.Nil(t, result.Error)
		assert.NotEmpty(t, result.ToRawBytes())
	})

	t.Run("decryption_with_reader_set_streaming_branch", func(t *testing.T) {
		c1 := cipher.NewSalsa20Cipher()
		c1.SetKey(salsa20Key)
		c1.SetNonce(salsa20Nonce)

		// First encrypt the data
		encrypted := NewEncrypter().FromBytes(salsa20Data).BySalsa20(c1).ToRawBytes()
		assert.NotEmpty(t, encrypted)

		// Test streaming decryption branch
		reader := strings.NewReader(string(encrypted))
		c2 := cipher.NewSalsa20Cipher()
		c2.SetKey(salsa20Key)
		c2.SetNonce(salsa20Nonce)

		d := NewDecrypter()
		d.reader = reader
		result := d.BySalsa20(c2)

		assert.Nil(t, result.Error)
		assert.Equal(t, salsa20Data, result.ToBytes())
	})

	t.Run("encryption_with_large_data", func(t *testing.T) {
		c := cipher.NewSalsa20Cipher()
		c.SetKey(salsa20Key)
		c.SetNonce(salsa20Nonce)

		// Test with large data
		largeData := make([]byte, 10000)
		for i := range largeData {
			largeData[i] = byte(i % 256)
		}

		encrypted := NewEncrypter().FromBytes(largeData).BySalsa20(c).ToRawBytes()
		assert.NotEmpty(t, encrypted)
		assert.NotEqual(t, largeData, encrypted)

		// Decrypt and verify
		c2 := cipher.NewSalsa20Cipher()
		c2.SetKey(salsa20Key)
		c2.SetNonce(salsa20Nonce)

		decrypted := NewDecrypter().FromRawBytes(encrypted).BySalsa20(c2).ToBytes()
		assert.Equal(t, largeData, decrypted)
	})

	t.Run("encryption_with_binary_data", func(t *testing.T) {
		c := cipher.NewSalsa20Cipher()
		c.SetKey(salsa20Key)
		c.SetNonce(salsa20Nonce)

		// Test with binary data
		binaryData := []byte{0x00, 0x01, 0x02, 0x03, 0xFF, 0xFE, 0xFD, 0xFC}

		encrypted := NewEncrypter().FromBytes(binaryData).BySalsa20(c).ToRawBytes()
		assert.NotEmpty(t, encrypted)
		assert.NotEqual(t, binaryData, encrypted)

		// Decrypt and verify
		c2 := cipher.NewSalsa20Cipher()
		c2.SetKey(salsa20Key)
		c2.SetNonce(salsa20Nonce)

		decrypted := NewDecrypter().FromRawBytes(encrypted).BySalsa20(c2).ToBytes()
		assert.Equal(t, binaryData, decrypted)
	})

	t.Run("encryption_with_unicode_data", func(t *testing.T) {
		c := cipher.NewSalsa20Cipher()
		c.SetKey(salsa20Key)
		c.SetNonce(salsa20Nonce)

		// Test with unicode data
		unicodeData := []byte("Hello 世界 🌍 测试")

		encrypted := NewEncrypter().FromBytes(unicodeData).BySalsa20(c).ToRawBytes()
		assert.NotEmpty(t, encrypted)
		assert.NotEqual(t, unicodeData, encrypted)

		// Decrypt and verify
		c2 := cipher.NewSalsa20Cipher()
		c2.SetKey(salsa20Key)
		c2.SetNonce(salsa20Nonce)

		decrypted := NewDecrypter().FromRawBytes(encrypted).BySalsa20(c2).ToBytes()
		assert.Equal(t, unicodeData, decrypted)
	})
}
