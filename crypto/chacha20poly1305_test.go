package crypto

import (
	"bytes"
	"strings"
	"testing"

	"github.com/dromara/dongle/crypto/cipher"
	"github.com/stretchr/testify/assert"
)

var chaCha20Poly1305Data = []byte("hello world from chacha20poly1305")

func TestEncrypter_ByChaCha20Poly1305(t *testing.T) {
	key := []byte("dongle1234567890abcdef123456789x") // 32 bytes
	nonce := []byte("123456789012")                   // 12 bytes
	aad := []byte("additional authenticated data")

	c := cipher.NewChaCha20Poly1305Cipher()
	c.SetKey(key)
	c.SetNonce(nonce)
	c.SetAAD(aad)

	t.Run("normal encrypt", func(t *testing.T) {
		encrypted := NewEncrypter().FromBytes(chaCha20Poly1305Data).ByChaCha20Poly1305(c).ToRawBytes()
		assert.NotEmpty(t, encrypted)
		assert.NotEqual(t, chaCha20Poly1305Data, encrypted)
		// ChaCha20-Poly1305 adds 16-byte authentication tag
		assert.Equal(t, len(chaCha20Poly1305Data)+16, len(encrypted))
	})

	t.Run("empty data encrypt", func(t *testing.T) {
		e := NewEncrypter().FromBytes([]byte{})
		result := e.ByChaCha20Poly1305(c)
		assert.Nil(t, result.Error)
		assert.Empty(t, result.ToRawBytes())
	})

	t.Run("stream encrypt", func(t *testing.T) {
		e := NewEncrypter().FromString("hello world").ByChaCha20Poly1305(c)
		assert.Nil(t, e.Error)
		assert.NotEmpty(t, e.ToRawBytes())
	})

	t.Run("encrypt with invalid key", func(t *testing.T) {
		invalidCipher := cipher.NewChaCha20Poly1305Cipher()
		invalidCipher.SetKey([]byte("short")) // Invalid key size
		invalidCipher.SetNonce(nonce)

		e := NewEncrypter().FromBytes(chaCha20Poly1305Data)
		result := e.ByChaCha20Poly1305(invalidCipher)
		assert.NotNil(t, result.Error)
		assert.Contains(t, result.Error.Error(), "invalid key size")
	})

	t.Run("encrypt with invalid nonce", func(t *testing.T) {
		invalidCipher := cipher.NewChaCha20Poly1305Cipher()
		invalidCipher.SetKey(key)
		invalidCipher.SetNonce([]byte("short")) // Invalid nonce size

		e := NewEncrypter().FromBytes(chaCha20Poly1305Data)
		result := e.ByChaCha20Poly1305(invalidCipher)
		assert.NotNil(t, result.Error)
		assert.Contains(t, result.Error.Error(), "invalid nonce size")
	})

	t.Run("encrypt from string", func(t *testing.T) {
		encrypted := NewEncrypter().FromString("hello world").ByChaCha20Poly1305(c).ToRawBytes()
		assert.NotEmpty(t, encrypted)
		assert.NotEqual(t, []byte("hello world"), encrypted)
	})

	t.Run("encrypt with error state", func(t *testing.T) {
		e := NewEncrypter().FromBytes(chaCha20Poly1305Data)
		e.Error = assert.AnError // Set error state
		result := e.ByChaCha20Poly1305(c)
		assert.Equal(t, assert.AnError, result.Error)
	})

	t.Run("encrypt from reader", func(t *testing.T) {
		reader := strings.NewReader("hello world from reader")
		e := NewEncrypter()
		e.reader = reader // Set reader directly for stream processing
		result := e.ByChaCha20Poly1305(c)
		assert.Nil(t, result.Error)
		assert.NotEmpty(t, result.ToRawBytes())
	})

	t.Run("encrypt from reader with error", func(t *testing.T) {
		invalidCipher := cipher.NewChaCha20Poly1305Cipher()
		invalidCipher.SetKey([]byte("short"))

		reader := strings.NewReader("test data")
		e := NewEncrypter()
		e.reader = reader // Set reader directly for stream processing
		result := e.ByChaCha20Poly1305(invalidCipher)
		assert.NotNil(t, result.Error)
	})
}

func TestDecrypter_ByChaCha20Poly1305(t *testing.T) {
	key := []byte("dongle1234567890abcdef123456789x") // 32 bytes
	nonce := []byte("123456789012")                   // 12 bytes
	aad := []byte("additional authenticated data")

	c := cipher.NewChaCha20Poly1305Cipher()
	c.SetKey(key)
	c.SetNonce(nonce)
	c.SetAAD(aad)

	t.Run("normal decrypt", func(t *testing.T) {
		encrypted := NewEncrypter().FromBytes(chaCha20Poly1305Data).ByChaCha20Poly1305(c).ToRawBytes()

		c2 := cipher.NewChaCha20Poly1305Cipher()
		c2.SetKey(key)
		c2.SetNonce(nonce)
		c2.SetAAD(aad)

		decrypted := NewDecrypter().FromRawBytes(encrypted).ByChaCha20Poly1305(c2).ToBytes()
		assert.Equal(t, chaCha20Poly1305Data, decrypted)
	})

	t.Run("decrypt from string", func(t *testing.T) {
		plaintext := "hello world from chacha20poly1305"

		c1 := cipher.NewChaCha20Poly1305Cipher()
		c1.SetKey(key)
		c1.SetNonce(nonce)
		c1.SetAAD(aad)

		encrypted := NewEncrypter().FromString(plaintext).ByChaCha20Poly1305(c1).ToRawString()

		c2 := cipher.NewChaCha20Poly1305Cipher()
		c2.SetKey(key)
		c2.SetNonce(nonce)
		c2.SetAAD(aad)

		decrypted := NewDecrypter().FromRawString(encrypted).ByChaCha20Poly1305(c2).ToString()
		assert.Equal(t, plaintext, decrypted)
	})

	t.Run("empty data decrypt", func(t *testing.T) {
		// Test empty source data
		d := NewDecrypter().FromRawBytes([]byte{})
		result := d.ByChaCha20Poly1305(c)
		assert.Nil(t, result.Error)
		assert.Empty(t, result.ToBytes())

		// Test empty string
		decryptedStr := NewDecrypter().FromRawString("").ByChaCha20Poly1305(c).ToString()
		assert.Empty(t, decryptedStr)
	})

	t.Run("stream decrypt", func(t *testing.T) {
		// First encrypt some data
		encrypted := NewEncrypter().FromString("hello world").ByChaCha20Poly1305(c).ToRawString()

		// Then decrypt using stream
		d := NewDecrypter().FromRawString(encrypted).ByChaCha20Poly1305(c)
		assert.Nil(t, d.Error)
		assert.Equal(t, "hello world", d.ToString())
	})

	t.Run("decrypt invalid data", func(t *testing.T) {
		d := NewDecrypter().FromRawBytes(chaCha20Poly1305Data) // Raw data, not encrypted
		result := d.ByChaCha20Poly1305(c)
		assert.NotNil(t, result.Error)
		assert.Contains(t, result.Error.Error(), "message authentication failed")
	})

	t.Run("decrypt tampered data", func(t *testing.T) {
		encrypted := NewEncrypter().FromBytes(chaCha20Poly1305Data).ByChaCha20Poly1305(c).ToRawBytes()

		// Tamper with the encrypted data
		tamperedData := make([]byte, len(encrypted))
		copy(tamperedData, encrypted)
		tamperedData[0] ^= 1 // Flip one bit

		d := NewDecrypter().FromRawBytes(tamperedData)
		result := d.ByChaCha20Poly1305(c)
		assert.NotNil(t, result.Error)
		assert.Contains(t, result.Error.Error(), "message authentication failed")
	})

	t.Run("decrypt with invalid key", func(t *testing.T) {
		encrypted := NewEncrypter().FromBytes(chaCha20Poly1305Data).ByChaCha20Poly1305(c).ToRawBytes()

		invalidCipher := cipher.NewChaCha20Poly1305Cipher()
		invalidCipher.SetKey([]byte("short")) // Wrong key size
		invalidCipher.SetNonce(nonce)

		d := NewDecrypter().FromRawBytes(encrypted)
		result := d.ByChaCha20Poly1305(invalidCipher)
		assert.NotNil(t, result.Error)
		assert.Contains(t, result.Error.Error(), "invalid key size")
	})

	t.Run("decrypt with wrong aad", func(t *testing.T) {
		// Encrypt with one AAD
		c1 := cipher.NewChaCha20Poly1305Cipher()
		c1.SetKey(key)
		c1.SetNonce(nonce)
		c1.SetAAD([]byte("original aad"))

		encrypted := NewEncrypter().FromBytes(chaCha20Poly1305Data).ByChaCha20Poly1305(c1).ToRawBytes()

		// Try to decrypt with different AAD
		c2 := cipher.NewChaCha20Poly1305Cipher()
		c2.SetKey(key)
		c2.SetNonce(nonce)
		c2.SetAAD([]byte("different aad"))

		d := NewDecrypter().FromRawBytes(encrypted)
		result := d.ByChaCha20Poly1305(c2)
		assert.NotNil(t, result.Error)
		assert.Contains(t, result.Error.Error(), "message authentication failed")
	})

	t.Run("decrypt with error state", func(t *testing.T) {
		d := NewDecrypter()
		d.Error = assert.AnError // Set error state
		result := d.ByChaCha20Poly1305(c)
		assert.Equal(t, assert.AnError, result.Error)
	})

	t.Run("decrypt from reader", func(t *testing.T) {
		// First encrypt some data to bytes
		encrypted := NewEncrypter().FromBytes(chaCha20Poly1305Data).ByChaCha20Poly1305(c).ToRawBytes()

		// Create reader from encrypted data
		reader := bytes.NewReader(encrypted)
		d := NewDecrypter()
		d.reader = reader // Set reader directly for stream processing
		result := d.ByChaCha20Poly1305(c)
		assert.Nil(t, result.Error)
		assert.Equal(t, chaCha20Poly1305Data, result.ToBytes())
	})

	t.Run("decrypt from reader with error", func(t *testing.T) {
		invalidCipher := cipher.NewChaCha20Poly1305Cipher()
		invalidCipher.SetKey([]byte("short"))

		reader := bytes.NewReader([]byte("fake encrypted data"))
		d := NewDecrypter()
		d.reader = reader // Set reader directly for stream processing
		result := d.ByChaCha20Poly1305(invalidCipher)
		assert.NotNil(t, result.Error)
	})
}
