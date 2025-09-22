package twofish

import (
	"testing"

	"github.com/dromara/dongle/crypto/cipher"
	"github.com/stretchr/testify/assert"
)

// Test data for Twofish CBC mode
var (
	twofishKey128 = []byte("1234567890123456")                 // 16-byte key for Twofish-128
	twofishKey192 = []byte("123456789012345678901234")         // 24-byte key for Twofish-192
	twofishKey256 = []byte("12345678901234567890123456789012") // 32-byte key for Twofish-256
	twofishIV     = []byte("1234567890123456")                 // 16-byte IV for Twofish (block size)
	twofishSrc    = []byte("hello world")
)

func TestTwofishCBC_Encrypt(t *testing.T) {
	t.Run("encrypt with 128-bit key", func(t *testing.T) {
		c := cipher.NewTwofishCipher(cipher.CBC)
		c.SetKey(twofishKey128)
		c.SetIV(twofishIV)

		encrypter := NewStdEncrypter(c)
		encrypted, err := encrypter.Encrypt(twofishSrc)

		assert.Nil(t, err)
		assert.NotEmpty(t, encrypted)
		assert.NotEqual(t, twofishSrc, encrypted)
	})

	t.Run("encrypt with 192-bit key", func(t *testing.T) {
		c := cipher.NewTwofishCipher(cipher.CBC)
		c.SetKey(twofishKey192)
		c.SetIV(twofishIV)

		encrypter := NewStdEncrypter(c)
		encrypted, err := encrypter.Encrypt(twofishSrc)

		assert.Nil(t, err)
		assert.NotEmpty(t, encrypted)
		assert.NotEqual(t, twofishSrc, encrypted)
	})

	t.Run("encrypt with 256-bit key", func(t *testing.T) {
		c := cipher.NewTwofishCipher(cipher.CBC)
		c.SetKey(twofishKey256)
		c.SetIV(twofishIV)

		encrypter := NewStdEncrypter(c)
		encrypted, err := encrypter.Encrypt(twofishSrc)

		assert.Nil(t, err)
		assert.NotEmpty(t, encrypted)
		assert.NotEqual(t, twofishSrc, encrypted)
	})

	t.Run("encrypt empty data", func(t *testing.T) {
		c := cipher.NewTwofishCipher(cipher.CBC)
		c.SetKey(twofishKey128)
		c.SetIV(twofishIV)

		encrypter := NewStdEncrypter(c)
		encrypted, err := encrypter.Encrypt([]byte{})

		assert.Nil(t, err)
		assert.Empty(t, encrypted)
	})
}

func TestTwofishCBC_Decrypt(t *testing.T) {
	t.Run("decrypt with 128-bit key", func(t *testing.T) {
		c := cipher.NewTwofishCipher(cipher.CBC)
		c.SetKey(twofishKey128)
		c.SetIV(twofishIV)

		// First encrypt
		encrypter := NewStdEncrypter(c)
		encrypted, err := encrypter.Encrypt(twofishSrc)
		assert.Nil(t, err)

		// Then decrypt
		decrypter := NewStdDecrypter(c)
		decrypted, err := decrypter.Decrypt(encrypted)

		assert.Nil(t, err)
		assert.Equal(t, twofishSrc, decrypted)
	})

	t.Run("decrypt with 192-bit key", func(t *testing.T) {
		c := cipher.NewTwofishCipher(cipher.CBC)
		c.SetKey(twofishKey192)
		c.SetIV(twofishIV)

		// First encrypt
		encrypter := NewStdEncrypter(c)
		encrypted, err := encrypter.Encrypt(twofishSrc)
		assert.Nil(t, err)

		// Then decrypt
		decrypter := NewStdDecrypter(c)
		decrypted, err := decrypter.Decrypt(encrypted)

		assert.Nil(t, err)
		assert.Equal(t, twofishSrc, decrypted)
	})

	t.Run("decrypt with 256-bit key", func(t *testing.T) {
		c := cipher.NewTwofishCipher(cipher.CBC)
		c.SetKey(twofishKey256)
		c.SetIV(twofishIV)

		// First encrypt
		encrypter := NewStdEncrypter(c)
		encrypted, err := encrypter.Encrypt(twofishSrc)
		assert.Nil(t, err)

		// Then decrypt
		decrypter := NewStdDecrypter(c)
		decrypted, err := decrypter.Decrypt(encrypted)

		assert.Nil(t, err)
		assert.Equal(t, twofishSrc, decrypted)
	})

	t.Run("decrypt empty data", func(t *testing.T) {
		c := cipher.NewTwofishCipher(cipher.CBC)
		c.SetKey(twofishKey128)
		c.SetIV(twofishIV)

		decrypter := NewStdDecrypter(c)
		decrypted, err := decrypter.Decrypt([]byte{})

		assert.Nil(t, err)
		assert.Empty(t, decrypted)
	})
}

func TestTwofishCBC_RoundTrip(t *testing.T) {
	t.Run("round trip with 128-bit key", func(t *testing.T) {
		c := cipher.NewTwofishCipher(cipher.CBC)
		c.SetKey(twofishKey128)
		c.SetIV(twofishIV)

		encrypter := NewStdEncrypter(c)
		encrypted, err := encrypter.Encrypt(twofishSrc)
		assert.Nil(t, err)

		decrypter := NewStdDecrypter(c)
		decrypted, err := decrypter.Decrypt(encrypted)
		assert.Nil(t, err)

		assert.Equal(t, twofishSrc, decrypted)
	})

	t.Run("round trip with 192-bit key", func(t *testing.T) {
		c := cipher.NewTwofishCipher(cipher.CBC)
		c.SetKey(twofishKey192)
		c.SetIV(twofishIV)

		encrypter := NewStdEncrypter(c)
		encrypted, err := encrypter.Encrypt(twofishSrc)
		assert.Nil(t, err)

		decrypter := NewStdDecrypter(c)
		decrypted, err := decrypter.Decrypt(encrypted)
		assert.Nil(t, err)

		assert.Equal(t, twofishSrc, decrypted)
	})

	t.Run("round trip with 256-bit key", func(t *testing.T) {
		c := cipher.NewTwofishCipher(cipher.CBC)
		c.SetKey(twofishKey256)
		c.SetIV(twofishIV)

		encrypter := NewStdEncrypter(c)
		encrypted, err := encrypter.Encrypt(twofishSrc)
		assert.Nil(t, err)

		decrypter := NewStdDecrypter(c)
		decrypted, err := decrypter.Decrypt(encrypted)
		assert.Nil(t, err)

		assert.Equal(t, twofishSrc, decrypted)
	})
}
