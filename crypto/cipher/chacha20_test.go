package cipher

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestChaCha20Cipher_SetKey tests the SetKey method (inherited from baseCipher)
func TestChaCha20Cipher_SetKey(t *testing.T) {
	t.Run("set 32 byte key", func(t *testing.T) {
		cipher := NewChaCha20Cipher()
		key := []byte("12345678901234567890123456789012") // 32 bytes

		cipher.SetKey(key)
		assert.Equal(t, key, cipher.Key)
		assert.Len(t, cipher.Key, 32)
	})

	t.Run("set empty key", func(t *testing.T) {
		cipher := NewChaCha20Cipher()
		var key []byte

		cipher.SetKey(key)
		assert.Equal(t, key, cipher.Key)
		assert.Empty(t, cipher.Key)
	})

	t.Run("set nil key", func(t *testing.T) {
		cipher := NewChaCha20Cipher()

		cipher.SetKey(nil)
		assert.Nil(t, cipher.Key)
	})

	t.Run("set short key", func(t *testing.T) {
		cipher := NewChaCha20Cipher()
		key := []byte("shortkey")

		cipher.SetKey(key)
		assert.Equal(t, key, cipher.Key)
		assert.Len(t, cipher.Key, 8)
	})

	t.Run("set long key", func(t *testing.T) {
		cipher := NewChaCha20Cipher()
		key := []byte("this is a very long key that exceeds 32 bytes length")

		cipher.SetKey(key)
		assert.Equal(t, key, cipher.Key)
		assert.Len(t, cipher.Key, len(key))
	})

	t.Run("overwrite existing key", func(t *testing.T) {
		cipher := NewChaCha20Cipher()
		key1 := []byte("firstkeyfirstkeyfirstkeyfirstkey") // 32 bytes
		key2 := []byte("secondkeysecondkeysecondkeysecon") // 32 bytes

		cipher.SetKey(key1)
		assert.Equal(t, key1, cipher.Key)

		cipher.SetKey(key2)
		assert.Equal(t, key2, cipher.Key)
		assert.NotEqual(t, key1, cipher.Key)
	})

	t.Run("set key with special characters", func(t *testing.T) {
		cipher := NewChaCha20Cipher()
		key := []byte("special!@#$%^&*()chars_123456789")

		cipher.SetKey(key)
		assert.Equal(t, key, cipher.Key)
	})

	t.Run("set key with binary data", func(t *testing.T) {
		cipher := NewChaCha20Cipher()
		key := make([]byte, 32)
		for i := range key {
			key[i] = byte(i % 256)
		}

		cipher.SetKey(key)
		assert.Equal(t, key, cipher.Key)
		assert.Len(t, cipher.Key, 32)
	})
}

// TestChaCha20Cipher_SetNonce tests the SetNonce method
func TestChaCha20Cipher_SetNonce(t *testing.T) {
	t.Run("set 12 byte nonce", func(t *testing.T) {
		cipher := NewChaCha20Cipher()
		nonce := []byte("123456789012") // 12 bytes

		cipher.SetNonce(nonce)
		assert.Equal(t, nonce, cipher.Nonce)
		assert.Len(t, cipher.Nonce, 12)
	})

	t.Run("set empty nonce", func(t *testing.T) {
		cipher := NewChaCha20Cipher()
		var nonce []byte

		cipher.SetNonce(nonce)
		assert.Equal(t, nonce, cipher.Nonce)
		assert.Empty(t, cipher.Nonce)
	})

	t.Run("set nil nonce", func(t *testing.T) {
		cipher := NewChaCha20Cipher()

		cipher.SetNonce(nil)
		assert.Nil(t, cipher.Nonce)
	})

	t.Run("set short nonce", func(t *testing.T) {
		cipher := NewChaCha20Cipher()
		nonce := []byte("short")

		cipher.SetNonce(nonce)
		assert.Equal(t, nonce, cipher.Nonce)
		assert.Len(t, cipher.Nonce, 5)
	})

	t.Run("set long nonce", func(t *testing.T) {
		cipher := NewChaCha20Cipher()
		nonce := []byte("this is a very long nonce")

		cipher.SetNonce(nonce)
		assert.Equal(t, nonce, cipher.Nonce)
		assert.Len(t, cipher.Nonce, len(nonce))
	})

	t.Run("overwrite existing nonce", func(t *testing.T) {
		cipher := NewChaCha20Cipher()
		nonce1 := []byte("firstnonce12")
		nonce2 := []byte("secondnonce1")

		cipher.SetNonce(nonce1)
		assert.Equal(t, nonce1, cipher.Nonce)

		cipher.SetNonce(nonce2)
		assert.Equal(t, nonce2, cipher.Nonce)
		assert.NotEqual(t, nonce1, cipher.Nonce)
	})

	t.Run("set nonce with special characters", func(t *testing.T) {
		cipher := NewChaCha20Cipher()
		nonce := []byte("!@#$%^&*()12")

		cipher.SetNonce(nonce)
		assert.Equal(t, nonce, cipher.Nonce)
	})

	t.Run("set nonce with binary data", func(t *testing.T) {
		cipher := NewChaCha20Cipher()
		nonce := make([]byte, 12)
		for i := range nonce {
			nonce[i] = byte(i % 256)
		}

		cipher.SetNonce(nonce)
		assert.Equal(t, nonce, cipher.Nonce)
		assert.Len(t, cipher.Nonce, 12)
	})

	t.Run("nonce independent from key", func(t *testing.T) {
		cipher := NewChaCha20Cipher()
		key := []byte("testkeyfortestingtestkeyfortesti") // 32 bytes
		nonce := []byte("testnonce123")                   // 12 bytes

		cipher.SetKey(key)
		cipher.SetNonce(nonce)

		assert.Equal(t, key, cipher.Key)
		assert.Equal(t, nonce, cipher.Nonce)

		// Setting key should not affect nonce
		newKey := []byte("newkeyfornewkeynewkeyfornewkeyn") // 32 bytes
		cipher.SetKey(newKey)
		assert.Equal(t, newKey, cipher.Key)
		assert.Equal(t, nonce, cipher.Nonce) // nonce unchanged

		// Setting nonce should not affect key
		newNonce := []byte("newnonce1234") // 12 bytes
		cipher.SetNonce(newNonce)
		assert.Equal(t, newKey, cipher.Key) // key unchanged
		assert.Equal(t, newNonce, cipher.Nonce)
	})
}
