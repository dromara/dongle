package cipher

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestRc4Cipher_SetKey tests the SetKey method
func TestRc4Cipher_SetKey(t *testing.T) {
	t.Run("set key", func(t *testing.T) {
		cipher := NewRc4Cipher()
		key := []byte("testkey123")

		cipher.SetKey(key)
		assert.Equal(t, key, cipher.Key)
	})

	t.Run("set empty key", func(t *testing.T) {
		cipher := NewRc4Cipher()
		key := []byte{}

		cipher.SetKey(key)
		assert.Equal(t, key, cipher.Key)
		assert.Empty(t, cipher.Key)
	})

	t.Run("set nil key", func(t *testing.T) {
		cipher := NewRc4Cipher()

		cipher.SetKey(nil)
		assert.Nil(t, cipher.Key)
	})

	t.Run("set long key", func(t *testing.T) {
		cipher := NewRc4Cipher()
		key := make([]byte, 256)
		for i := range key {
			key[i] = byte(i % 256)
		}

		cipher.SetKey(key)
		assert.Equal(t, key, cipher.Key)
		assert.Len(t, cipher.Key, 256)
	})

	t.Run("overwrite existing key", func(t *testing.T) {
		cipher := NewRc4Cipher()
		key1 := []byte("firstkey")
		key2 := []byte("secondkey")

		cipher.SetKey(key1)
		assert.Equal(t, key1, cipher.Key)

		cipher.SetKey(key2)
		assert.Equal(t, key2, cipher.Key)
		assert.NotEqual(t, key1, cipher.Key)
	})
}
