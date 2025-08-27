package cipher

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestTeaCipher_SetKey tests the SetKey method
func TestTeaCipher_SetKey(t *testing.T) {
	t.Run("set key", func(t *testing.T) {
		cipher := NewTeaCipher()
		key := []byte("testkey1234567890")

		cipher.SetKey(key)
		assert.Equal(t, key, cipher.Key)
	})

	t.Run("set empty key", func(t *testing.T) {
		cipher := NewTeaCipher()
		var key []byte

		cipher.SetKey(key)
		assert.Equal(t, key, cipher.Key)
		assert.Empty(t, cipher.Key)
	})

	t.Run("set nil key", func(t *testing.T) {
		cipher := NewTeaCipher()

		cipher.SetKey(nil)
		assert.Nil(t, cipher.Key)
	})

	t.Run("set 16 byte key", func(t *testing.T) {
		cipher := NewTeaCipher()
		key := make([]byte, 16)
		for i := range key {
			key[i] = byte(i % 256)
		}

		cipher.SetKey(key)
		assert.Equal(t, key, cipher.Key)
		assert.Len(t, cipher.Key, 16)
	})

	t.Run("overwrite existing key", func(t *testing.T) {
		cipher := NewTeaCipher()
		key1 := []byte("firstkey12345678")
		key2 := []byte("secondkey1234567")

		cipher.SetKey(key1)
		assert.Equal(t, key1, cipher.Key)

		cipher.SetKey(key2)
		assert.Equal(t, key2, cipher.Key)
		assert.NotEqual(t, key1, cipher.Key)
	})
}

// TestTeaCipher_SetRounds tests the SetRounds method
func TestTeaCipher_SetRounds(t *testing.T) {
	t.Run("set default rounds", func(t *testing.T) {
		cipher := NewTeaCipher()
		assert.Equal(t, 64, cipher.Rounds)
	})

	t.Run("set custom rounds", func(t *testing.T) {
		cipher := NewTeaCipher()
		rounds := 32

		cipher.SetRounds(rounds)
		assert.Equal(t, rounds, cipher.Rounds)
	})

	t.Run("set zero rounds", func(t *testing.T) {
		cipher := NewTeaCipher()
		rounds := 0

		cipher.SetRounds(rounds)
		assert.Equal(t, rounds, cipher.Rounds)
	})

	t.Run("set negative rounds", func(t *testing.T) {
		cipher := NewTeaCipher()
		rounds := -10

		cipher.SetRounds(rounds)
		assert.Equal(t, rounds, cipher.Rounds)
	})

	t.Run("set large rounds", func(t *testing.T) {
		cipher := NewTeaCipher()
		rounds := 128

		cipher.SetRounds(rounds)
		assert.Equal(t, rounds, cipher.Rounds)
	})

	t.Run("overwrite existing rounds", func(t *testing.T) {
		cipher := NewTeaCipher()
		rounds1 := 32
		rounds2 := 96

		cipher.SetRounds(rounds1)
		assert.Equal(t, rounds1, cipher.Rounds)

		cipher.SetRounds(rounds2)
		assert.Equal(t, rounds2, cipher.Rounds)
		assert.NotEqual(t, rounds1, cipher.Rounds)
	})
}
