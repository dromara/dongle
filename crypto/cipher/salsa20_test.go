package cipher

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewSalsa20Cipher(t *testing.T) {
	cipher := NewSalsa20Cipher()
	assert.NotNil(t, cipher)
	assert.Nil(t, cipher.Key)
	assert.Nil(t, cipher.Nonce)
}

func TestSalsa20Cipher_SetKey(t *testing.T) {
	cipher := NewSalsa20Cipher()
	key := make([]byte, 32)
	cipher.SetKey(key)
	assert.Equal(t, key, cipher.Key)
}

func TestSalsa20Cipher_SetNonce(t *testing.T) {
	cipher := NewSalsa20Cipher()
	nonce := make([]byte, 8)
	cipher.SetNonce(nonce)
	assert.Equal(t, nonce, cipher.Nonce)
}
