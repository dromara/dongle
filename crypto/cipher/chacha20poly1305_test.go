package cipher

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestChaCha20Poly1305Cipher_SetNonce(t *testing.T) {
	cipher := NewChaCha20Poly1305Cipher()
	nonce := []byte("123456789012") // 12 bytes

	cipher.SetNonce(nonce)
	assert.Equal(t, nonce, cipher.Nonce)

	// Test with different nonce
	differentNonce := []byte("abcdefghijkl")
	cipher.SetNonce(differentNonce)
	assert.Equal(t, differentNonce, cipher.Nonce)

	// Test with nil nonce
	cipher.SetNonce(nil)
	assert.Nil(t, cipher.Nonce)

	// Test with empty nonce
	cipher.SetNonce([]byte{})
	assert.Equal(t, []byte{}, cipher.Nonce)
}

func TestChaCha20Poly1305Cipher_SetAAD(t *testing.T) {
	cipher := NewChaCha20Poly1305Cipher()
	aad := []byte("additional authenticated data")

	cipher.SetAAD(aad)
	assert.Equal(t, aad, cipher.AAD)

	// Test with different AAD
	differentAAD := []byte("different aad")
	cipher.SetAAD(differentAAD)
	assert.Equal(t, differentAAD, cipher.AAD)

	// Test with nil AAD
	cipher.SetAAD(nil)
	assert.Nil(t, cipher.AAD)

	// Test with empty AAD
	cipher.SetAAD([]byte{})
	assert.Equal(t, []byte{}, cipher.AAD)
}
