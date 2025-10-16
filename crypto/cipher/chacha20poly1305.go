package cipher

// ChaCha20Poly1305Cipher defines a ChaCha20Poly1305Cipher struct.
type ChaCha20Poly1305Cipher struct {
	baseCipher
	Nonce []byte
	AAD   []byte
}

// NewChaCha20Poly1305Cipher returns a new ChaCha20Poly1305Cipher instance.
func NewChaCha20Poly1305Cipher() (c *ChaCha20Poly1305Cipher) {
	return &ChaCha20Poly1305Cipher{}
}

// SetNonce sets the nonce for the cipher.
func (c *ChaCha20Poly1305Cipher) SetNonce(nonce []byte) {
	c.Nonce = nonce
}

// SetAAD sets the additional authenticated data (AAD) for the cipher.
func (c *ChaCha20Poly1305Cipher) SetAAD(aad []byte) {
	c.AAD = aad
}
