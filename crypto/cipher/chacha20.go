package cipher

type ChaCha20Cipher struct {
	baseCipher
	Nonce []byte
}

// NewChaCha20Cipher returns a new ChaCha20 cipher instance.
func NewChaCha20Cipher() (c *ChaCha20Cipher) {
	return &ChaCha20Cipher{}
}

// SetNonce sets the nonce for the cipher.
func (c *ChaCha20Cipher) SetNonce(nonce []byte) {
	c.Nonce = nonce
}
