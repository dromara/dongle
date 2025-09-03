package cipher

type ChaCha20Cipher struct {
	baseCipher
	Nonce []byte
}

func NewChaCha20Cipher() (c *ChaCha20Cipher) {
	return &ChaCha20Cipher{}
}

func (c *ChaCha20Cipher) SetNonce(nonce []byte) {
	c.Nonce = nonce
}
