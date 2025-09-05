package cipher

type ChaCha20Poly1305Cipher struct {
	baseCipher
	Nonce []byte
	AAD   []byte
}

func NewChaCha20Poly1305Cipher() (c *ChaCha20Poly1305Cipher) {
	return &ChaCha20Poly1305Cipher{}
}

func (c *ChaCha20Poly1305Cipher) SetNonce(nonce []byte) {
	c.Nonce = nonce
}

func (c *ChaCha20Poly1305Cipher) SetAAD(aad []byte) {
	c.AAD = aad
}
