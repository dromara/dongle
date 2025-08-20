package cipher

type TripleDesCipher struct {
	Key     []byte
	IV      []byte
	Nonce   []byte
	Aad     []byte
	Block   BlockMode
	Padding PaddingMode
}

func New3DesCipher(block BlockMode) (c *TripleDesCipher) {
	return &TripleDesCipher{
		Block:   block,
		Padding: PKCS7,
	}
}

func (c *TripleDesCipher) SetPadding(padding PaddingMode) {
	c.Padding = padding
}

func (c *TripleDesCipher) SetKey(key []byte) {
	c.Key = key
}

func (c *TripleDesCipher) SetIV(iv []byte) {
	c.IV = iv
}

func (c *TripleDesCipher) SetNonce(nonce []byte) {
	c.Nonce = nonce
}

func (c *TripleDesCipher) SetAAD(aad []byte) {
	c.Aad = aad
}
