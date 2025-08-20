package cipher

type DesCipher struct {
	Key     []byte
	IV      []byte
	Nonce   []byte
	Aad     []byte
	Block   BlockMode
	Padding PaddingMode
}

func NewDesCipher(block BlockMode) (c *DesCipher) {
	return &DesCipher{
		Block:   block,
		Padding: PKCS7,
	}
}

func (c *DesCipher) SetPadding(padding PaddingMode) {
	c.Padding = padding
}

func (c *DesCipher) SetKey(key []byte) {
	c.Key = key
}

func (c *DesCipher) SetIV(iv []byte) {
	c.IV = iv
}

func (c *DesCipher) SetNonce(nonce []byte) {
	c.Nonce = nonce
}

func (c *DesCipher) SetAAD(aad []byte) {
	c.Aad = aad
}
