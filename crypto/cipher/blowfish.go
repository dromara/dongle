package cipher

type BlowfishCipher struct {
	Key     []byte
	IV      []byte
	Nonce   []byte
	Aad     []byte
	Block   BlockMode
	Padding PaddingMode
}

func NewBlowfishCipher(block BlockMode) (c *BlowfishCipher) {
	return &BlowfishCipher{
		Block:   block,
		Padding: PKCS7,
	}
}

func (c *BlowfishCipher) SetPadding(padding PaddingMode) {
	c.Padding = padding
}

func (c *BlowfishCipher) SetKey(key []byte) {
	c.Key = key
}

func (c *BlowfishCipher) SetIV(iv []byte) {
	c.IV = iv
}

func (c *BlowfishCipher) SetNonce(nonce []byte) {
	c.Nonce = nonce
}

func (c *BlowfishCipher) SetAAD(aad []byte) {
	c.Aad = aad
}
