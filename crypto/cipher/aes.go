package cipher

type AesCipher struct {
	Key     []byte
	IV      []byte
	Nonce   []byte
	Aad     []byte
	Block   BlockMode
	Padding PaddingMode
}

func NewAesCipher(block BlockMode) (c *AesCipher) {
	return &AesCipher{
		Block:   block,
		Padding: PKCS7,
	}
}

func (c *AesCipher) SetPadding(padding PaddingMode) {
	c.Padding = padding
}

func (c *AesCipher) SetKey(key []byte) {
	c.Key = key
}

func (c *AesCipher) SetIV(iv []byte) {
	c.IV = iv
}

func (c *AesCipher) SetNonce(nonce []byte) {
	c.Nonce = nonce
}

func (c *AesCipher) SetAAD(aad []byte) {
	c.Aad = aad
}
