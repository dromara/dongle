package cipher

type XteaCipher struct {
	blockCipher
}

// NewXteaCipher returns a new Xtea cipher instance.
func NewXteaCipher(block BlockMode) (c *XteaCipher) {
	return &XteaCipher{
		blockCipher{
			Block:   block,
			Padding: PKCS7,
		},
	}
}
