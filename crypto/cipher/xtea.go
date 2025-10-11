package cipher

type XteaCipher struct {
	blockCipher
}

func NewXteaCipher(block BlockMode) (c *XteaCipher) {
	return &XteaCipher{
		blockCipher{
			Block:   block,
			Padding: PKCS7,
		},
	}
}
