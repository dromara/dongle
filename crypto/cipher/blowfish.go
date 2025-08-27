package cipher

type BlowfishCipher struct {
	blockCipher
}

func NewBlowfishCipher(block BlockMode) (c *BlowfishCipher) {
	return &BlowfishCipher{
		blockCipher{
			Block:   block,
			Padding: PKCS7,
		},
	}
}
