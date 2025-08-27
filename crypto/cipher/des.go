package cipher

type DesCipher struct {
	blockCipher
}

func NewDesCipher(block BlockMode) (c *DesCipher) {
	return &DesCipher{
		blockCipher{
			Block:   block,
			Padding: PKCS7,
		},
	}
}
