package cipher

type TwofishCipher struct {
	blockCipher
}

func NewTwofishCipher(block BlockMode) (c *TwofishCipher) {
	return &TwofishCipher{
		blockCipher{
			Block:   block,
			Padding: PKCS7,
		},
	}
}
