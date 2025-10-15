package cipher

type TwofishCipher struct {
	blockCipher
}

// NewTwofishCipher returns a new Twofish cipher instance.
func NewTwofishCipher(block BlockMode) (c *TwofishCipher) {
	return &TwofishCipher{
		blockCipher{
			Block:   block,
			Padding: PKCS7,
		},
	}
}
