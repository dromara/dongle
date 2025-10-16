package cipher

// TwofishCipher defines a TwofishCipher struct.
type TwofishCipher struct {
	blockCipher
}

// NewTwofishCipher returns a new TwofishCipher instance.
func NewTwofishCipher(block BlockMode) (c *TwofishCipher) {
	return &TwofishCipher{
		blockCipher{
			Block:   block,
			Padding: PKCS7,
		},
	}
}
