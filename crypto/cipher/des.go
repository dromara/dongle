package cipher

type DesCipher struct {
	blockCipher
}

// NewDesCipher returns a new DES cipher instance.
func NewDesCipher(block BlockMode) (c *DesCipher) {
	return &DesCipher{
		blockCipher{
			Block:   block,
			Padding: PKCS7,
		},
	}
}
