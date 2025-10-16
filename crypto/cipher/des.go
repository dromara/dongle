package cipher

// DesCipher defines a DesCipher struct.
type DesCipher struct {
	blockCipher
}

// NewDesCipher returns a new DesCipher instance.
func NewDesCipher(block BlockMode) (c *DesCipher) {
	return &DesCipher{
		blockCipher{
			Block:   block,
			Padding: PKCS7,
		},
	}
}
