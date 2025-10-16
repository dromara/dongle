package cipher

// BlowfishCipher defines a BlowfishCipher struct.
type BlowfishCipher struct {
	blockCipher
}

// NewBlowfishCipher returns a new BlowfishCipher instance.
func NewBlowfishCipher(block BlockMode) (c *BlowfishCipher) {
	return &BlowfishCipher{
		blockCipher{
			Block:   block,
			Padding: PKCS7,
		},
	}
}
