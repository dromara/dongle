package cipher

type BlowfishCipher struct {
	blockCipher
}

// NewBlowfishCipher returns a new Blowfish cipher instance.
func NewBlowfishCipher(block BlockMode) (c *BlowfishCipher) {
	return &BlowfishCipher{
		blockCipher{
			Block:   block,
			Padding: PKCS7,
		},
	}
}
