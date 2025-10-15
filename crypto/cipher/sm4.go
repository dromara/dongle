package cipher

type Sm4Cipher struct {
	blockCipher
}

// NewSm4Cipher returns a new Sm4 cipher instance.
func NewSm4Cipher(block BlockMode) (c *Sm4Cipher) {
	return &Sm4Cipher{
		blockCipher{
			Block:   block,
			Padding: PKCS7,
		},
	}
}
