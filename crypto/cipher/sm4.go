package cipher

// Sm4Cipher defines a Sm4Cipher struct.
type Sm4Cipher struct {
	blockCipher
}

// NewSm4Cipher returns a new Sm4Cipher instance.
func NewSm4Cipher(block BlockMode) (c *Sm4Cipher) {
	return &Sm4Cipher{
		blockCipher{
			Block:   block,
			Padding: PKCS7,
		},
	}
}
