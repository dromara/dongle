package cipher

type AesCipher struct {
	blockCipher
}

// NewAesCipher returns a new AES cipher instance.
func NewAesCipher(block BlockMode) (c *AesCipher) {
	return &AesCipher{
		blockCipher{
			Block:   block,
			Padding: PKCS7,
		},
	}
}
