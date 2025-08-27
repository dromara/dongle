package cipher

type AesCipher struct {
	blockCipher
}

func NewAesCipher(block BlockMode) (c *AesCipher) {
	return &AesCipher{
		blockCipher{
			Block:   block,
			Padding: PKCS7,
		},
	}
}
