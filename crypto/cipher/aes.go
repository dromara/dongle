package cipher

// AesCipher defines a AesCipher struct.
type AesCipher struct {
	blockCipher
}

// NewAesCipher returns a new AesCipher instance.
func NewAesCipher(block BlockMode) (c *AesCipher) {
	return &AesCipher{
		blockCipher{
			Block:   block,
			Padding: PKCS7,
		},
	}
}
