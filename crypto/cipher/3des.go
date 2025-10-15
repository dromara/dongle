package cipher

type TripleDesCipher struct {
	blockCipher
}

// New3DesCipher returns a new TripleDES cipher instance.
func New3DesCipher(block BlockMode) (c *TripleDesCipher) {
	return &TripleDesCipher{
		blockCipher{
			Block:   block,
			Padding: PKCS7,
		},
	}
}
