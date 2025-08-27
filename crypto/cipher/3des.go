package cipher

type TripleDesCipher struct {
	blockCipher
}

func New3DesCipher(block BlockMode) (c *TripleDesCipher) {
	return &TripleDesCipher{
		blockCipher{
			Block:   block,
			Padding: PKCS7,
		},
	}
}
