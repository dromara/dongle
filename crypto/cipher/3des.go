package cipher

// TripleDesCipher defines a TripleDesCipher struct.
type TripleDesCipher struct {
	blockCipher
}

// New3DesCipher returns a new TripleDesCipher instance.
func New3DesCipher(block BlockMode) (c *TripleDesCipher) {
	return &TripleDesCipher{
		blockCipher{
			Block:   block,
			Padding: PKCS7,
		},
	}
}
