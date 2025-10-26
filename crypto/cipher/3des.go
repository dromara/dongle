package cipher

// TripleDesCipher defines a TripleDesCipher struct.
type TripleDesCipher struct {
	blockCipher
}

// New3DesCipher returns a new TripleDesCipher instance.
func New3DesCipher(block BlockMode) *TripleDesCipher {
	c := &TripleDesCipher{}
	c.Block = block
	c.Padding = No
	return c
}
