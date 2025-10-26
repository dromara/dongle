package cipher

// AesCipher defines a AesCipher struct.
type AesCipher struct {
	blockCipher
}

// NewAesCipher returns a new AesCipher instance.
func NewAesCipher(block BlockMode) *AesCipher {
	c := &AesCipher{}
	c.Block = block
	c.Padding = No
	return c
}
