package cipher

// DesCipher defines a DesCipher struct.
type DesCipher struct {
	blockCipher
}

// NewDesCipher returns a new DesCipher instance.
func NewDesCipher(block BlockMode) *DesCipher {
	c := &DesCipher{}
	c.Block = block
	c.Padding = No
	return c
}
