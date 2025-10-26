package cipher

// BlowfishCipher defines a BlowfishCipher struct.
type BlowfishCipher struct {
	blockCipher
}

// NewBlowfishCipher returns a new BlowfishCipher instance.
func NewBlowfishCipher(block BlockMode) *BlowfishCipher {
	c := &BlowfishCipher{}
	c.Block = block
	c.Padding = No
	return c
}
