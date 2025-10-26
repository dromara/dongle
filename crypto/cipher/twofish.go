package cipher

// TwofishCipher defines a TwofishCipher struct.
type TwofishCipher struct {
	blockCipher
}

// NewTwofishCipher returns a new TwofishCipher instance.
func NewTwofishCipher(block BlockMode) *TwofishCipher {
	c := &TwofishCipher{}
	c.Block = block
	c.Padding = No
	return c
}
