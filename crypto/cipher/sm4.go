package cipher

// Sm4Cipher defines a Sm4Cipher struct.
type Sm4Cipher struct {
	blockCipher
}

// NewSm4Cipher returns a new Sm4Cipher instance.
func NewSm4Cipher(block BlockMode) *Sm4Cipher {
	c := &Sm4Cipher{}
	c.Block = block
	c.Padding = No
	return c
}
