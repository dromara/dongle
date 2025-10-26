package cipher

// XteaCipher defines a XteaCipher struct.
type XteaCipher struct {
	blockCipher
}

// NewXteaCipher returns a new XteaCipher instance.
func NewXteaCipher(block BlockMode) *XteaCipher {
	c := &XteaCipher{}
	c.Block = block
	c.Padding = No
	return c
}
