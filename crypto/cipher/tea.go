package cipher

// TeaCipher defines a TeaCipher struct.
type TeaCipher struct {
	blockCipher
	Rounds int
}

// NewTeaCipher returns a new TeaCipher instance.
func NewTeaCipher(block BlockMode) *TeaCipher {
	c := &TeaCipher{}
	c.Block = block
	c.Padding = No
	c.Rounds = 64
	return c
}

// SetRounds sets the number of rounds for the cipher.
func (c *TeaCipher) SetRounds(rounds int) {
	c.Rounds = rounds
}
