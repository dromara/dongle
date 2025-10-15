package cipher

type TeaCipher struct {
	blockCipher
	Rounds int
}

// NewTeaCipher returns a new Tea cipher.
func NewTeaCipher(block BlockMode) (c *TeaCipher) {
	return &TeaCipher{
		blockCipher: blockCipher{
			Block:   block,
			Padding: PKCS7,
		},
		Rounds: 64,
	}
}

// SetRounds sets the number of rounds for the cipher.
func (c *TeaCipher) SetRounds(rounds int) {
	c.Rounds = rounds
}
