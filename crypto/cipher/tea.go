package cipher

type TeaCipher struct {
	blockCipher
	Rounds int
}

func NewTeaCipher(block BlockMode) (c *TeaCipher) {
	return &TeaCipher{
		blockCipher: blockCipher{
			Block:   block,
			Padding: PKCS7,
		},
		Rounds: 64,
	}
}

func (c *TeaCipher) SetRounds(rounds int) {
	c.Rounds = rounds
}
