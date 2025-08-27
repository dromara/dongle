package cipher

type TeaCipher struct {
	baseCipher
	Rounds int
}

func NewTeaCipher() (c *TeaCipher) {
	return &TeaCipher{
		Rounds: 64,
	}
}

func (c *TeaCipher) SetRounds(rounds int) {
	c.Rounds = rounds
}
