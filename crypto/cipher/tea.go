package cipher

type TeaCipher struct {
	Key    []byte
	Rounds int
}

func NewTeaCipher() (c *TeaCipher) {
	return &TeaCipher{
		Rounds: 64,
	}
}

func (c *TeaCipher) SetKey(key []byte) {
	c.Key = key
}

func (c *TeaCipher) SetRounds(rounds int) {
	c.Rounds = rounds
}
