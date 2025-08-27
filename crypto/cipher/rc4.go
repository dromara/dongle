package cipher

type Rc4Cipher struct {
	baseCipher
}

func NewRc4Cipher() (c *Rc4Cipher) {
	return &Rc4Cipher{}
}
