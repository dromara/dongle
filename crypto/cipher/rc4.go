package cipher

type Rc4Cipher struct {
	baseCipher
}

// NewRc4Cipher returns a new Rc4 cipher instance.
func NewRc4Cipher() (c *Rc4Cipher) {
	return &Rc4Cipher{}
}
