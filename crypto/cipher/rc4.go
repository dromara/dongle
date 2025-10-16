package cipher

// Rc4Cipher defines a Rc4Cipher struct.
type Rc4Cipher struct {
	baseCipher
}

// NewRc4Cipher returns a new Rc4Cipher instance.
func NewRc4Cipher() (c *Rc4Cipher) {
	return &Rc4Cipher{}
}
