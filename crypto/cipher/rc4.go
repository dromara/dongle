package cipher

type Rc4Cipher struct {
	Key []byte
}

func NewRc4Cipher() (c *Rc4Cipher) {
	return &Rc4Cipher{}
}

func (c *Rc4Cipher) SetKey(key []byte) {
	c.Key = key
}
