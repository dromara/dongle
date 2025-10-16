package cipher

// Salsa20Cipher defines a Salsa20Cipher struct.
// Salsa20 is a stream cipher that uses a 32-byte key and 8-byte nonce.
type Salsa20Cipher struct {
	baseCipher
	Nonce []byte // 8-byte nonce for Salsa20
}

// NewSalsa20Cipher creates a new Salsa20Cipher instance.
func NewSalsa20Cipher() *Salsa20Cipher {
	return &Salsa20Cipher{}
}

// SetNonce sets the nonce for the cipher.
// The nonce must be exactly 8 bytes for Salsa20.
func (c *Salsa20Cipher) SetNonce(nonce []byte) {
	c.Nonce = nonce
}
