package cipher

// XteaCipher defines a XteaCipher struct.
type XteaCipher struct {
	blockCipher
}

// NewXteaCipher returns a new XteaCipher instance.
func NewXteaCipher(block BlockMode) (c *XteaCipher) {
	return &XteaCipher{
		blockCipher{
			Block:   block,
			Padding: PKCS7,
		},
	}
}
