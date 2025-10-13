package cipher

type Sm4Cipher struct {
	blockCipher
}

func NewSm4Cipher(block BlockMode) (c *Sm4Cipher) {
	return &Sm4Cipher{
		blockCipher{
			Block:   block,
			Padding: PKCS7,
		},
	}
}
