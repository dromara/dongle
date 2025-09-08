package cipher

import "crypto/cipher"

type baseCipher struct {
	Key []byte
}

func (c *baseCipher) SetKey(key []byte) {
	c.Key = key
}

type blockCipher struct {
	baseCipher
	IV      []byte
	Nonce   []byte
	AAD     []byte
	Block   BlockMode
	Padding PaddingMode
}

func (c *blockCipher) SetPadding(padding PaddingMode) {
	c.Padding = padding
}

func (c *blockCipher) SetIV(iv []byte) {
	c.IV = iv
}

func (c *blockCipher) SetNonce(nonce []byte) {
	c.Nonce = nonce
}

func (c *blockCipher) SetAAD(aad []byte) {
	c.AAD = aad
}

func (c *blockCipher) Encrypt(src []byte, block cipher.Block) (dst []byte, err error) {
	var paddedSrc []byte
	switch c.Padding {
	case No:
		paddedSrc = src
	case Zero:
		paddedSrc = newZeroPadding(src, block.BlockSize())
	case PKCS5:
		paddedSrc = newPKCS5Padding(src)
	case PKCS7:
		paddedSrc = newPKCS7Padding(src, block.BlockSize())
	case AnsiX923:
		paddedSrc = newAnsiX923Padding(src, block.BlockSize())
	case ISO97971:
		paddedSrc = newISO97971Padding(src, block.BlockSize())
	case ISO10126:
		paddedSrc = newISO10126Padding(src, block.BlockSize())
	case ISO78164:
		paddedSrc = newISO78164Padding(src, block.BlockSize())
	case Bit:
		paddedSrc = newBitPadding(src, block.BlockSize())
	}
	switch c.Block {
	case CBC:
		return newCBCEncrypter(paddedSrc, c.IV, block)
	case ECB:
		return newECBEncrypter(paddedSrc, block)
	case CTR:
		return newCTREncrypter(src, c.IV, block)
	case GCM:
		return newGCMEncrypter(src, c.Nonce, c.AAD, block)
	case CFB:
		return newCFBEncrypter(src, c.IV, block)
	case OFB:
		return newOFBEncrypter(src, c.IV, block)
	}
	return
}

func (c *blockCipher) Decrypt(src []byte, block cipher.Block) (dst []byte, err error) {
	var decrypted []byte
	switch c.Block {
	case CBC:
		decrypted, err = newCBCDecrypter(src, c.IV, block)
	case CTR:
		decrypted, err = newCTRDecrypter(src, c.IV, block)
	case ECB:
		decrypted, err = newECBDecrypter(src, block)
	case GCM:
		decrypted, err = newGCMDecrypter(src, c.Nonce, c.AAD, block)
	case CFB:
		decrypted, err = newCFBDecrypter(src, c.IV, block)
	case OFB:
		decrypted, err = newOFBDecrypter(src, c.IV, block)
	}
	if err != nil {
		return
	}
	switch c.Padding {
	case No:
		dst = decrypted
	case Zero:
		dst = newZeroUnPadding(decrypted)
	case PKCS5:
		dst = newPKCS5UnPadding(decrypted)
	case PKCS7:
		dst = newPKCS7UnPadding(decrypted)
	case AnsiX923:
		dst = newAnsiX923UnPadding(decrypted)
	case ISO97971:
		dst = newISO97971UnPadding(decrypted)
	case ISO10126:
		dst = newISO10126UnPadding(decrypted)
	case ISO78164:
		dst = newISO78164UnPadding(decrypted)
	case Bit:
		dst = newBitUnPadding(decrypted)
	}
	return
}
