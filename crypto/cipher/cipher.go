// Package cipher provides cryptographic cipher configuration and base functionality.
// It supports various symmetric encryption algorithms with different block modes,
// padding schemes, and streaming capabilities for secure data encryption and decryption.
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
	if c.Block == CFB {
		return newCFBEncrypter(src, c.IV, block)
	}
	if c.Block == OFB {
		return newOFBEncrypter(src, c.IV, block)
	}
	if c.Block == CTR {
		return newCTREncrypter(src, c.IV, block)
	}
	if c.Block == GCM {
		return newGCMEncrypter(src, c.Nonce, c.AAD, block)
	}

	paddedSrc := newPadding(c.Padding, src, block.BlockSize())
	if c.Block == CBC {
		return newCBCEncrypter(paddedSrc, c.IV, block)
	}
	if c.Block == ECB {
		return newECBEncrypter(paddedSrc, block)
	}
	return
}

func (c *blockCipher) Decrypt(src []byte, block cipher.Block) (dst []byte, err error) {
	if c.Block == CFB {
		return newCFBDecrypter(src, c.IV, block)
	}
	if c.Block == OFB {
		return newOFBDecrypter(src, c.IV, block)
	}
	if c.Block == CTR {
		return newCTRDecrypter(src, c.IV, block)
	}
	if c.Block == GCM {
		return newGCMDecrypter(src, c.Nonce, c.AAD, block)
	}
	var decrypted []byte
	if c.Block == CBC {
		decrypted, err = newCBCDecrypter(src, c.IV, block)
	}
	if c.Block == ECB {
		decrypted, err = newECBDecrypter(src, block)
	}
	if err != nil {
		return
	}
	dst = newUnPadding(c.Padding, decrypted)
	return
}
