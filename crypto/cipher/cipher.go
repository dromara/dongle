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
		return NewCFBEncrypter(src, c.IV, block)
	}
	if c.Block == OFB {
		return NewOFBEncrypter(src, c.IV, block)
	}
	if c.Block == CTR {
		return NewCTREncrypter(src, c.IV, block)
	}
	if c.Block == GCM {
		return NewGCMEncrypter(src, c.Nonce, c.AAD, block)
	}

	paddedSrc := padding(c.Padding, src, block.BlockSize())
	if c.Block == CBC {
		return NewCBCEncrypter(paddedSrc, c.IV, block)
	}
	if c.Block == ECB {
		return NewECBEncrypter(paddedSrc, block)
	}
	return
}

func (c *blockCipher) Decrypt(src []byte, block cipher.Block) (dst []byte, err error) {
	if c.Block == CFB {
		return NewCFBDecrypter(src, c.IV, block)
	}
	if c.Block == OFB {
		return NewOFBDecrypter(src, c.IV, block)
	}
	if c.Block == CTR {
		return NewCTRDecrypter(src, c.IV, block)
	}
	if c.Block == GCM {
		return NewGCMDecrypter(src, c.Nonce, c.AAD, block)
	}
	var paddedDst []byte
	if c.Block == CBC {
		paddedDst, err = NewCBCDecrypter(src, c.IV, block)
	}
	if c.Block == ECB {
		paddedDst, err = NewECBDecrypter(src, block)
	}
	if err != nil {
		return
	}
	dst = unpadding(c.Padding, paddedDst)
	return
}

// padding applies the specified padding mode to the source data.
func padding(paddingMode PaddingMode, src []byte, blockSize int) []byte {
	switch paddingMode {
	case Zero:
		return NewZeroPadding(src, blockSize)
	case PKCS5:
		return NewPKCS5Padding(src)
	case PKCS7:
		return NewPKCS7Padding(src, blockSize)
	case AnsiX923:
		return NewAnsiX923Padding(src, blockSize)
	case ISO97971:
		return NewISO97971Padding(src, blockSize)
	case ISO10126:
		return NewISO10126Padding(src, blockSize)
	case ISO78164:
		return NewISO78164Padding(src, blockSize)
	case Bit:
		return NewBitPadding(src, blockSize)
	}
	return src
}

// unpadding removes the specified padding mode from the source data.
func unpadding(paddingMode PaddingMode, src []byte) []byte {
	switch paddingMode {
	case Zero:
		return NewZeroUnPadding(src)
	case PKCS5:
		return NewPKCS5UnPadding(src)
	case PKCS7:
		return NewPKCS7UnPadding(src)
	case AnsiX923:
		return NewAnsiX923UnPadding(src)
	case ISO97971:
		return NewISO97971UnPadding(src)
	case ISO10126:
		return NewISO10126UnPadding(src)
	case ISO78164:
		return NewISO78164UnPadding(src)
	case Bit:
		return NewBitUnPadding(src)
	}
	return src
}
