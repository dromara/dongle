// Package cipher provides cryptographic cipher configuration and base functionality.
// It supports various symmetric encryption algorithms with different block modes,
// padding modes, and streaming capabilities for secure data encryption and decryption.
package cipher

import "crypto/cipher"

type baseCipher struct {
	Key []byte
}

// SetKey sets the encryption key for the cipher.
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

// SetPadding sets the padding mode for the cipher.
func (c *blockCipher) SetPadding(padding PaddingMode) {
	c.Padding = padding
}

// SetIV sets the initialization vector (IV) for the cipher.
func (c *blockCipher) SetIV(iv []byte) {
	c.IV = iv
}

// SetNonce sets the nonce for the cipher.
func (c *blockCipher) SetNonce(nonce []byte) {
	c.Nonce = nonce
}

// SetAAD sets the additional authentication data (AAD) for the cipher.
func (c *blockCipher) SetAAD(aad []byte) {
	c.AAD = aad
}

// Encrypt encrypts the source data using the specified cipher.
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

	// Only CBC/ECB block modes require add padding
	paddedSrc, err := c.padding(src, block.BlockSize())
	if err != nil {
		return
	}
	if c.Block == CBC {
		return NewCBCEncrypter(paddedSrc, c.IV, block)
	}
	if c.Block == ECB {
		return NewECBEncrypter(paddedSrc, block)
	}

	return dst, UnsupportedBlockModeError{mode: c.Block}
}

// Decrypt decrypts the source data using the specified cipher.
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

	// Only CBC/ECB block modes require remove padding
	var paddedDst []byte
	if c.Block == CBC {
		if paddedDst, err = NewCBCDecrypter(src, c.IV, block); err != nil {
			return
		}
		return c.unpadding(paddedDst)
	}
	if c.Block == ECB {
		if paddedDst, err = NewECBDecrypter(src, block); err != nil {
			return
		}
		return c.unpadding(paddedDst)
	}

	return dst, UnsupportedBlockModeError{mode: c.Block}
}

// padding adds padding to the source data.
func (c *blockCipher) padding(src []byte, blockSize int) (dst []byte, err error) {
	switch c.Padding {
	case No:
		return NewNoPadding(src), nil
	case Zero:
		return NewZeroPadding(src, blockSize), nil
	case PKCS5:
		return NewPKCS5Padding(src), nil
	case PKCS7:
		return NewPKCS7Padding(src, blockSize), nil
	case AnsiX923:
		return NewAnsiX923Padding(src, blockSize), nil
	case ISO97971:
		return NewISO97971Padding(src, blockSize), nil
	case ISO10126:
		return NewISO10126Padding(src, blockSize), nil
	case ISO78164:
		return NewISO78164Padding(src, blockSize), nil
	case Bit:
		return NewBitPadding(src, blockSize), nil
	case TBC:
		return NewTBCPadding(src, blockSize), nil
	default:
		return dst, UnsupportedPaddingModeError{mode: c.Padding}
	}
}

// unpadding removes padding from the source data.
func (c *blockCipher) unpadding(src []byte) (dst []byte, err error) {
	switch c.Padding {
	case No:
		return NewNoUnPadding(src), nil
	case Zero:
		return NewZeroUnPadding(src), nil
	case PKCS5:
		return NewPKCS5UnPadding(src), nil
	case PKCS7:
		return NewPKCS7UnPadding(src), nil
	case AnsiX923:
		return NewAnsiX923UnPadding(src), nil
	case ISO97971:
		return NewISO97971UnPadding(src), nil
	case ISO10126:
		return NewISO10126UnPadding(src), nil
	case ISO78164:
		return NewISO78164UnPadding(src), nil
	case Bit:
		return NewBitUnPadding(src), nil
	case TBC:
		return NewTBCUnPadding(src), nil
	default:
		return dst, UnsupportedPaddingModeError{mode: c.Padding}
	}
}
