package cipher

import (
	"crypto/cipher"
)

// CipherInterface defines the common interface for all cipher types
type CipherInterface interface {
	Encrypt(src []byte, cipherBlock cipher.Block) (dst []byte, err error)
	Decrypt(src []byte, cipherBlock cipher.Block) (dst []byte, err error)
}

// KeySetter defines the interface for ciphers that can set a key
type KeySetter interface {
	SetKey(key []byte)
}

// KeyGetter defines the interface for ciphers that can get a key
type KeyGetter interface {
	GetKey() []byte
}

// IVSetter defines the interface for ciphers that can set an IV
type IVSetter interface {
	SetIV(iv []byte)
}

// NonceSetter defines the interface for ciphers that can set a nonce
type NonceSetter interface {
	SetNonce(nonce []byte)
}

// AADSetter defines the interface for ciphers that can set AAD
type AADSetter interface {
	SetAAD(aad []byte)
}

// PaddingSetter defines the interface for ciphers that can set padding
type PaddingSetter interface {
	SetPadding(padding PaddingMode)
}

// CipherSetter combines all the setter interfaces
type CipherSetter interface {
	KeySetter
	IVSetter
	NonceSetter
	AADSetter
	PaddingSetter
}
