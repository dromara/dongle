// Package sm2 implements SM2 public key encryption, decryption, signing and verification
// with optional streaming helpers.
package sm2

import (
	"crypto/ecdsa"
)

type cache struct {
	pubKey *ecdsa.PublicKey
	priKey *ecdsa.PrivateKey
}
