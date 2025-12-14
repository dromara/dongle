// Package rsa implements RSA encryption, decryption, signing, and verification with streaming support.
// It provides RSA operations using the standard RSA algorithm with support
// for different key sizes and padding schemes.
package rsa

import (
	"crypto/rsa"
	"hash"
)

type cache struct {
	pubKey *rsa.PublicKey  // Cached public key for better performance
	priKey *rsa.PrivateKey // Cached private key for better performance
	hash   hash.Hash       // Cached hash function for OAEP padding
}
