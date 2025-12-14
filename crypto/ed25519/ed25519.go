// Package ed25519 implements ED25519 digital signature generation and verification with streaming support.
// It provides ED25519 operations using the standard ED25519 algorithm with support
// for high-performance digital signatures and verification.
package ed25519

import (
	"crypto/ed25519"
)

type cache struct {
	pubKey ed25519.PublicKey  // Cached public key for better performance
	priKey ed25519.PrivateKey // Cached private key for better performance
}
