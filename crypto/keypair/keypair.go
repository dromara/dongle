// Package keypair provides cryptographic key pair management for multiple algorithms.
//
// It supports key generation, parsing, formatting, and manipulation for:
//   - RSA: Supports PKCS1 and PKCS8 key formats, with configurable padding schemes
//   - SM2: Supports PKCS8/PKIX formats with configurable ciphertext order
//   - Ed25519: Supports PKCS8 format
//
// Each key pair type provides methods for:
//   - Generating new key pairs
//   - Parsing keys from PEM format
//   - Formatting keys to PEM format
//   - Setting algorithm-specific parameters
package keypair

// KeyType represents the type of cryptographic key (public or private).
// This is used to distinguish between public key and private key
// in key pair operations and management.
type KeyType string

const (
	PublicKey  KeyType = "publicKey"
	PrivateKey KeyType = "privateKey"
)
