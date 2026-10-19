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
//
// Beyond the PEM produced by GenKeyPair, every Parse/Format/Set method accepts
// base64 or hex encoded DER, as well as bare key material (a raw Ed25519 seed,
// a 65 byte SM2 point or a 32 byte SM2 scalar), so keys printed by other tools
// can be used without converting them first. Keys of another algorithm are
// reported as an UnsupportedKeyFormatError, they never panic.
package keypair

// KeyType represents the type of cryptographic key (public or private).
// This is used to distinguish between public key and private key
// in key pair operations and management.
type KeyType string

const (
	PublicKey  KeyType = "publicKey"
	PrivateKey KeyType = "privateKey"
)
