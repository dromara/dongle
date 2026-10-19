package keypair

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

// Ed25519KeyPair represents an ED25519 key pair with public and private keys.
// It supports PKCS8 format and provides methods for key generation,
// formatting, and parsing.
type Ed25519KeyPair struct {
	// PublicKey contains the PEM-encoded public key
	PublicKey []byte

	// PrivateKey contains the PEM-encoded private key
	PrivateKey []byte

	// Signature contains the signature bytes for verification
	Signature []byte
}

// NewEd25519KeyPair returns a new Ed25519KeyPair instance.
func NewEd25519KeyPair() *Ed25519KeyPair {
	return &Ed25519KeyPair{}
}

// GenKeyPair generates a new Ed25519KeyPair instance.
// The generated keys are formatted in PEM format using PKCS8 format.
//
// Note: The generated keys are automatically formatted in PEM format using PKCS8 format.
func (k *Ed25519KeyPair) GenKeyPair() error {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}

	// ED25519 only supports PKCS8 format
	if privateKeyDer, err := x509.MarshalPKCS8PrivateKey(privateKey); err == nil {
		k.PrivateKey = pem.EncodeToMemory(&pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: privateKeyDer,
		})
	}

	if publicKeyDer, err := x509.MarshalPKIXPublicKey(publicKey); err == nil {
		k.PublicKey = pem.EncodeToMemory(&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: publicKeyDer,
		})
	}

	return nil
}

// SetPublicKey sets the public key and formats it in PEM format.
// The input may be PEM, base64, hex or raw key material and is rewritten as a
// canonical "PUBLIC KEY" block. See FormatPublicKey for the accepted inputs.
func (k *Ed25519KeyPair) SetPublicKey(publicKey []byte) error {
	key, err := k.FormatPublicKey(publicKey)
	if err == nil {
		k.PublicKey = key
	}
	return err
}

// SetPrivateKey sets the private key and formats it in PEM format.
// The input may be PEM, base64, hex or raw key material and is rewritten as a
// canonical "PRIVATE KEY" block. See FormatPrivateKey for the accepted inputs.
func (k *Ed25519KeyPair) SetPrivateKey(privateKey []byte) error {
	key, err := k.FormatPrivateKey(privateKey)
	if err == nil {
		k.PrivateKey = key
	}
	return err
}

// ParsePublicKey parses the public key and returns a crypto/ed25519.PublicKey.
//
// In addition to the PEM produced by GenKeyPair it accepts:
//   - a PEM block whose body is the raw 32 byte key instead of PKIX DER
//   - base64 or hex encoded PKIX DER, or base64/hex of the raw 32 byte key
//   - the raw 32 byte key
func (k *Ed25519KeyPair) ParsePublicKey() (ed25519.PublicKey, error) {
	if len(k.PublicKey) == 0 {
		return nil, EmptyPublicKeyError{}
	}
	return selectKey(k.PublicKey, PublicKey, "Ed25519", parseEd25519PublicKey)
}

// parseEd25519PublicKey reads a raw 32 byte key or a PKIX SubjectPublicKeyInfo.
func parseEd25519PublicKey(body []byte) (ed25519.PublicKey, error) {
	if len(body) == ed25519.PublicKeySize {
		return ed25519.PublicKey(body), nil
	}

	publicKey, err := x509.ParsePKIXPublicKey(body)
	if err != nil {
		return nil, err
	}
	key, ok := publicKey.(ed25519.PublicKey)
	if !ok {
		return nil, UnsupportedKeyFormatError{
			Algorithm: "Ed25519",
			Detail:    fmt.Sprintf("the parsed key is %s, not an Ed25519 key", describeKey(publicKey)),
		}
	}
	return key, nil
}

// ParsePrivateKey parses the private key and returns a crypto/ed25519.PrivateKey.
//
// In addition to the PEM produced by GenKeyPair it accepts:
//   - base64 or hex encoded PKCS#8 DER
//   - base64 or hex encoded 32 byte seed, as printed by many key generators
//   - the raw 32 byte seed or 64 byte private key
func (k *Ed25519KeyPair) ParsePrivateKey() (ed25519.PrivateKey, error) {
	if len(k.PrivateKey) == 0 {
		return nil, EmptyPrivateKeyError{}
	}
	return selectKey(k.PrivateKey, PrivateKey, "Ed25519", parseEd25519PrivateKey)
}

// parseEd25519PrivateKey reads a PKCS#8 PrivateKeyInfo, a 32 byte seed or a
// 64 byte private key.
func parseEd25519PrivateKey(body []byte) (ed25519.PrivateKey, error) {
	switch len(body) {
	case ed25519.SeedSize:
		return ed25519.NewKeyFromSeed(body), nil
	case ed25519.PrivateKeySize:
		return ed25519.PrivateKey(body), nil
	}

	privateKey, err := x509.ParsePKCS8PrivateKey(body)
	if err != nil {
		return nil, err
	}
	key, ok := privateKey.(ed25519.PrivateKey)
	if !ok {
		return nil, UnsupportedKeyFormatError{
			Algorithm: "Ed25519",
			Detail:    fmt.Sprintf("the parsed key is %s, not an Ed25519 key", describeKey(privateKey)),
		}
	}
	return key, nil
}

// FormatPublicKey formats the public key into a PEM "PUBLIC KEY" block.
// It accepts the same inputs as ParsePublicKey, so keys copied from other tools
// are normalized instead of being rejected.
func (k *Ed25519KeyPair) FormatPublicKey(publicKey []byte) ([]byte, error) {
	if len(publicKey) == 0 {
		return []byte{}, EmptyPublicKeyError{}
	}

	key, err := selectKey(publicKey, PublicKey, "Ed25519", parseEd25519PublicKey)
	if err != nil {
		return []byte{}, err
	}
	der, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		return []byte{}, InvalidPublicKeyError{Err: err}
	}
	return pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: der,
	}), nil
}

// FormatPrivateKey formats the private key into a PEM "PRIVATE KEY" block.
// It accepts the same inputs as ParsePrivateKey.
func (k *Ed25519KeyPair) FormatPrivateKey(privateKey []byte) ([]byte, error) {
	if len(privateKey) == 0 {
		return []byte{}, EmptyPrivateKeyError{}
	}

	key, err := selectKey(privateKey, PrivateKey, "Ed25519", parseEd25519PrivateKey)
	if err != nil {
		return []byte{}, err
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return []byte{}, InvalidPrivateKeyError{Err: err}
	}
	return pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: der,
	}), nil
}

// CompressPublicKey returns the base64 body of the public key PEM block.
// The input is decoded with pem.Decode, so optional block headers such as
// "Bag Attributes" are dropped instead of ending up in the body.
func (k *Ed25519KeyPair) CompressPublicKey(publicKey []byte) []byte {
	return compressKey(publicKey)
}

// CompressPrivateKey returns the base64 body of the private key PEM block.
// The input is decoded with pem.Decode, so optional block headers such as
// "Bag Attributes" are dropped instead of ending up in the body.
func (k *Ed25519KeyPair) CompressPrivateKey(privateKey []byte) []byte {
	return compressKey(privateKey)
}
