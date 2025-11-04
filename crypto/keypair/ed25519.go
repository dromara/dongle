package keypair

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"io"
	"io/fs"
)

// Ed25519KeyPair represents an ED25519 key pair with public and private keys.
// It supports PKCS8 format and provides methods for key generation,
// formatting, and parsing.
type Ed25519KeyPair struct {
	// PublicKey contains the PEM-encoded public key
	PublicKey []byte

	// PrivateKey contains the PEM-encoded private key
	PrivateKey []byte

	// Sign contains the signature bytes for verification
	Sign []byte
}

// NewEd25519KeyPair returns a new Ed25519KeyPair instance.
func NewEd25519KeyPair() *Ed25519KeyPair {
	return &Ed25519KeyPair{}
}

// GenKeyPair generates a new Ed25519KeyPair instance.
// The generated keys are formatted in PEM format using PKCS8 format.
//
// Note: The generated keys are automatically formatted in PEM format using PKCS8 format.
func (k *Ed25519KeyPair) GenKeyPair() {
	publicKey, privateKey, _ := ed25519.GenerateKey(rand.Reader)

	// ED25519 only supports PKCS8 format
	privateBytes, _ := x509.MarshalPKCS8PrivateKey(privateKey)
	k.PrivateKey = pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privateBytes,
	})

	publicBytes, _ := x509.MarshalPKIXPublicKey(publicKey)
	k.PublicKey = pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicBytes,
	})
}

// SetPublicKey sets the public key and formats it in PKCS8 format.
// The input key is expected to be in PEM format and will be reformatted if necessary.
func (k *Ed25519KeyPair) SetPublicKey(publicKey []byte) {
	k.PublicKey = k.formatPublicKey(publicKey)
}

// SetPrivateKey sets the private key and formats it in PKCS8 format.
// The input key is expected to be in PEM format and will be reformatted if necessary.
func (k *Ed25519KeyPair) SetPrivateKey(privateKey []byte) {
	k.PrivateKey = k.formatPrivateKey(privateKey)
}

// LoadPublicKey loads a public key from a file.
// The file should contain a PEM-encoded public key.
// This method reads the entire file content and sets it as the public key.
//
// Note: The file format is automatically detected from the PEM headers.
// Only PKCS8 format is supported for ED25519.
func (k *Ed25519KeyPair) LoadPublicKey(f fs.File) error {
	key, err := io.ReadAll(f)
	if err == nil {
		k.PublicKey = key
		return nil
	}
	return err
}

// LoadPrivateKey loads a private key from a file.
// The file should contain a PEM-encoded private key.
// This method reads the entire file content and sets it as the private key.
//
// Note: The file format is automatically detected from the PEM headers.
// Only PKCS8 format is supported for ED25519.
func (k *Ed25519KeyPair) LoadPrivateKey(f fs.File) error {
	key, err := io.ReadAll(f)
	if err == nil {
		k.PrivateKey = key
		return nil
	}
	return err
}

// ParsePublicKey parses the public key from PEM format and returns a Go crypto/ed25519.PublicKey.
// It supports PKCS8 format.
//
// Note: This method automatically detects the key format from the PEM headers.
func (k *Ed25519KeyPair) ParsePublicKey() (ed25519.PublicKey, error) {
	publicKey := k.PublicKey
	block, _ := pem.Decode(publicKey)
	if block == nil {
		return nil, NilPemBlockError{}
	}

	// Parse based on the PEM block type
	if block.Type == "PUBLIC KEY" {
		// PKCS8 format public key
		pub, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, InvalidPublicKeyError{Err: err}
		}
		return pub.(ed25519.PublicKey), nil
	}
	return nil, nil
}

// ParsePrivateKey parses the private key from PEM format and returns a Go crypto/ed25519.PrivateKey.
// It supports PKCS8 format.
//
// Note: This method automatically detects the key format from the PEM headers.
func (k *Ed25519KeyPair) ParsePrivateKey() (ed25519.PrivateKey, error) {
	privateKey := k.PrivateKey
	block, _ := pem.Decode(privateKey)
	if block == nil {
		return nil, NilPemBlockError{}
	}

	// Parse based on the PEM block type
	if block.Type == "PRIVATE KEY" {
		// PKCS8 format private key
		pri8, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, InvalidPrivateKeyError{Err: err}
		}
		return pri8.(ed25519.PrivateKey), nil
	}
	return nil, nil
}

// formatPublicKey formats the public key into the specified PEM format.
func (k *Ed25519KeyPair) formatPublicKey(publicKey []byte) []byte {
	if len(publicKey) == 0 {
		return []byte{}
	}

	// ED25519 only supports PKCS8 format
	header := "-----BEGIN PUBLIC KEY-----\n"
	tail := "-----END PUBLIC KEY-----\n"

	return formatKeyBody(publicKey, header, tail)
}

// formatPrivateKey formats the private key into the specified PEM format.
func (k *Ed25519KeyPair) formatPrivateKey(privateKey []byte) []byte {
	if len(privateKey) == 0 {
		return []byte{}
	}

	// ED25519 only supports PKCS8 format
	header := "-----BEGIN PRIVATE KEY-----\n"
	tail := "-----END PRIVATE KEY-----\n"

	return formatKeyBody(privateKey, header, tail)
}
