package keypair

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"io"
	"io/fs"
	"strings"

	"github.com/dromara/dongle/utils"
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

	// Error stores any error that occurred during key operations
	Error error
}

// NewEd25519KeyPair returns a new Ed25519KeyPair instance.
func NewEd25519KeyPair() *Ed25519KeyPair {
	return &Ed25519KeyPair{}
}

// GenKeyPair generates a new Ed25519KeyPair instance.
// The generated keys are formatted in PEM format using PKCS8 format.
//
// Note: The generated keys are automatically formatted in PEM format using PKCS8 format.
func (k *Ed25519KeyPair) GenKeyPair() *Ed25519KeyPair {
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

	return k
}

// SetPublicKey sets the public key and formats it in PKCS8 format.
// The input key is expected to be in PEM format and will be reformatted if necessary.
func (k *Ed25519KeyPair) SetPublicKey(publicKey []byte) {
	k.PublicKey = k.FormatPublicKey(publicKey)
}

// SetPrivateKey sets the private key and formats it in PKCS8 format.
// The input key is expected to be in PEM format and will be reformatted if necessary.
func (k *Ed25519KeyPair) SetPrivateKey(privateKey []byte) {
	k.PrivateKey = k.FormatPrivateKey(privateKey)
}

// LoadPublicKey loads a public key from a file.
// The file should contain a PEM-encoded public key.
// This method reads the entire file content and sets it as the public key.
//
// Note: The file format is automatically detected from the PEM headers.
// Only PKCS8 format is supported for ED25519.
func (k *Ed25519KeyPair) LoadPublicKey(f fs.File) {
	if f == nil {
		k.Error = NilPemBlockError{}
		return
	}
	// Read the entire file content
	k.PublicKey, k.Error = io.ReadAll(f)
	return
}

// LoadPrivateKey loads a private key from a file.
// The file should contain a PEM-encoded private key.
// This method reads the entire file content and sets it as the private key.
//
// Note: The file format is automatically detected from the PEM headers.
// Only PKCS8 format is supported for ED25519.
func (k *Ed25519KeyPair) LoadPrivateKey(f fs.File) {
	if f == nil {
		k.Error = NilPemBlockError{}
		return
	}
	k.PrivateKey, k.Error = io.ReadAll(f)
}

// ParsePublicKey parses the public key from PEM format and returns a Go crypto/ed25519.PublicKey.
// It supports PKCS8 format.
//
// Note: This method automatically detects the key format from the PEM headers.
func (k *Ed25519KeyPair) ParsePublicKey() (pub ed25519.PublicKey, err error) {
	publicKey := k.PublicKey
	block, _ := pem.Decode(publicKey)
	if block == nil {
		err = NilPemBlockError{}
		return
	}

	// Parse based on the PEM block type
	if block.Type == "PUBLIC KEY" {
		// PKCS8 format public key
		pubInterface, err8 := x509.ParsePKIXPublicKey(block.Bytes)
		if err8 != nil {
			err = InvalidPublicKeyError{Err: err8}
			return
		}
		pub, err = pubInterface.(ed25519.PublicKey), nil
	}
	return
}

// ParsePrivateKey parses the private key from PEM format and returns a Go crypto/ed25519.PrivateKey.
// It supports PKCS8 format.
//
// Note: This method automatically detects the key format from the PEM headers.
func (k *Ed25519KeyPair) ParsePrivateKey() (pri ed25519.PrivateKey, err error) {
	privateKey := k.PrivateKey
	block, _ := pem.Decode(privateKey)
	if block == nil {
		err = NilPemBlockError{}
		return
	}

	// Parse based on the PEM block type
	if block.Type == "PRIVATE KEY" {
		// PKCS8 format private key
		pri8, err8 := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err8 != nil {
			err = InvalidPrivateKeyError{Err: err8}
			return
		}
		pri, err = pri8.(ed25519.PrivateKey), nil
	}
	// For unknown key formats, return nil without error (consistent with ParsePublicKey)
	return
}

// FormatPublicKey formats the public key into the specified PEM format.
func (k *Ed25519KeyPair) FormatPublicKey(publicKey []byte) []byte {
	if len(publicKey) == 0 {
		return []byte{}
	}

	// ED25519 only supports PKCS8 format
	header := "-----BEGIN PUBLIC KEY-----\n"
	tail := "-----END PUBLIC KEY-----\n"

	return formatKeyBody(publicKey, header, tail)
}

// FormatPrivateKey formats the private key into the specified PEM format.
func (k *Ed25519KeyPair) FormatPrivateKey(privateKey []byte) []byte {
	if len(privateKey) == 0 {
		return []byte{}
	}

	// ED25519 only supports PKCS8 format
	header := "-----BEGIN PRIVATE KEY-----\n"
	tail := "-----END PRIVATE KEY-----\n"

	return formatKeyBody(privateKey, header, tail)
}

// CompressPublicKey removes the PEM headers and footers from the public key.
// It supports PKCS8 format and removes all whitespace characters.
// The resulting byte slice contains only the base64-encoded key data.
func (k *Ed25519KeyPair) CompressPublicKey(publicKey []byte) []byte {
	// Convert byte slice to string for easier manipulation
	keyStr := utils.Bytes2String(publicKey)

	// Remove the PEM headers (only PKCS8 for ED25519)
	keyStr = strings.ReplaceAll(keyStr, "-----BEGIN PUBLIC KEY-----", "")

	// Remove the PEM footers (only PKCS8 for ED25519)
	keyStr = strings.ReplaceAll(keyStr, "-----END PUBLIC KEY-----", "")

	// Remove all newline characters and whitespace
	keyStr = strings.ReplaceAll(keyStr, "\n", "")
	keyStr = strings.ReplaceAll(keyStr, "\r", "")
	keyStr = strings.ReplaceAll(keyStr, " ", "")
	keyStr = strings.ReplaceAll(keyStr, "\t", "")

	// Remove any remaining whitespace that might be present
	keyStr = strings.TrimSpace(keyStr)

	return utils.String2Bytes(keyStr)
}

// CompressPrivateKey removes the PEM headers and footers from the private key.
// It supports PKCS8 format and removes all whitespace characters.
// The resulting byte slice contains only the base64-encoded key data.
func (k *Ed25519KeyPair) CompressPrivateKey(privateKey []byte) []byte {
	// Convert byte slice to string for easier manipulation
	keyStr := utils.Bytes2String(privateKey)

	// Remove the PEM headers (only PKCS8 for ED25519)
	keyStr = strings.ReplaceAll(keyStr, "-----BEGIN PRIVATE KEY-----", "")

	// Remove the PEM footers (only PKCS8 for ED25519)
	keyStr = strings.ReplaceAll(keyStr, "-----END PRIVATE KEY-----", "")

	// Remove all newline characters and whitespace
	keyStr = strings.ReplaceAll(keyStr, "\n", "")
	keyStr = strings.ReplaceAll(keyStr, "\r", "")
	keyStr = strings.ReplaceAll(keyStr, " ", "")
	keyStr = strings.ReplaceAll(keyStr, "\t", "")

	// Remove any remaining whitespace that might be present
	keyStr = strings.TrimSpace(keyStr)

	return utils.String2Bytes(keyStr)
}
