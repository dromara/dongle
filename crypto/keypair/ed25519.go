package keypair

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"strings"

	"github.com/dromara/dongle/coding"
	"github.com/dromara/dongle/internal/utils"
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

// SetPublicKey sets the public key and formats it in PKCS8 format.
// The input key is expected to be in PEM format and will be reformatted if necessary.
func (k *Ed25519KeyPair) SetPublicKey(publicKey []byte) error {
	key, err := k.FormatPublicKey(publicKey)
	if err == nil {
		k.PublicKey = key
	}
	return err
}

// SetPrivateKey sets the private key and formats it in PKCS8 format.
// The input key is expected to be in PEM format and will be reformatted if necessary.
func (k *Ed25519KeyPair) SetPrivateKey(privateKey []byte) error {
	key, err := k.FormatPrivateKey(privateKey)
	if err == nil {
		k.PrivateKey = key
	}
	return err
}

// ParsePublicKey parses the public key from PEM format and returns a Go crypto/ed25519.PublicKey.
// It supports PKCS8 format.
//
// Note: This method automatically detects the key format from the PEM headers.
func (k *Ed25519KeyPair) ParsePublicKey() (ed25519.PublicKey, error) {
	publicKey := k.PublicKey
	if len(publicKey) == 0 {
		return nil, EmptyPublicKeyError{}
	}
	block, _ := pem.Decode(publicKey)
	if block == nil {
		return nil, InvalidPublicKeyError{}
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
	return nil, UnsupportedPemTypeError{}
}

// ParsePrivateKey parses the private key from PEM format and returns a Go crypto/ed25519.PrivateKey.
// It supports PKCS8 format.
//
// Note: This method automatically detects the key format from the PEM headers.
func (k *Ed25519KeyPair) ParsePrivateKey() (ed25519.PrivateKey, error) {
	privateKey := k.PrivateKey
	if len(privateKey) == 0 {
		return nil, EmptyPrivateKeyError{}
	}
	block, _ := pem.Decode(privateKey)
	if block == nil {
		return nil, InvalidPrivateKeyError{}
	}

	// Parse based on the PEM block type
	if block.Type == "PRIVATE KEY" {
		// PKCS8 format private key
		pri, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, InvalidPrivateKeyError{Err: err}
		}
		return pri.(ed25519.PrivateKey), nil
	}
	return nil, UnsupportedPemTypeError{}
}

// FormatPublicKey formats base64-encoded der public key into the specified PEM format.
func (k *Ed25519KeyPair) FormatPublicKey(publicKey []byte) ([]byte, error) {
	if len(publicKey) == 0 {
		return []byte{}, EmptyPublicKeyError{}
	}

	decoder := coding.NewDecoder().FromBytes(publicKey).ByBase64()
	if decoder.Error != nil {
		return []byte{}, InvalidPublicKeyError{Err: decoder.Error}
	}

	// ED25519 only supports PKCS8 format
	// Use pem.EncodeToMemory to format the key
	return pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: decoder.ToBytes(),
	}), nil
}

// FormatPrivateKey formats base64-encoded der private key into the specified PEM format.
func (k *Ed25519KeyPair) FormatPrivateKey(privateKey []byte) ([]byte, error) {
	if len(privateKey) == 0 {
		return []byte{}, EmptyPrivateKeyError{}
	}

	decoder := coding.NewDecoder().FromBytes(privateKey).ByBase64()
	if decoder.Error != nil {
		return []byte{}, InvalidPrivateKeyError{Err: decoder.Error}
	}

	// ED25519 only supports PKCS8 format
	// Use pem.EncodeToMemory to format the key
	return pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: decoder.ToBytes(),
	}), nil
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
