// Package keypair provides RSA key pair management functionality.
// It supports key generation, formatting, parsing, and manipulation for both PKCS1 and PKCS8 formats.
package keypair

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"strings"

	"github.com/dromara/dongle/coding"
	"github.com/dromara/dongle/internal/utils"
)

// RsaKeyPair represents an RSA key pair with public and private keys.
// It supports both PKCS1 and PKCS8 formats and provides methods for key generation,
// formatting, and parsing.
type RsaKeyPair struct {
	// PublicKey contains the PEM-encoded public key
	PublicKey []byte

	// PrivateKey contains the PEM-encoded private key
	PrivateKey []byte

	// Sign contains the signature bytes for verification
	Sign []byte

	// Format specifies the key format (PKCS1 or PKCS8)
	Format KeyFormat

	// Hash specifies the hash function used for RSA operations
	// This is used for OAEP padding in encryption and for signature generation/verification
	Hash crypto.Hash
}

// NewRsaKeyPair returns a new RsaKeyPair instance.
// The default format is PKCS8 and the default hash function is SHA256.
func NewRsaKeyPair() *RsaKeyPair {
	return &RsaKeyPair{
		Format: PKCS8,
		Hash:   crypto.SHA256,
	}
}

// GenKeyPair generates a new RsaKeyPair with the specified key size.
// The generated keys are formatted according to the current Format setting.
//
// Note: The generated keys are automatically formatted in PEM format
// according to the current Format setting (PKCS1 or PKCS8).
func (k *RsaKeyPair) GenKeyPair(size int) error {
	// Generate a new RSA private key
	key, err := rsa.GenerateKey(rand.Reader, size)
	if err != nil {
		return err
	}

	// Format keys according to the specified format
	if k.Format == PKCS1 {
		// PKCS1 format: Use specific RSA headers
		privateKeyDer := x509.MarshalPKCS1PrivateKey(key)
		k.PrivateKey = pem.EncodeToMemory(&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: privateKeyDer,
		})
		publicKeyDer := x509.MarshalPKCS1PublicKey(&key.PublicKey)
		k.PublicKey = pem.EncodeToMemory(&pem.Block{
			Type:  "RSA PUBLIC KEY",
			Bytes: publicKeyDer,
		})
		return nil
	}

	if k.Format == PKCS8 {
		// PKCS8 format: Use generic headers
		if privateKeyDer, err := x509.MarshalPKCS8PrivateKey(key); err == nil {
			k.PrivateKey = pem.EncodeToMemory(&pem.Block{
				Type:  "PRIVATE KEY",
				Bytes: privateKeyDer,
			})
		}

		if publicKeyDer, err := x509.MarshalPKIXPublicKey(&key.PublicKey); err == nil {
			k.PublicKey = pem.EncodeToMemory(&pem.Block{
				Type:  "PUBLIC KEY",
				Bytes: publicKeyDer,
			})
		}
		return nil
	}
	return UnsupportedPemTypeError{}
}

// SetPublicKey sets the public key and formats it according to the current format.
// The input key is expected to be in PEM format and will be reformatted if necessary.
func (k *RsaKeyPair) SetPublicKey(publicKey []byte) error {
	key, err := k.FormatPublicKey(publicKey)
	if err == nil {
		k.PublicKey = key
	}
	return err
}

// SetPrivateKey sets the private key and formats it according to the current format.
// The input key is expected to be in PEM format and will be reformatted if necessary.
func (k *RsaKeyPair) SetPrivateKey(privateKey []byte) error {
	key, err := k.FormatPrivateKey(privateKey)
	if err == nil {
		k.PrivateKey = key
	}
	return err
}

// SetFormat sets the key format for the RSA key pair.
// This affects how keys are generated, formatted, and parsed.
// The format can be either PKCS1 or PKCS8.
func (k *RsaKeyPair) SetFormat(format KeyFormat) {
	k.Format = format
}

// SetHash sets the hash function used for OAEP padding in RSA operations.
// This is particularly important for PKCS8 format keys that use OAEP padding.
func (k *RsaKeyPair) SetHash(hash crypto.Hash) {
	k.Hash = hash
}

// ParsePublicKey parses the public key from PEM format.
// It supports both PKCS1 and PKCS8 formats automatically.
//
// Note: This method automatically detects the key format from the PEM headers.
func (k *RsaKeyPair) ParsePublicKey() (*rsa.PublicKey, error) {
	publicKey := k.PublicKey
	if len(publicKey) == 0 {
		return nil, EmptyPublicKeyError{}
	}
	block, _ := pem.Decode(publicKey)
	if block == nil {
		return nil, InvalidPublicKeyError{}
	}

	// PKCS1 format public key
	if block.Type == "RSA PUBLIC KEY" {
		pub, err := x509.ParsePKCS1PublicKey(block.Bytes)
		if err != nil {
			err = InvalidPublicKeyError{Err: err}
		}
		return pub, err
	}

	// PKCS8 format public key
	if block.Type == "PUBLIC KEY" {
		pub, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, InvalidPublicKeyError{Err: err}
		}
		return pub.(*rsa.PublicKey), err
	}
	return nil, UnsupportedPemTypeError{}
}

// ParsePrivateKey parses the private key from PEM format.
// It supports both PKCS1 and PKCS8 formats automatically.
//
// Note: This method automatically detects the key format from the PEM headers.
func (k *RsaKeyPair) ParsePrivateKey() (*rsa.PrivateKey, error) {
	privateKey := k.PrivateKey
	if len(privateKey) == 0 {
		return nil, EmptyPrivateKeyError{}
	}
	block, _ := pem.Decode(privateKey)
	if block == nil {
		return nil, InvalidPrivateKeyError{}
	}

	// PKCS1 format private key
	if block.Type == "RSA PRIVATE KEY" {
		pri, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, InvalidPrivateKeyError{Err: err}
		}
		return pri, err
	}

	// PKCS8 format private key
	if block.Type == "PRIVATE KEY" {
		pri, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, InvalidPrivateKeyError{Err: err}
		}
		return pri.(*rsa.PrivateKey), err
	}
	return nil, UnsupportedPemTypeError{}
}

// FormatPublicKey formats base64-encoded der public key into the specified PEM format.
func (k *RsaKeyPair) FormatPublicKey(publicKey []byte) ([]byte, error) {
	if len(publicKey) == 0 {
		return []byte{}, EmptyPublicKeyError{}
	}

	decoder := coding.NewDecoder().FromBytes(publicKey).ByBase64()
	if decoder.Error != nil {
		return []byte{}, InvalidPublicKeyError{Err: decoder.Error}
	}

	var blockType string
	switch k.Format {
	case PKCS1:
		blockType = "RSA PUBLIC KEY"
	case PKCS8:
		blockType = "PUBLIC KEY"
	default:
		return []byte{}, UnsupportedPemTypeError{}
	}

	// Use pem.EncodeToMemory to format the key
	return pem.EncodeToMemory(&pem.Block{
		Type:  blockType,
		Bytes: decoder.ToBytes(),
	}), nil
}

// FormatPrivateKey formats base64-encoded der private key into the specified PEM format.
func (k *RsaKeyPair) FormatPrivateKey(privateKey []byte) ([]byte, error) {
	if len(privateKey) == 0 {
		return []byte{}, EmptyPrivateKeyError{}
	}

	decoder := coding.NewDecoder().FromBytes(privateKey).ByBase64()
	if decoder.Error != nil {
		return []byte{}, InvalidPrivateKeyError{Err: decoder.Error}
	}

	var blockType string
	switch k.Format {
	case PKCS1:
		blockType = "RSA PRIVATE KEY"
	case PKCS8:
		blockType = "PRIVATE KEY"
	default:
		return []byte{}, UnsupportedPemTypeError{}
	}

	// Use pem.EncodeToMemory to format the key
	return pem.EncodeToMemory(&pem.Block{
		Type:  blockType,
		Bytes: decoder.ToBytes(),
	}), nil
}

// CompressPublicKey removes the PEM headers and footers from the public key.
// It supports both PKCS1 and PKCS8 formats and removes all whitespace characters.
// The resulting byte slice contains only the base64-encoded key data.
func (k *RsaKeyPair) CompressPublicKey(publicKey []byte) []byte {
	// Convert byte slice to string for easier manipulation
	keyStr := utils.Bytes2String(publicKey)

	// Remove the PEM headers (both PKCS1 and PKCS8)
	keyStr = strings.ReplaceAll(keyStr, "-----BEGIN PUBLIC KEY-----", "")
	keyStr = strings.ReplaceAll(keyStr, "-----BEGIN RSA PUBLIC KEY-----", "")

	// Remove the PEM footers (both PKCS1 and PKCS8)
	keyStr = strings.ReplaceAll(keyStr, "-----END PUBLIC KEY-----", "")
	keyStr = strings.ReplaceAll(keyStr, "-----END RSA PUBLIC KEY-----", "")

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
// It supports both PKCS1 and PKCS8 formats and removes all whitespace characters.
// The resulting byte slice contains only the base64-encoded key data.
func (k *RsaKeyPair) CompressPrivateKey(privateKey []byte) []byte {
	// Convert byte slice to string for easier manipulation
	keyStr := utils.Bytes2String(privateKey)

	// Remove the PEM headers (both PKCS1 and PKCS8)
	keyStr = strings.ReplaceAll(keyStr, "-----BEGIN PRIVATE KEY-----", "")
	keyStr = strings.ReplaceAll(keyStr, "-----BEGIN RSA PRIVATE KEY-----", "")

	// Remove the PEM footers (both PKCS1 and PKCS8)
	keyStr = strings.ReplaceAll(keyStr, "-----END PRIVATE KEY-----", "")
	keyStr = strings.ReplaceAll(keyStr, "-----END RSA PRIVATE KEY-----", "")

	// Remove all newline characters and whitespace
	keyStr = strings.ReplaceAll(keyStr, "\n", "")
	keyStr = strings.ReplaceAll(keyStr, "\r", "")
	keyStr = strings.ReplaceAll(keyStr, " ", "")
	keyStr = strings.ReplaceAll(keyStr, "\t", "")

	// Remove any remaining whitespace that might be present
	keyStr = strings.TrimSpace(keyStr)

	return utils.String2Bytes(keyStr)
}
