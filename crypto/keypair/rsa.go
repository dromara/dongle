// Package keypair provides RSA key pair management functionality.
// It supports key generation, formatting, parsing, and manipulation for both PKCS1 and PKCS8 formats.
package keypair

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"io"
	"io/fs"
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
		privateBytes := x509.MarshalPKCS1PrivateKey(key)
		k.PrivateKey = pem.EncodeToMemory(&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: privateBytes,
		})
		publicBytes := x509.MarshalPKCS1PublicKey(&key.PublicKey)
		k.PublicKey = pem.EncodeToMemory(&pem.Block{
			Type:  "RSA PUBLIC KEY",
			Bytes: publicBytes,
		})
	}

	if k.Format == PKCS8 {
		// PKCS8 format: Use generic headers
		privateBytes, _ := x509.MarshalPKCS8PrivateKey(key)
		k.PrivateKey = pem.EncodeToMemory(&pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: privateBytes,
		})
		publicBytes, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
		k.PublicKey = pem.EncodeToMemory(&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: publicBytes,
		})
	}
	return nil
}

// SetPublicKey sets the public key and formats it according to the current format.
// The input key is expected to be in PEM format and will be reformatted if necessary.
func (k *RsaKeyPair) SetPublicKey(publicKey []byte) {
	k.PublicKey = k.formatPublicKey(publicKey)
}

// SetPrivateKey sets the private key and formats it according to the current format.
// The input key is expected to be in PEM format and will be reformatted if necessary.
func (k *RsaKeyPair) SetPrivateKey(privateKey []byte) {
	k.PrivateKey = k.formatPrivateKey(privateKey)
}

// LoadPublicKey loads a public key from a file.
// The file should contain a PEM-encoded public key.
// This method reads the entire file content and sets it as the public key.
//
// Note: The file format is automatically detected from the PEM headers.
// Both PKCS1 and PKCS8 formats are supported.
func (k *RsaKeyPair) LoadPublicKey(f fs.File) error {
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
// Both PKCS1 and PKCS8 formats are supported.
func (k *RsaKeyPair) LoadPrivateKey(f fs.File) error {
	key, err := io.ReadAll(f)
	if err == nil {
		k.PrivateKey = key
		return nil
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
	block, _ := pem.Decode(publicKey)
	if block == nil {
		return nil, NilPemBlockError{}
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
	return nil, nil
}

// ParsePrivateKey parses the private key from PEM format.
// It supports both PKCS1 and PKCS8 formats automatically.
//
// Note: This method automatically detects the key format from the PEM headers.
func (k *RsaKeyPair) ParsePrivateKey() (*rsa.PrivateKey, error) {
	privateKey := k.PrivateKey
	block, _ := pem.Decode(privateKey)
	if block == nil {
		return nil, NilPemBlockError{}
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
	return nil, nil
}

// formatPublicKey formats the public key into the specified PEM format.
func (k *RsaKeyPair) formatPublicKey(publicKey []byte) []byte {
	if len(publicKey) == 0 {
		return []byte{}
	}

	// Determine the appropriate headers based on the format
	var header, tail string
	if k.Format == PKCS1 {
		header = "-----BEGIN RSA PUBLIC KEY-----\n"
		tail = "-----END RSA PUBLIC KEY-----\n"
	}
	if k.Format == PKCS8 {
		header = "-----BEGIN PUBLIC KEY-----\n"
		tail = "-----END PUBLIC KEY-----\n"
	}

	return formatKeyBody(publicKey, header, tail)
}

// formatPrivateKey formats the private key into the specified PEM format.
func (k *RsaKeyPair) formatPrivateKey(privateKey []byte) []byte {
	if len(privateKey) == 0 {
		return []byte{}
	}

	// Determine the appropriate headers based on the format
	var header, tail string
	if k.Format == PKCS1 {
		header = "-----BEGIN RSA PRIVATE KEY-----\n"
		tail = "-----END RSA PRIVATE KEY-----\n"
	}
	if k.Format == PKCS8 {
		header = "-----BEGIN PRIVATE KEY-----\n"
		tail = "-----END PRIVATE KEY-----\n"
	}

	return formatKeyBody(privateKey, header, tail)
}
