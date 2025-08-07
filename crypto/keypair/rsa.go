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

	"github.com/dromara/dongle/coding"
	"github.com/dromara/dongle/utils"
)

// KeyFormat represents the format of RSA keys.
// It can be either PKCS1 or PKCS8 format.
type KeyFormat string

// Key format constants for RSA key pairs.
const (
	// PKCS1 represents the PKCS#1 format for RSA keys.
	// This format uses specific headers like "-----BEGIN RSA PUBLIC KEY-----".
	PKCS1 KeyFormat = "pkcs1"

	// PKCS8 represents the PKCS#8 format for RSA keys.
	// This format uses generic headers like "-----BEGIN PUBLIC KEY-----".
	PKCS8 KeyFormat = "pkcs8"
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

	// Error stores any error that occurred during key operations
	Error error
}

// NewRsaKeyPair creates and returns a new RSA key pair instance.
// The default format is PKCS8 and the default hash function is SHA256.
func NewRsaKeyPair() *RsaKeyPair {
	return &RsaKeyPair{
		Format: PKCS8,
		Hash:   crypto.SHA256,
	}
}

// GenKeyPair generates a new RSA key pair with the specified key size.
// The generated keys are formatted according to the current Format setting.
//
// Note: The generated keys are automatically formatted in PEM format
// according to the current Format setting (PKCS1 or PKCS8).
func (k *RsaKeyPair) GenKeyPair(size int) *RsaKeyPair {
	// Generate a new RSA private key
	key, err := rsa.GenerateKey(rand.Reader, size)
	if err != nil {
		k.Error = err
		return k
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
	return k
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
func (k *RsaKeyPair) LoadPublicKey(f fs.File) {
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
// Both PKCS1 and PKCS8 formats are supported.
func (k *RsaKeyPair) LoadPrivateKey(f fs.File) {
	if f == nil {
		k.Error = NilPemBlockError{}
		return
	}
	k.PrivateKey, k.Error = io.ReadAll(f)
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

// SetRawSign sets the signature in raw byte format.
// This method directly assigns the signature bytes without any decoding or conversion.
func (k *RsaKeyPair) SetRawSign(sign []byte) {
	k.Sign = sign
}

// SetHexSign sets the signature in hexadecimal format.
// This method decodes the hex string to raw bytes before setting the signature.
func (k *RsaKeyPair) SetHexSign(sign []byte) {
	k.Sign = coding.NewDecoder().FromBytes(sign).ByHex().ToBytes()
}

// SetBase64Sign sets the signature in Base64 format.
// This method decodes the Base64 string to raw bytes before setting the signature.
func (k *RsaKeyPair) SetBase64Sign(sign []byte) {
	k.Sign = coding.NewDecoder().FromBytes(sign).ByBase64().ToBytes()
}

// ParsePublicKey parses the public key from PEM format and returns a Go crypto/rsa.PublicKey.
// It supports both PKCS1 and PKCS8 formats automatically.
//
// Note: This method automatically detects the key format from the PEM headers.
func (k *RsaKeyPair) ParsePublicKey() (pub *rsa.PublicKey, err error) {
	publicKey := k.PublicKey
	block, _ := pem.Decode(publicKey)
	if block == nil {
		err = NilPemBlockError{}
		return
	}

	// Parse based on the PEM block type
	if block.Type == "RSA PUBLIC KEY" {
		// PKCS1 format public key
		pub, err = x509.ParsePKCS1PublicKey(block.Bytes)
		if err != nil {
			err = InvalidPublicKeyError{Err: err}
			return
		}
	}
	if block.Type == "PUBLIC KEY" {
		// PKCS8 format public key
		pub8, err8 := x509.ParsePKIXPublicKey(block.Bytes)
		if err8 != nil {
			err = InvalidPublicKeyError{Err: err8}
			return
		}
		pub, err = pub8.(*rsa.PublicKey), err8
	}
	return
}

// ParsePrivateKey parses the private key from PEM format and returns a Go crypto/rsa.PrivateKey.
// It supports both PKCS1 and PKCS8 formats automatically.
//
// Note: This method automatically detects the key format from the PEM headers.
func (k *RsaKeyPair) ParsePrivateKey() (pri *rsa.PrivateKey, err error) {
	privateKey := k.PrivateKey
	block, _ := pem.Decode(privateKey)
	if block == nil {
		err = NilPemBlockError{}
		return
	}

	// Parse based on the PEM block type
	if block.Type == "RSA PRIVATE KEY" {
		// PKCS1 format private key
		pri, err = x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			err = InvalidPrivateKeyError{Err: err}
			return
		}
	}
	if block.Type == "PRIVATE KEY" {
		// PKCS8 format private key
		pri8, err8 := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err8 != nil {
			err = InvalidPrivateKeyError{Err: err}
			return
		}
		pri, err = pri8.(*rsa.PrivateKey), err8
	}
	return
}

// formatPublicKey formats a public key according to the specified format.
// It decodes the input PEM key and reformats it with the appropriate headers.
func (k *RsaKeyPair) formatPublicKey(publicKey []byte) []byte {
	if len(publicKey) == 0 {
		return nil
	}

	// Decode the PEM block to get the raw key bytes
	block, _ := pem.Decode(publicKey)
	if block == nil {
		return nil
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

	return formatKeyBody(block.Bytes, header, tail)
}

// formatPrivateKey formats a private key according to the specified format.
// It decodes the input PEM key and reformats it with the appropriate headers.
func (k *RsaKeyPair) formatPrivateKey(privateKey []byte) []byte {
	if len(privateKey) == 0 {
		return nil
	}

	// Decode the PEM block to get the raw key bytes
	block, _ := pem.Decode(privateKey)
	if block == nil {
		return nil
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

	return formatKeyBody(block.Bytes, header, tail)
}

// formatKeyBody formats the key body into 64-character lines with the specified header and tail.
// This is a helper function used by formatPublicKey and formatPrivateKey.
func formatKeyBody(keyBody []byte, header, tail string) []byte {
	bodyStr := utils.Bytes2String(keyBody)
	formatted := header

	// Split the key body into 64-character lines
	for i := 0; i < len(bodyStr); i += 64 {
		end := i + 64
		if end > len(bodyStr) {
			end = len(bodyStr)
		}
		formatted += bodyStr[i:end] + "\n"
	}
	formatted += tail
	return utils.String2Bytes(formatted)
}
