// Package keypair provides ED25519 key pair management functionality.
// It supports key generation, formatting, parsing, and manipulation for PKCS8 format.
package keypair

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"io"
	"io/fs"

	"github.com/dromara/dongle/coding"
	"github.com/dromara/dongle/util"
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

// NewEd25519KeyPair creates and returns a new ED25519 key pair instance.
func NewEd25519KeyPair() *Ed25519KeyPair {
	return &Ed25519KeyPair{}
}

// GenKeyPair generates a new ED25519 key pair.
// The generated keys are formatted in PEM format using PKCS8 format.
//
// Note: The generated keys are automatically formatted in PEM format using PKCS8 format.
func (k *Ed25519KeyPair) GenKeyPair() *Ed25519KeyPair {
	return k.genKeyPairWithRand(rand.Reader)
}

// genKeyPairWithRand generates a new ED25519 key pair using the specified random reader.
// This method is primarily used for testing purposes to simulate error conditions.
func (k *Ed25519KeyPair) genKeyPairWithRand(randReader io.Reader) *Ed25519KeyPair {
	publicKey, privateKey, _ := ed25519.GenerateKey(randReader)

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

// SetRawSign sets the signature in raw byte format.
// This method directly assigns the signature bytes without any decoding or conversion.
func (k *Ed25519KeyPair) SetRawSign(sign []byte) {
	k.Sign = sign
}

// SetHexSign sets the signature in hexadecimal format.
// This method decodes the hex string to raw bytes before setting the signature.
func (k *Ed25519KeyPair) SetHexSign(sign []byte) {
	k.Sign = coding.NewDecoder().FromBytes(sign).ByHex().ToBytes()
}

// SetBase64Sign sets the signature in Base64 format.
// This method decodes the Base64 string to raw bytes before setting the signature.
func (k *Ed25519KeyPair) SetBase64Sign(sign []byte) {
	k.Sign = coding.NewDecoder().FromBytes(sign).ByBase64().ToBytes()
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

// formatPublicKey formats a public key according to the specified format.
// It decodes the input PEM key and reformats it with the appropriate headers.
func (k *Ed25519KeyPair) formatPublicKey(publicKey []byte) []byte {
	if len(publicKey) == 0 {
		return nil
	}

	// Decode the PEM block to get the raw key bytes
	block, _ := pem.Decode(publicKey)
	if block == nil {
		return nil
	}

	// ED25519 only supports PKCS8 format
	header := "-----BEGIN PUBLIC KEY-----\n"
	tail := "-----END PUBLIC KEY-----\n"

	return k.formatKeyBody(block.Bytes, header, tail)
}

// formatPrivateKey formats a private key according to the specified format.
// It decodes the input PEM key and reformats it with the appropriate headers.
func (k *Ed25519KeyPair) formatPrivateKey(privateKey []byte) []byte {
	if len(privateKey) == 0 {
		return nil
	}

	// Decode the PEM block to get the raw key bytes
	block, _ := pem.Decode(privateKey)
	if block == nil {
		return nil
	}

	// ED25519 only supports PKCS8 format
	header := "-----BEGIN PRIVATE KEY-----\n"
	tail := "-----END PRIVATE KEY-----\n"

	return k.formatKeyBody(block.Bytes, header, tail)
}

// formatKeyBody formats the key body into 64-character lines with the specified header and tail.
// This is a helper function used by formatPublicKey and formatPrivateKey.
func (k *Ed25519KeyPair) formatKeyBody(keyBody []byte, header, tail string) []byte {
	bodyStr := util.Bytes2String(keyBody)
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
	return util.String2Bytes(formatted)
}
