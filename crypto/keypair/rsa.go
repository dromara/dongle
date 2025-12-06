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

// RsaKeyFormat represents the PEM encoding format for RSA keys.
// This ONLY affects key generation (GenKeyPair) and determines the PEM header.
//
// IMPORTANT: RsaKeyFormat does NOT affect encryption/decryption/signing operations.
// For cryptographic operations, use RsaPaddingScheme instead.
//
// Key parsing (ParsePublicKey/ParsePrivateKey) automatically detects the format
// from PEM headers, so this field is not used during parsing.
type RsaKeyFormat string

// Key format constants for RSA key pairs.
const (
	// PKCS1 generates keys with RSA-specific PEM headers.
	// - Private key: "-----BEGIN RSA PRIVATE KEY-----"
	// - Public key: "-----BEGIN RSA PUBLIC KEY-----"
	// - Usage: Legacy compatibility, OpenSSL traditional format
	PKCS1 RsaKeyFormat = "pkcs1"

	// PKCS8 generates keys with generic PEM headers (recommended).
	// - Private key: "-----BEGIN PRIVATE KEY-----"
	// - Public key: "-----BEGIN PUBLIC KEY-----"
	// - Usage: Modern standard, works with multiple key algorithms
	PKCS8 RsaKeyFormat = "pkcs8"
)

// RsaPaddingScheme represents the padding scheme for RSA cryptographic operations.
//
// Different padding schemes are used for different operations:
// - PKCS1v15: Can be used for both encryption and signing
// - OAEP: Only for encryption (more secure than PKCS1v15)
// - PSS: Only for signing (more secure than PKCS1v15)
type RsaPaddingScheme string

const (
	// PKCS1v15 uses PKCS#1 v1.5 padding for RSA operations.
	// - For encryption/decryption: rsa.EncryptPKCS1v15 / rsa.DecryptPKCS1v15
	// - For signing/verification: rsa.SignPKCS1v15 / rsa.VerifyPKCS1v15
	// - Compatibility: Works with JSEncrypt, PHP openssl_* defaults
	// - Security: Adequate for most applications, widely supported
	// - Usage: Can be used for both encryption and signing operations
	PKCS1v15 RsaPaddingScheme = "pkcs1v15"

	// OAEP uses Optimal Asymmetric Encryption Padding (more secure).
	// - For encryption/decryption: rsa.EncryptOAEP / rsa.DecryptOAEP
	// - Compatibility: Modern standard, may not work with older libraries
	// - Security: Recommended for encryption in new applications
	// - Usage: ONLY for encryption/decryption operations
	//
	// Note: Attempting to use OAEP for signing/verification will return an error.
	// For signing, use PKCS1v15 or PSS instead.
	OAEP RsaPaddingScheme = "oaep"

	// PSS uses Probabilistic Signature Scheme (more secure for signing).
	// - For signing/verification: rsa.SignPSS / rsa.VerifyPSS
	// - Compatibility: Modern standard, may not work with older libraries
	// - Security: Recommended for signing in new applications
	// - Usage: ONLY for signing/verification operations
	//
	// Note: Attempting to use PSS for encryption/decryption will return an error.
	// For encryption, use PKCS1v15 or OAEP instead.
	PSS RsaPaddingScheme = "pss"
)

// RsaKeyPair represents an RSA key pair with public and private keys.
// It supports both PKCS1 and PKCS8 key formats and provides methods for
// key generation, formatting, and parsing.
type RsaKeyPair struct {
	// PublicKey contains the PEM-encoded public key
	PublicKey []byte

	// PrivateKey contains the PEM-encoded private key
	PrivateKey []byte

	// Signature contains the signature bytes for verification
	Signature []byte

	// Format specifies the key format for PEM encoding.
	// This field affects:
	//   - GenKeyPair(): PEM header format when generating keys
	//   - FormatPublicKey(): PEM header format when formatting public keys
	//   - FormatPrivateKey(): PEM header format when formatting private keys
	// It does NOT affect cryptographic operations.
	Format RsaKeyFormat

	// Padding specifies the padding scheme for RSA cryptographic operations.
	// This field affects encryption, decryption, signing, and verification algorithms.
	//
	// Available padding schemes:
	// - PKCS1v15: Can be used for both encryption and signing operations
	// - OAEP: ONLY for encryption/decryption (error if used for signing/verification)
	// - PSS: ONLY for signing/verification (error if used for encryption/decryption)
	//
	// Note: Padding is independent from Format. You can use any padding with any key format.
	Padding RsaPaddingScheme

	// Hash specifies the hash function used for RSA cryptographic operations.
	// Usage depends on the Padding scheme:
	// - PKCS1v15: Used for hashing message data before signing
	// - OAEP: Used for mask generation in encryption/decryption
	// - PSS: Used for mask generation in signing/verification
	Hash crypto.Hash
}

// NewRsaKeyPair returns a new RsaKeyPair instance with default settings.
// Defaults:
//   - Format: PKCS8 (modern standard for key generation)
//   - Padding: "" (empty, will use PKCS1v15 as fallback in cryptographic operations)
//   - Hash: SHA256
//
// Note: When Padding is not explicitly set, cryptographic operations will use PKCS1v15
// as the default fallback, which works for both encryption and signing.
//
// For explicit security requirements:
//   - For encryption: kp.SetPadding(keypair.OAEP)
//   - For signing: kp.SetPadding(keypair.PSS)
//   - For both: kp.SetPadding(keypair.PKCS1v15)
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
	return UnsupportedKeyFormatError{}
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

// SetPadding sets the padding scheme for RSA cryptographic operations.
//
// Padding schemes:
//   - PKCS1v15: Can be used for both encryption and signing
//   - OAEP: ONLY for encryption (returns error if used for signing)
//   - PSS: ONLY for signing (returns error if used for encryption)
func (k *RsaKeyPair) SetPadding(padding RsaPaddingScheme) {
	k.Padding = padding
}

// SetFormat sets the key format for the RSA key pair.
// This affects:
//   - GenKeyPair(): Determines the PEM header format when generating keys
//   - FormatPublicKey(): Determines the PEM header format when formatting public keys
//   - FormatPrivateKey(): Determines the PEM header format when formatting private keys
func (k *RsaKeyPair) SetFormat(format RsaKeyFormat) {
	k.Format = format
}

// SetHash sets the hash function used for OAEP padding in RSA operations.
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
	return nil, UnsupportedKeyFormatError{}
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
	return nil, UnsupportedKeyFormatError{}
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
		return []byte{}, UnsupportedKeyFormatError{}
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
		return []byte{}, UnsupportedKeyFormatError{}
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
