// Package keypair manages cryptographic key pairs (RSA, SM2):
// generate, parse and format keys. SM2 uses PKCS#8 (private), PKIX/SPKI (public),
// and CipherOrder to control C1/C2/C3 ciphertext order.
package keypair

// KeyFormat represents the PEM encoding format for RSA keys.
// This ONLY affects key generation (GenKeyPair) and determines the PEM header.
//
// IMPORTANT: KeyFormat does NOT affect encryption/decryption/signing operations.
// For cryptographic operations, use PaddingScheme instead.
//
// Key parsing (ParsePublicKey/ParsePrivateKey) automatically detects the format
// from PEM headers, so this field is not used during parsing.
type KeyFormat string

// Key format constants for RSA key pairs.
const (
	// PKCS1 generates keys with RSA-specific PEM headers.
	// - Private key: "-----BEGIN RSA PRIVATE KEY-----"
	// - Public key: "-----BEGIN RSA PUBLIC KEY-----"
	// - Usage: Legacy compatibility, OpenSSL traditional format
	PKCS1 KeyFormat = "pkcs1"

	// PKCS8 generates keys with generic PEM headers (recommended).
	// - Private key: "-----BEGIN PRIVATE KEY-----"
	// - Public key: "-----BEGIN PUBLIC KEY-----"
	// - Usage: Modern standard, works with multiple key algorithms
	PKCS8 KeyFormat = "pkcs8"
)

// PaddingScheme represents the padding scheme for RSA cryptographic operations.
//
// Different padding schemes are used for different operations:
// - PKCS1v15: Can be used for both encryption and signing
// - OAEP: Only for encryption (more secure than PKCS1v15)
// - PSS: Only for signing (more secure than PKCS1v15)
type PaddingScheme string

const (
	// PKCS1v15 uses PKCS#1 v1.5 padding for RSA operations.
	// - For encryption/decryption: rsa.EncryptPKCS1v15 / rsa.DecryptPKCS1v15
	// - For signing/verification: rsa.SignPKCS1v15 / rsa.VerifyPKCS1v15
	// - Compatibility: Works with JSEncrypt, PHP openssl_* defaults
	// - Security: Adequate for most applications, widely supported
	// - Usage: Can be used for both encryption and signing operations
	PKCS1v15 PaddingScheme = "pkcs1v15"

	// OAEP uses Optimal Asymmetric Encryption Padding (more secure).
	// - For encryption/decryption: rsa.EncryptOAEP / rsa.DecryptOAEP
	// - Compatibility: Modern standard, may not work with older libraries
	// - Security: Recommended for encryption in new applications
	// - Usage: ONLY for encryption/decryption operations
	//
	// Note: Attempting to use OAEP for signing/verification will return an error.
	// For signing, use PKCS1v15 or PSS instead.
	OAEP PaddingScheme = "oaep"

	// PSS uses Probabilistic Signature Scheme (more secure for signing).
	// - For signing/verification: rsa.SignPSS / rsa.VerifyPSS
	// - Compatibility: Modern standard, may not work with older libraries
	// - Security: Recommended for signing in new applications
	// - Usage: ONLY for signing/verification operations
	//
	// Note: Attempting to use PSS for encryption/decryption will return an error.
	// For encryption, use PKCS1v15 or OAEP instead.
	PSS PaddingScheme = "pss"
)

// CipherOrder specifies the concatenation order of SM2 ciphertext
// components. It controls how the library assembles (encrypt) and
// interprets (decrypt) the C1, C2, C3 parts.
//
// C1: EC point (x1||y1) in uncompressed form; C2: XORed plaintext;
// C3: SM3 digest over x2 || M || y2.
type CipherOrder string

// Supported SM2 ciphertext orders.
const (
	// C1C2C3 means ciphertext bytes are C1 || C2 || C3.
	C1C2C3 CipherOrder = "c1c2c3"
	// C1C3C2 means ciphertext bytes are C1 || C3 || C2.
	C1C3C2 CipherOrder = "c1c3c2"
)
