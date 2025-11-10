// Package keypair manages cryptographic key pairs (RSA, SM2):
// generate, parse and format keys. SM2 uses PKCS#8 (private), PKIX/SPKI (public),
// and CipherOrder to control C1/C2/C3 ciphertext order.
package keypair

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
