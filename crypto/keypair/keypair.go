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
