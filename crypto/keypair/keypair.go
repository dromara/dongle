// Package keypair provides cryptographic key pair management functionality.
// It supports key generation, formatting, parsing, and manipulation for various
// cryptographic algorithms with different key formats.
package keypair

import (
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
