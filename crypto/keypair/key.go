package keypair

import (
	"crypto/dsa"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
)

// keyMaterial is one possible interpretation of user supplied key material.
type keyMaterial struct {
	// blockType is the PEM block type, it is empty when the input was not PEM.
	blockType string
	// bytes holds the body of a PEM block, the decoded base64/hex bytes, or the
	// untouched input when none of the encodings matched.
	bytes []byte
}

// keyMaterials lists the possible interpretations of data.
//
// Keys reach dongle from many places (openssl, online generators, other SDKs),
// so PEM text, base64, hex and raw DER/point bytes are all accepted. Only the
// algorithm specific parser knows which interpretation is right, therefore all
// candidates are returned and tried in order.
func keyMaterials(data []byte) []keyMaterial {
	if len(data) == 0 {
		return nil
	}

	if block, _ := pem.Decode(data); block != nil {
		return []keyMaterial{{blockType: block.Type, bytes: block.Bytes}}
	}

	text := strings.Join(strings.Fields(string(data)), "")
	materials := make([]keyMaterial, 0, 3)
	if decoded, ok := decodeBase64(text); ok {
		materials = append(materials, keyMaterial{bytes: decoded})
	}
	if decoded, ok := decodeHex(text); ok {
		materials = append(materials, keyMaterial{bytes: decoded})
	}
	return append(materials, keyMaterial{bytes: data})
}

// decodeBase64 decodes text with the common base64 alphabets, with or without
// padding, so that keys copied from tool output are accepted as is.
func decodeBase64(text string) ([]byte, bool) {
	if text == "" {
		return nil, false
	}
	encodings := [...]*base64.Encoding{
		base64.StdEncoding,
		base64.RawStdEncoding,
		base64.URLEncoding,
		base64.RawURLEncoding,
	}
	for _, encoding := range encodings {
		if decoded, err := encoding.DecodeString(text); err == nil && len(decoded) > 0 {
			return decoded, true
		}
	}
	return nil, false
}

// decodeHex decodes a hexadecimal string, as printed by several SM2 tools.
func decodeHex(text string) ([]byte, bool) {
	if len(text) == 0 || len(text)%2 != 0 {
		return nil, false
	}
	decoded, err := hex.DecodeString(text)
	if err != nil || len(decoded) == 0 {
		return nil, false
	}
	return decoded, true
}

// Key marshalling goes through variables so that the error branches can be
// exercised in tests: crypto/x509 never fails for a key that has already been
// parsed into its typed form.
var (
	marshalPKIXPublicKey   = x509.MarshalPKIXPublicKey
	marshalPKCS8PrivateKey = x509.MarshalPKCS8PrivateKey
)

// keyBlockAlgorithms maps the PEM block types that carry a single key to the
// algorithm they belong to. An empty algorithm means the block type is generic
// ("PUBLIC KEY" / "PRIVATE KEY") and can hold any algorithm.
var keyBlockAlgorithms = map[string]string{
	"PUBLIC KEY":          "",
	"PRIVATE KEY":         "",
	"RSA PUBLIC KEY":      "RSA",
	"RSA PRIVATE KEY":     "RSA",
	"EC PUBLIC KEY":       "EC",
	"EC PRIVATE KEY":      "EC",
	"ED25519 PUBLIC KEY":  "Ed25519",
	"ED25519 PRIVATE KEY": "Ed25519",
}

// checkKeyBlock rejects PEM blocks that cannot hold a key of the wanted type
// and algorithm before any algorithm specific parsing happens.
func checkKeyBlock(blockType string, typ KeyType, algorithm string) error {
	if blockType == "" {
		return nil
	}

	blockAlgorithm, ok := keyBlockAlgorithms[blockType]
	if !ok {
		if blockType == "ENCRYPTED PRIVATE KEY" {
			return UnsupportedKeyFormatError{
				Algorithm: algorithm,
				Detail:    "encrypted private keys are not supported, decrypt the key first",
			}
		}
		return UnsupportedKeyFormatError{
			Algorithm: algorithm,
			Detail:    fmt.Sprintf("PEM block %q does not hold a key", blockType),
		}
	}

	if typ == PublicKey && strings.HasSuffix(blockType, "PRIVATE KEY") {
		return UnsupportedKeyFormatError{
			Algorithm: algorithm,
			Detail:    fmt.Sprintf("expected a public key, got the PEM block %q", blockType),
		}
	}
	if typ == PrivateKey && strings.HasSuffix(blockType, "PUBLIC KEY") {
		return UnsupportedKeyFormatError{
			Algorithm: algorithm,
			Detail:    fmt.Sprintf("expected a private key, got the PEM block %q", blockType),
		}
	}
	if blockAlgorithm != "" && blockAlgorithm != algorithm {
		// SM2 keys are EC keys, a block labelled "EC" may hold them, the
		// parser checks the curve instead.
		if blockAlgorithm != "EC" || algorithm != "SM2" {
			return UnsupportedKeyFormatError{
				Algorithm: algorithm,
				Detail:    fmt.Sprintf("the key is an %s key, not an %s key", blockAlgorithm, algorithm),
			}
		}
	}
	return nil
}

// selectKey tries every interpretation of material with parse and returns the
// first key that could be read. Unsupported formats are reported as they are,
// every other failure is wrapped into the error type matching typ.
func selectKey[T any](material []byte, typ KeyType, algorithm string, parse func([]byte) (T, error)) (T, error) {
	var zero T
	var firstErr error

	for _, candidate := range keyMaterials(material) {
		if err := checkKeyBlock(candidate.blockType, typ, algorithm); err != nil {
			return zero, err
		}
		key, err := parse(candidate.bytes)
		if err == nil {
			return key, nil
		}
		if firstErr == nil {
			firstErr = err
		}
	}
	return zero, keyError(firstErr, typ)
}

// keyError converts a parser error into the error type matching the key type.
func keyError(err error, typ KeyType) error {
	if err == nil {
		err = errors.New("unrecognized key material")
	}
	var unsupported UnsupportedKeyFormatError
	if errors.As(err, &unsupported) {
		return unsupported
	}
	if typ == PublicKey {
		return InvalidPublicKeyError{Err: err}
	}
	return InvalidPrivateKeyError{Err: err}
}

// describeKey names a parsed key for error messages, for example "an RSA key".
func describeKey(key any) string {
	switch key.(type) {
	case *rsa.PrivateKey, *rsa.PublicKey:
		return "an RSA key"
	case *ecdsa.PrivateKey, *ecdsa.PublicKey:
		return "an ECDSA key"
	case *dsa.PrivateKey, *dsa.PublicKey:
		return "a DSA key"
	case ed25519.PrivateKey, ed25519.PublicKey:
		return "an Ed25519 key"
	}
	return fmt.Sprintf("a key of type %T", key)
}

// compressKey returns the base64 body of the first PEM block, or the input with
// its armor lines removed when it is not a complete PEM block.
func compressKey(key []byte) []byte {
	if block, _ := pem.Decode(key); block != nil {
		return []byte(base64.StdEncoding.EncodeToString(block.Bytes))
	}

	var body []string
	for _, line := range strings.Split(string(key), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "-----") {
			continue
		}
		body = append(body, line)
	}
	return []byte(strings.Join(body, ""))
}
