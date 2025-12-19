package keypair

import (
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/pem"
	"strings"

	"github.com/dromara/dongle/coding"
	"github.com/dromara/dongle/crypto/internal/sm2"
	"github.com/dromara/dongle/internal/utils"
)

// Sm2CipherMode specifies the concatenation mode of SM2 ciphertext
// components. It controls how the library assembles (encrypt) and
// interprets (decrypt) the C1, C2, C3 parts.
//
// C1: EC point (x1||y1) in uncompressed form; C2: XORed plaintext;
// C3: SM3 digest over x2 || M || y2.
//
// NOTE: For performance and boundary checks, would it be better to set the type to uint8?
type Sm2CipherMode string

// Supported SM2 ciphertext orders.
const (
	// C1C2C3 means ciphertext bytes are C1 || C2 || C3 in bytes.
	C1C2C3 Sm2CipherMode = "c1c2c3"
	// C1C3C2 means ciphertext bytes are C1 || C3 || C2 in bytes.
	C1C3C2 Sm2CipherMode = "c1c3c2"
	// ASN1C1C2C3 means ciphertext bytes are C1 || C2 || C3 in ASN1.
	ASN1C1C2C3 Sm2CipherMode = "asn1_c1c2c3"
	// ASN1C1C3C2 means ciphertext bytes are C1 || C3 || C2 in ASN1.
	ASN1C1C3C2 Sm2CipherMode = "asn1_c1c3c2"
)

type Sm2SingMode uint8

const (
	// Digital signature in ASN1 format
	ASN1 Sm2SingMode = iota
	// Digital signature in bytes format
	Bytes
)

var (
	bitStringPublicKeyParser  = sm2.ParseBitStringPublicKey
	bitStringPrivateKeyParser = sm2.ParseBitStringPrivateKey
)

// Sm2KeyPair represents an SM2 key pair with public and private keys.
// Keys are handled in PKCS8 (for private) and PKIX (for public) PEM formats.
type Sm2KeyPair struct {
	// PublicKey contains the PEM-encoded public key
	PublicKey []byte

	// PrivateKey contains the PEM-encoded private key
	PrivateKey []byte

	// Order specifies the mode of SM2 ciphertext components.
	// It controls how Encrypt assembles and Decrypt interprets ciphertext.
	// NOTE: Perhaps renaming this to CipherMode would be more appropriate?
	Mode Sm2CipherMode

	// SingMode controls the logic of signing and verification.
	// There are two common ways to handle SM2 signature data:
	// one is to encode R and S in ASN1 format, and the other is to concatenate R and S.
	//
	// Default is ASN1 format.
	SingMode Sm2SingMode

	// Window controls internal SM2 fixed-base/wNAF window size (2..6).
	// 4 means use library default.
	Window int

	// UID is the user identifier for SM2 signature operations.
	// If empty, the default UID "1234567812345678" will be used (per GM/T 0009-2012).
	UID []byte
}

// NewSm2KeyPair returns a new Sm2KeyPair with defaults
// (Order=C1C3C2, Window=4).
func NewSm2KeyPair() *Sm2KeyPair {
	return &Sm2KeyPair{
		Mode:   C1C3C2,
		Window: 4,
	}
}

// GenKeyPair generates a new SM2 key pair and fills PublicKey/PrivateKey.
// Private key is PKCS#8 (PEM "PRIVATE KEY"), public key is SPKI/PKIX (PEM "PUBLIC KEY").
func (k *Sm2KeyPair) GenKeyPair() error {
	c := sm2.NewCurve()

	// Generate unbiased scalar d in range [1, n-1]
	d, err := sm2.RandScalar(c, rand.Reader)
	if err != nil {
		return err
	}

	x, y := c.ScalarBaseMult(d.Bytes())
	privateKey := &ecdsa.PrivateKey{PublicKey: ecdsa.PublicKey{Curve: c, X: x, Y: y}, D: d}

	// Marshal PKCS8 private key
	privateKeyDer, _ := sm2.MarshalPKCS8PrivateKey(privateKey)
	k.PrivateKey = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateKeyDer})

	// Marshal SPKI public key
	publicKeyDer, _ := sm2.MarshalSPKIPublicKey(&privateKey.PublicKey)
	k.PublicKey = pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicKeyDer})
	return nil
}

// SetOrder sets ciphertext order to C1C3C2 or C1C2C3.
// Deprecated: `SetOrder` will be removed in the future, use `SetMode` instead.
func (k *Sm2KeyPair) SetOrder(order Sm2CipherMode) {
	k.SetMode(order)
}

// SetMode sets ciphertext mode to C1C3C2 or C1C2C3.
// It affects how Encrypt assembles and Decrypt interprets ciphertext.
func (k *Sm2KeyPair) SetMode(mode Sm2CipherMode) {
	k.Mode = mode
}

// SetSingMode sets the mode for SM2 Sign and Verify
func (k *Sm2KeyPair) SetSingMode(mode Sm2SingMode) {
	k.SingMode = mode
}

// SetWindow sets scalar-multiplication window (2..6).
// Values outside the range are clamped.
func (k *Sm2KeyPair) SetWindow(window int) {
	if window < 2 {
		window = 2
	}
	if window > 6 {
		window = 6
	}
	k.Window = window
}

// SetUID sets the user identifier for SM2 signature operations.
// If uid is nil or empty, the default UID "1234567812345678" will be used.
func (k *Sm2KeyPair) SetUID(uid []byte) {
	k.UID = uid
}

// SetPublicKey sets the public key after formatting to PEM.
// Accepts base64-encoded DER of SubjectPublicKeyInfo.
func (k *Sm2KeyPair) SetPublicKey(publicKey []byte) error {
	key, err := k.FormatPublicKey(publicKey)
	if err == nil {
		k.PublicKey = key
	}
	return err
}

// SetPrivateKey sets the private key after formatting to PEM.
// Accepts base64-encoded DER of PKCS#8 PrivateKeyInfo.
func (k *Sm2KeyPair) SetPrivateKey(privateKey []byte) error {
	key, err := k.FormatPrivateKey(privateKey)
	if err == nil {
		k.PrivateKey = key
	}
	return err
}

// ParsePublicKey parses the PEM-encoded public key and returns *sm2.PublicKey.
func (k *Sm2KeyPair) ParsePublicKey() (*ecdsa.PublicKey, error) {
	publicKey := k.PublicKey
	if len(publicKey) == 0 {
		return nil, EmptyPublicKeyError{}
	}
	if len(publicKey) == 65 {
		pub, err := bitStringPublicKeyParser(publicKey)
		if err != nil {
			return nil, InvalidPublicKeyError{Err: err}
		}
		return pub, nil
	}
	block, _ := pem.Decode(publicKey)
	if block == nil || block.Type != "PUBLIC KEY" {
		return nil, InvalidPublicKeyError{}
	}
	pub, err := sm2.ParseSPKIPublicKey(block.Bytes)
	if err != nil {
		return nil, InvalidPublicKeyError{Err: err}
	}
	return pub, nil
}

// ParsePrivateKey parses the PEM-encoded private key and returns *sm2.PrivateKey.
func (k *Sm2KeyPair) ParsePrivateKey() (*ecdsa.PrivateKey, error) {
	privateKey := k.PrivateKey
	if len(privateKey) == 0 {
		return nil, EmptyPrivateKeyError{}
	}
	if len(privateKey) == 32 {
		pri, err := bitStringPrivateKeyParser(privateKey)
		if err != nil {
			return nil, InvalidPrivateKeyError{Err: err}
		}
		return pri, nil
	}
	block, _ := pem.Decode(privateKey)
	if block == nil || block.Type != "PRIVATE KEY" {
		return nil, InvalidPrivateKeyError{}
	}
	pri, err := sm2.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, InvalidPrivateKeyError{Err: err}
	}
	return pri, nil
}

// FormatPublicKey formats base64-encoded der public key into the specified PEM format.
func (k *Sm2KeyPair) FormatPublicKey(publicKey []byte) ([]byte, error) {
	if len(publicKey) == 0 {
		return []byte{}, EmptyPublicKeyError{}
	}
	decoder := coding.NewDecoder().FromBytes(publicKey).ByBase64()
	if decoder.Error != nil {
		return []byte{}, InvalidPublicKeyError{Err: decoder.Error}
	}
	return pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: decoder.ToBytes(),
	}), nil
}

// FormatPrivateKey formats base64-encoded der private key into the specified PEM format.
func (k *Sm2KeyPair) FormatPrivateKey(privateKey []byte) ([]byte, error) {
	if len(privateKey) == 0 {
		return []byte{}, EmptyPrivateKeyError{}
	}
	decoder := coding.NewDecoder().FromBytes(privateKey).ByBase64()
	if decoder.Error != nil {
		return []byte{}, InvalidPrivateKeyError{Err: decoder.Error}
	}
	return pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: decoder.ToBytes(),
	}), nil
}

// CompressPublicKey strips headers/footers and whitespace from the PEM public key.
func (k *Sm2KeyPair) CompressPublicKey(publicKey []byte) []byte {
	keyStr := utils.Bytes2String(publicKey)
	keyStr = strings.ReplaceAll(keyStr, "-----BEGIN PUBLIC KEY-----", "")
	keyStr = strings.ReplaceAll(keyStr, "-----END PUBLIC KEY-----", "")
	keyStr = strings.ReplaceAll(keyStr, "\n", "")
	keyStr = strings.ReplaceAll(keyStr, "\r", "")
	keyStr = strings.ReplaceAll(keyStr, " ", "")
	keyStr = strings.ReplaceAll(keyStr, "\t", "")
	keyStr = strings.TrimSpace(keyStr)
	return utils.String2Bytes(keyStr)
}

// CompressPrivateKey strips headers/footers and whitespace from the PEM private key.
func (k *Sm2KeyPair) CompressPrivateKey(privateKey []byte) []byte {
	keyStr := utils.Bytes2String(privateKey)
	keyStr = strings.ReplaceAll(keyStr, "-----BEGIN PRIVATE KEY-----", "")
	keyStr = strings.ReplaceAll(keyStr, "-----END PRIVATE KEY-----", "")
	keyStr = strings.ReplaceAll(keyStr, "-----BEGIN ENCRYPTED PRIVATE KEY-----", "")
	keyStr = strings.ReplaceAll(keyStr, "-----END ENCRYPTED PRIVATE KEY-----", "")
	keyStr = strings.ReplaceAll(keyStr, "\n", "")
	keyStr = strings.ReplaceAll(keyStr, "\r", "")
	keyStr = strings.ReplaceAll(keyStr, " ", "")
	keyStr = strings.ReplaceAll(keyStr, "\t", "")
	keyStr = strings.TrimSpace(keyStr)
	return utils.String2Bytes(keyStr)
}
