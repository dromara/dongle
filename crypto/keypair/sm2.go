package keypair

import (
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/pem"
	"fmt"

	"github.com/dromara/dongle/crypto/internal/sm2"
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

// The SM2 DER helpers are routed through variables so that the error branches
// of FormatPublicKey and FormatPrivateKey can be exercised in tests: the
// helpers never fail for a key that has already been parsed.
var (
	bitStringPublicKeyParser  = sm2.ParseBitStringPublicKey
	bitStringPrivateKeyParser = sm2.ParseBitStringPrivateKey
	marshalSm2PublicKey       = sm2.MarshalSPKIPublicKey
	marshalSm2PrivateKey      = sm2.MarshalPKCS8PrivateKey
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
		Mode:     C1C3C2,
		SingMode: ASN1,
		Window:   4,
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

// sm2CoordinateSize is the byte length of an sm2p256v1 coordinate and of
// the private key scalar.
const sm2CoordinateSize = 32

// SetPublicKey sets the public key after formatting it to PEM.
// The input may be PEM, base64, hex or raw key material and is rewritten as a
// canonical "PUBLIC KEY" block. See FormatPublicKey for the accepted inputs.
func (k *Sm2KeyPair) SetPublicKey(publicKey []byte) error {
	key, err := k.FormatPublicKey(publicKey)
	if err == nil {
		k.PublicKey = key
	}
	return err
}

// SetPrivateKey sets the private key after formatting it to PEM.
// The input may be PEM, base64, hex or raw key material and is rewritten as a
// canonical "PRIVATE KEY" block. See FormatPrivateKey for the accepted inputs.
func (k *Sm2KeyPair) SetPrivateKey(privateKey []byte) error {
	key, err := k.FormatPrivateKey(privateKey)
	if err == nil {
		k.PrivateKey = key
	}
	return err
}

// ParsePublicKey parses the public key and returns an *ecdsa.PublicKey on the
// sm2p256v1 curve.
//
// In addition to the PEM produced by GenKeyPair it accepts:
//   - base64 or hex encoded PKIX DER
//   - base64 or hex encoded 65 byte uncompressed point (0x04 || X || Y)
//   - the raw 65 byte uncompressed point
//
// Keys generated for another curve are rejected, a point that belongs to
// P-256 while being wrapped in an SM2 SubjectPublicKeyInfo is reported as
// "point not on curve".
func (k *Sm2KeyPair) ParsePublicKey() (*ecdsa.PublicKey, error) {
	if len(k.PublicKey) == 0 {
		return nil, EmptyPublicKeyError{}
	}
	return selectKey(k.PublicKey, PublicKey, "SM2", parseSm2PublicKey)
}

// parseSm2PublicKey reads an uncompressed point or a PKIX SubjectPublicKeyInfo.
func parseSm2PublicKey(body []byte) (*ecdsa.PublicKey, error) {
	// Uncompressed point: 0x04 || X || Y.
	if len(body) == 1+2*sm2CoordinateSize {
		return bitStringPublicKeyParser(body)
	}

	publicKey, err := sm2.ParseSPKIPublicKey(body)
	if err != nil {
		return nil, fmt.Errorf("%w (want an sm2p256v1 SubjectPublicKeyInfo or a %d byte uncompressed point)", err, 1+2*sm2CoordinateSize)
	}
	return publicKey, nil
}

// ParsePrivateKey parses the private key and returns an *ecdsa.PrivateKey on
// the sm2p256v1 curve.
//
// In addition to the PEM produced by GenKeyPair it accepts:
//   - base64 or hex encoded PKCS#8 DER
//   - base64 or hex encoded 32 byte scalar
//   - the raw 32 byte scalar
func (k *Sm2KeyPair) ParsePrivateKey() (*ecdsa.PrivateKey, error) {
	if len(k.PrivateKey) == 0 {
		return nil, EmptyPrivateKeyError{}
	}
	return selectKey(k.PrivateKey, PrivateKey, "SM2", parseSm2PrivateKey)
}

// parseSm2PrivateKey reads a raw scalar or a PKCS#8 PrivateKeyInfo.
func parseSm2PrivateKey(body []byte) (*ecdsa.PrivateKey, error) {
	// Raw scalar.
	if len(body) == sm2CoordinateSize {
		return bitStringPrivateKeyParser(body)
	}

	privateKey, err := sm2.ParsePKCS8PrivateKey(body)
	if err != nil {
		return nil, fmt.Errorf("%w (want a PKCS#8 sm2p256v1 private key, a SEC1 \"EC PRIVATE KEY\" has to be converted first)", err)
	}
	return privateKey, nil
}

// FormatPublicKey formats the public key into a PEM "PUBLIC KEY" block.
// It accepts the same inputs as ParsePublicKey, so keys copied from other tools
// are normalized instead of being rejected.
func (k *Sm2KeyPair) FormatPublicKey(publicKey []byte) ([]byte, error) {
	if len(publicKey) == 0 {
		return []byte{}, EmptyPublicKeyError{}
	}

	pub, err := selectKey(publicKey, PublicKey, "SM2", parseSm2PublicKey)
	if err != nil {
		return []byte{}, err
	}
	der, err := marshalSm2PublicKey(pub)
	if err != nil {
		return []byte{}, InvalidPublicKeyError{Err: err}
	}
	return pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: der,
	}), nil
}

// FormatPrivateKey formats the private key into a PEM "PRIVATE KEY" block.
// It accepts the same inputs as ParsePrivateKey.
func (k *Sm2KeyPair) FormatPrivateKey(privateKey []byte) ([]byte, error) {
	if len(privateKey) == 0 {
		return []byte{}, EmptyPrivateKeyError{}
	}

	pri, err := selectKey(privateKey, PrivateKey, "SM2", parseSm2PrivateKey)
	if err != nil {
		return []byte{}, err
	}
	der, err := marshalSm2PrivateKey(pri)
	if err != nil {
		return []byte{}, InvalidPrivateKeyError{Err: err}
	}
	return pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: der,
	}), nil
}

// CompressPublicKey returns the base64 body of the public key PEM block.
// The input is decoded with pem.Decode, so optional block headers such as
// "Bag Attributes" are dropped instead of ending up in the body.
func (k *Sm2KeyPair) CompressPublicKey(publicKey []byte) []byte {
	return compressKey(publicKey)
}

// CompressPrivateKey returns the base64 body of the private key PEM block.
// The input is decoded with pem.Decode, so optional block headers such as
// "Bag Attributes" are dropped instead of ending up in the body.
func (k *Sm2KeyPair) CompressPrivateKey(privateKey []byte) []byte {
	return compressKey(privateKey)
}
