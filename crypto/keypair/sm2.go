package keypair

import (
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/pem"
	"io"
	"io/fs"
	"strings"

	"github.com/dromara/dongle/coding"
	"github.com/dromara/dongle/crypto/internal/sm2curve"
	"github.com/dromara/dongle/utils"
)

// Sm2KeyPair represents an SM2 key pair with public and private keys.
// Keys are handled in PKCS8 (for private) and PKIX (for public) PEM formats.
type Sm2KeyPair struct {
	// PublicKey contains the PEM-encoded public key
	PublicKey []byte

	// PrivateKey contains the PEM-encoded private key
	PrivateKey []byte

	Order CipherOrder
	// Window controls internal SM2 fixed-base/wNAF window size (2..6).
	// 4 means use library default.
	Window int
}

// NewSm2KeyPair returns a new Sm2KeyPair with defaults
// (Order=C1C3C2, Window=4).
func NewSm2KeyPair() *Sm2KeyPair {
	return &Sm2KeyPair{
		Order:  C1C3C2,
		Window: 4,
	}
}

// GenKeyPair generates a new SM2 key pair and fills PublicKey/PrivateKey.
// Private key is PKCS#8 (PEM "PRIVATE KEY"), public key is SPKI/PKIX (PEM "PUBLIC KEY").
func (k *Sm2KeyPair) GenKeyPair() error {
	c := sm2curve.New()

	// Generate unbiased scalar d in range [1, n-1]
	d, err := sm2curve.RandScalar(c, rand.Reader)
	if err != nil {
		return err
	}

	x, y := c.ScalarBaseMult(d.Bytes())
	privateKey := &ecdsa.PrivateKey{PublicKey: ecdsa.PublicKey{Curve: c, X: x, Y: y}, D: d}

	// Marshal PKCS8 private key
	privateKeyDer, _ := sm2curve.MarshalPKCS8PrivateKey(privateKey)
	k.PrivateKey = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateKeyDer})

	// Marshal SPKI public key
	publicKeyDer, _ := sm2curve.MarshalSPKIPublicKey(&privateKey.PublicKey)
	k.PublicKey = pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicKeyDer})
	return nil
}

// SetOrder sets ciphertext component order to C1C3C2 or C1C2C3.
// It affects how Encrypt assembles and Decrypt interprets ciphertext.
func (k *Sm2KeyPair) SetOrder(order CipherOrder) {
	k.Order = order
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

// LoadPublicKey reads a PEM-encoded public key from a file.
func (k *Sm2KeyPair) LoadPublicKey(f fs.File) error {
	key, err := io.ReadAll(f)
	if err == nil {
		k.PublicKey = key
	}
	return err
}

// LoadPrivateKey reads a PEM-encoded private key from a file.
func (k *Sm2KeyPair) LoadPrivateKey(f fs.File) error {
	key, err := io.ReadAll(f)
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
	block, _ := pem.Decode(publicKey)
	if block == nil || block.Type != "PUBLIC KEY" {
		return nil, InvalidPublicKeyError{}
	}
	pub, err := sm2curve.ParseSPKIPublicKey(block.Bytes)
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
	block, _ := pem.Decode(privateKey)
	if block == nil || block.Type != "PRIVATE KEY" {
		return nil, InvalidPrivateKeyError{}
	}
	pri, err := sm2curve.ParsePKCS8PrivateKey(block.Bytes)
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
