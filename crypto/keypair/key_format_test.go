package keypair

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"strings"
	"testing"

	sm2curve "github.com/dromara/dongle/crypto/internal/sm2"
)

// keyMaterialBase64 returns the base64 body of a PEM block.
func keyMaterialBase64(t *testing.T, key []byte) []byte {
	t.Helper()
	block, _ := pem.Decode(key)
	if block == nil {
		t.Fatalf("pem.Decode failed")
	}
	return []byte(base64.StdEncoding.EncodeToString(block.Bytes))
}

// newRsaKey returns a fresh RSA private key for cross algorithm tests.
func newRsaKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	return key
}

// Issue #41: assigning an RSA key to an Ed25519 key pair used to panic with
// "interface conversion: interface {} is *rsa.PrivateKey, not ed25519.PrivateKey".
func TestEd25519_RejectsRSAKeyWithoutPanic(t *testing.T) {
	rsaKey := newRsaKey(t)
	privateKeyDer, err := x509.MarshalPKCS8PrivateKey(rsaKey)
	if err != nil {
		t.Fatalf("MarshalPKCS8PrivateKey: %v", err)
	}

	kp := NewEd25519KeyPair()
	kp.PrivateKey = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateKeyDer})

	pri, err := kp.ParsePrivateKey()
	if err == nil {
		t.Fatalf("ParsePrivateKey expected an error for an RSA key")
	}
	if pri != nil {
		t.Fatalf("ParsePrivateKey returned a key for an RSA key")
	}
	var unsupported UnsupportedKeyFormatError
	if !errors.As(err, &unsupported) {
		t.Fatalf("error type = %T, want UnsupportedKeyFormatError", err)
	}
	if !strings.Contains(err.Error(), "RSA") {
		t.Fatalf("error %q does not name the algorithm of the key", err)
	}
}

// Issue #41: a base64 encoded 32 byte Ed25519 seed has to be accepted, both
// on its own and inside a PEM block that carries the raw seed.
func TestEd25519_AcceptsRawSeed(t *testing.T) {
	seed := make([]byte, ed25519.SeedSize)
	if _, err := rand.Read(seed); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}
	expected := ed25519.NewKeyFromSeed(seed)

	for name, key := range map[string][]byte{
		"base64 seed":       []byte(base64.StdEncoding.EncodeToString(seed)),
		"hex seed":          []byte(strings.ToUpper(encodeHex(seed))),
		"pem with raw seed": pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: seed}),
	} {
		t.Run(name, func(t *testing.T) {
			kp := NewEd25519KeyPair()
			if err := kp.SetPrivateKey(key); err != nil {
				t.Fatalf("SetPrivateKey: %v", err)
			}
			if !bytes.Contains(kp.PrivateKey, []byte("END PRIVATE KEY")) {
				t.Fatalf("SetPrivateKey did not normalize the key to PEM")
			}
			pri, err := kp.ParsePrivateKey()
			if err != nil {
				t.Fatalf("ParsePrivateKey: %v", err)
			}
			if !bytes.Equal(pri, expected) {
				t.Fatalf("parsed private key does not match the seed")
			}
		})
	}
}

// Issue #41: a base64 encoded raw 32 byte public key, and a PEM block that
// carries the raw key instead of PKIX DER, have to be accepted as well.
func TestEd25519_AcceptsRawPublicKey(t *testing.T) {
	seed := make([]byte, ed25519.SeedSize)
	if _, err := rand.Read(seed); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}
	publicKey := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)

	for name, key := range map[string][]byte{
		"base64 key":       []byte(base64.StdEncoding.EncodeToString(publicKey)),
		"pem with raw key": pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicKey}),
		"hex key":          []byte(encodeHex(publicKey)),
		"raw bytes":        publicKey,
		"pem of pkix der":  pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: mustPKIX(t, publicKey)}),
		"base64 of pkix":   []byte(base64.StdEncoding.EncodeToString(mustPKIX(t, publicKey))),
	} {
		t.Run(name, func(t *testing.T) {
			kp := NewEd25519KeyPair()
			if err := kp.SetPublicKey(key); err != nil {
				t.Fatalf("SetPublicKey: %v", err)
			}
			pub, err := kp.ParsePublicKey()
			if err != nil {
				t.Fatalf("ParsePublicKey: %v", err)
			}
			if !bytes.Equal(pub, publicKey) {
				t.Fatalf("parsed public key does not match the seed")
			}
		})
	}
}

// Issue #41: SM2 keys are often copied as a bare point, as a bare scalar or as
// hex, which the key pair used to reject.
func TestSm2_AcceptsRawKeyMaterial(t *testing.T) {
	source := NewSm2KeyPair()
	if err := source.GenKeyPair(); err != nil {
		t.Fatalf("GenKeyPair: %v", err)
	}

	block, _ := pem.Decode(source.PublicKey)
	if block == nil {
		t.Fatalf("pem.Decode public key failed")
	}
	point := block.Bytes[len(block.Bytes)-65:]

	privateKey, err := source.ParsePrivateKey()
	if err != nil {
		t.Fatalf("ParsePrivateKey of source: %v", err)
	}
	scalar := make([]byte, 32)
	privateKey.D.FillBytes(scalar)

	for name, key := range map[string][]byte{
		"base64 point":     []byte(base64.StdEncoding.EncodeToString(point)),
		"hex point":        []byte(encodeHex(point)),
		"raw point":        point,
		"pem of raw point": pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: point}),
	} {
		t.Run(name, func(t *testing.T) {
			kp := NewSm2KeyPair()
			if err := kp.SetPublicKey(key); err != nil {
				t.Fatalf("SetPublicKey: %v", err)
			}
			pub, err := kp.ParsePublicKey()
			if err != nil {
				t.Fatalf("ParsePublicKey: %v", err)
			}
			if pub.X.Cmp(privateKey.X) != 0 || pub.Y.Cmp(privateKey.Y) != 0 {
				t.Fatalf("parsed point does not match the key pair")
			}
		})
	}

	for name, key := range map[string][]byte{
		"base64 scalar": []byte(base64.StdEncoding.EncodeToString(scalar)),
		"hex scalar":    []byte(encodeHex(scalar)),
		"raw scalar":    scalar,
	} {
		t.Run(name, func(t *testing.T) {
			kp := NewSm2KeyPair()
			if err := kp.SetPrivateKey(key); err != nil {
				t.Fatalf("SetPrivateKey: %v", err)
			}
			pri, err := kp.ParsePrivateKey()
			if err != nil {
				t.Fatalf("ParsePrivateKey: %v", err)
			}
			if pri.D.Cmp(privateKey.D) != 0 {
				t.Fatalf("parsed scalar does not match the key pair")
			}
		})
	}
}

// Issue #41: a P-256 point wrapped in an SM2 SubjectPublicKeyInfo has to be
// reported as a point that is not on the curve, not as an ASN.1 failure.
func TestSm2_RejectsPointFromAnotherCurve(t *testing.T) {
	other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	otherPoint := make([]byte, 65)
	otherPoint[0] = 0x04
	other.X.FillBytes(otherPoint[1:33])
	other.Y.FillBytes(otherPoint[33:])

	source := NewSm2KeyPair()
	if err := source.GenKeyPair(); err != nil {
		t.Fatalf("GenKeyPair: %v", err)
	}
	block, _ := pem.Decode(source.PublicKey)
	if block == nil {
		t.Fatalf("pem.Decode failed")
	}

	// Keep the SM2 identifiers and replace the point with a P-256 point.
	der := append([]byte{}, block.Bytes...)
	copy(der[len(der)-65:], otherPoint)

	kp := NewSm2KeyPair()
	kp.PublicKey = pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})

	_, err = kp.ParsePublicKey()
	if err == nil {
		t.Fatalf("ParsePublicKey expected an error for a P-256 point")
	}
	var invalid InvalidPublicKeyError
	if !errors.As(err, &invalid) {
		t.Fatalf("error type = %T, want InvalidPublicKeyError", err)
	}
	if !strings.Contains(err.Error(), "point not on curve") {
		t.Fatalf("error %q does not explain that the point is not on the SM2 curve", err)
	}
}

// Issue #41: PEM text passed to SetPublicKey/SetPrivateKey used to be base64
// decoded byte by byte and rejected.
func TestSetKeys_AcceptPEM(t *testing.T) {
	sm2KeyPair := NewSm2KeyPair()
	if err := sm2KeyPair.GenKeyPair(); err != nil {
		t.Fatalf("GenKeyPair: %v", err)
	}

	kp := NewSm2KeyPair()
	if err := kp.SetPublicKey(sm2KeyPair.PublicKey); err != nil {
		t.Fatalf("SetPublicKey with PEM: %v", err)
	}
	if err := kp.SetPrivateKey(sm2KeyPair.PrivateKey); err != nil {
		t.Fatalf("SetPrivateKey with PEM: %v", err)
	}
	if _, err := kp.ParsePublicKey(); err != nil {
		t.Fatalf("ParsePublicKey: %v", err)
	}
	if _, err := kp.ParsePrivateKey(); err != nil {
		t.Fatalf("ParsePrivateKey: %v", err)
	}
}

// TestRsa_AcceptsBase64AndRawDer covers base64 and raw DER for RSA.
func TestRsa_AcceptsBase64AndRawDer(t *testing.T) {
	rsaKey := newRsaKey(t)
	publicKeyDer, err := x509.MarshalPKIXPublicKey(&rsaKey.PublicKey)
	if err != nil {
		t.Fatalf("MarshalPKIXPublicKey: %v", err)
	}
	privateKeyDer, err := x509.MarshalPKCS8PrivateKey(rsaKey)
	if err != nil {
		t.Fatalf("MarshalPKCS8PrivateKey: %v", err)
	}

	for name, key := range map[string][]byte{
		"raw der":    publicKeyDer,
		"base64 der": []byte(base64.StdEncoding.EncodeToString(publicKeyDer)),
		"pem":        pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicKeyDer}),
	} {
		t.Run("public/"+name, func(t *testing.T) {
			kp := NewRsaKeyPair()
			kp.PublicKey = key
			pub, err := kp.ParsePublicKey()
			if err != nil {
				t.Fatalf("ParsePublicKey: %v", err)
			}
			if pub.N.Cmp(rsaKey.N) != 0 {
				t.Fatalf("parsed modulus does not match")
			}
		})
	}

	for name, key := range map[string][]byte{
		"raw der":    privateKeyDer,
		"base64 der": []byte(base64.StdEncoding.EncodeToString(privateKeyDer)),
		"pem":        pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateKeyDer}),
	} {
		t.Run("private/"+name, func(t *testing.T) {
			kp := NewRsaKeyPair()
			kp.PrivateKey = key
			pri, err := kp.ParsePrivateKey()
			if err != nil {
				t.Fatalf("ParsePrivateKey: %v", err)
			}
			if pri.D.Cmp(rsaKey.D) != 0 {
				t.Fatalf("parsed private exponent does not match")
			}
		})
	}
}

// TestParseKeys_RejectWrongDirection makes sure a private key PEM handed to
// ParsePublicKey is reported as an unsupported format instead of a nil error.
func TestParseKeys_RejectWrongDirection(t *testing.T) {
	kp := NewEd25519KeyPair()
	if err := kp.GenKeyPair(); err != nil {
		t.Fatalf("GenKeyPair: %v", err)
	}

	wrong := NewEd25519KeyPair()
	wrong.PublicKey = kp.PrivateKey
	_, err := wrong.ParsePublicKey()
	if err == nil {
		t.Fatalf("ParsePublicKey expected an error for a private key block")
	}
	var unsupported UnsupportedKeyFormatError
	if !errors.As(err, &unsupported) {
		t.Fatalf("error type = %T, want UnsupportedKeyFormatError", err)
	}
	if !strings.Contains(err.Error(), "expected a public key") {
		t.Fatalf("error %q does not explain the direction mismatch", err)
	}
}

// TestParsePrivateKey_RejectsEncryptedKey covers the encrypted PEM header.
func TestParsePrivateKey_RejectsEncryptedKey(t *testing.T) {
	kp := NewEd25519KeyPair()
	kp.PrivateKey = pem.EncodeToMemory(&pem.Block{Type: "ENCRYPTED PRIVATE KEY", Bytes: []byte{1, 2, 3}})

	_, err := kp.ParsePrivateKey()
	if err == nil {
		t.Fatalf("ParsePrivateKey expected an error for an encrypted key")
	}
	var unsupported UnsupportedKeyFormatError
	if !errors.As(err, &unsupported) {
		t.Fatalf("error type = %T, want UnsupportedKeyFormatError", err)
	}
	if !strings.Contains(err.Error(), "decrypt") {
		t.Fatalf("error %q does not explain how to fix the key", err)
	}
}

// TestCompressKey_WithBagAttributes makes sure optional PEM headers are dropped
// with the block instead of ending up in the compressed body.
func TestCompressKey_WithBagAttributes(t *testing.T) {
	keyDer, err := x509.MarshalPKIXPublicKey(&newRsaKey(t).PublicKey)
	if err != nil {
		t.Fatalf("MarshalPKIXPublicKey: %v", err)
	}
	keyPem := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: keyDer})
	withAttributes := append([]byte("Bag Attributes\n    friendlyName: test\n    localKeyID: 01 02 03\n"), keyPem...)

	kp := NewRsaKeyPair()
	compressed := kp.CompressPublicKey(withAttributes)
	if bytes.Contains(compressed, []byte("Bag Attributes")) {
		t.Fatalf("CompressPublicKey kept the PEM headers")
	}
	if !bytes.Equal(compressed, keyMaterialBase64(t, keyPem)) {
		t.Fatalf("CompressPublicKey returned %q, want the base64 body", compressed)
	}
}

// TestSm2_RejectsOutOfRangeScalar covers a zero scalar and a scalar equal to
// the group order. Both used to be accepted and produced a private key without
// a meaningful public point.
func TestSm2_RejectsOutOfRangeScalar(t *testing.T) {
	order := make([]byte, 32)
	sm2curve.NewCurve().Params().N.FillBytes(order)

	for name, scalar := range map[string][]byte{
		"zero":  make([]byte, 32),
		"order": order,
	} {
		t.Run(name, func(t *testing.T) {
			kp := NewSm2KeyPair()
			kp.PrivateKey = scalar

			pri, err := kp.ParsePrivateKey()
			if err == nil {
				t.Fatalf("ParsePrivateKey expected an error for the %s scalar", name)
			}
			if pri != nil {
				t.Fatalf("ParsePrivateKey returned a key for the %s scalar", name)
			}
			var invalid InvalidPrivateKeyError
			if !errors.As(err, &invalid) {
				t.Fatalf("error type = %T, want InvalidPrivateKeyError", err)
			}
		})
	}
}

// mustPKIX marshals an Ed25519 public key into PKIX DER.
func mustPKIX(t *testing.T, publicKey ed25519.PublicKey) []byte {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		t.Fatalf("MarshalPKIXPublicKey: %v", err)
	}
	return der
}

// encodeHex formats bytes as lowercase hexadecimal.
func encodeHex(data []byte) string {
	const digits = "0123456789abcdef"
	out := make([]byte, 0, len(data)*2)
	for _, b := range data {
		out = append(out, digits[b>>4], digits[b&0x0f])
	}
	return string(out)
}
