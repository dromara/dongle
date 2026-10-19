package keypair

import (
	"bytes"
	"crypto/dsa"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"strings"
	"testing"
)

// TestDescribeKey covers the naming used in "the parsed key is %s" messages.
func TestDescribeKey(t *testing.T) {
	for name, tc := range map[string]struct {
		key  any
		want string
	}{
		"rsa private":  {&rsa.PrivateKey{}, "an RSA key"},
		"rsa public":   {&rsa.PublicKey{}, "an RSA key"},
		"ecdsa public": {&ecdsa.PublicKey{}, "an ECDSA key"},
		"dsa private":  {&dsa.PrivateKey{}, "a DSA key"},
		"ed25519":      {ed25519.PublicKey{}, "an Ed25519 key"},
		"unknown":      {42, "a key of type int"},
	} {
		if got := describeKey(tc.key); got != tc.want {
			t.Errorf("%s: describeKey = %q, want %q", name, got, tc.want)
		}
	}
}

// TestKeyError_Classification covers the error types returned by selectKey.
func TestKeyError_Classification(t *testing.T) {
	err := keyError(nil, PublicKey)
	var public InvalidPublicKeyError
	if !errors.As(err, &public) {
		t.Fatalf("nil error for a public key: got %T, want InvalidPublicKeyError", err)
	}
	if !strings.Contains(err.Error(), "unrecognized key material") {
		t.Fatalf("error %q does not explain the failure", err)
	}

	err = keyError(nil, PrivateKey)
	var private InvalidPrivateKeyError
	if !errors.As(err, &private) {
		t.Fatalf("nil error for a private key: got %T, want InvalidPrivateKeyError", err)
	}

	unsupported := UnsupportedKeyFormatError{Algorithm: "Ed25519", Detail: "no"}
	err = keyError(unsupported, PublicKey)
	var got UnsupportedKeyFormatError
	if !errors.As(err, &got) {
		t.Fatalf("unsupported format: got %T, want UnsupportedKeyFormatError", err)
	}
	if got.Algorithm != "Ed25519" || got.Detail != "no" {
		t.Fatalf("unsupported format error was rewritten: %+v", got)
	}
}

// TestKeyMaterials_Interpretations covers the candidate list built from an input.
func TestKeyMaterials_Interpretations(t *testing.T) {
	if materials := keyMaterials(nil); materials != nil {
		t.Fatalf("empty input returned %d candidates, want none", len(materials))
	}

	raw := []byte("not base64 !!")
	materials := keyMaterials(raw)
	if len(materials) != 1 || string(materials[0].bytes) != string(raw) || materials[0].blockType != "" {
		t.Fatalf("undecodable input returned %+v, want a single raw candidate", materials)
	}

	if _, ok := decodeBase64(""); ok {
		t.Fatal("decodeBase64 accepted an empty string")
	}
	if _, ok := decodeBase64("!!!"); ok {
		t.Fatal("decodeBase64 accepted invalid input")
	}
	if _, ok := decodeHex("abc"); ok {
		t.Fatal("decodeHex accepted an odd length string")
	}
}

// TestErrorMessages covers the remaining error string variants.
func TestErrorMessages(t *testing.T) {
	if got := (InvalidPublicKeyError{}).Error(); got != "invalid public key" {
		t.Fatalf("InvalidPublicKeyError{} = %q", got)
	}
	if got := (InvalidPrivateKeyError{}).Error(); got != "invalid private key" {
		t.Fatalf("InvalidPrivateKeyError{} = %q", got)
	}

	for name, tc := range map[string]struct {
		err  UnsupportedKeyFormatError
		want string
	}{
		"algorithm and detail": {
			UnsupportedKeyFormatError{Algorithm: "Ed25519", Detail: "no"},
			"unsupported Ed25519 key format: no",
		},
		"detail only": {
			UnsupportedKeyFormatError{Detail: "no"},
			"unsupported key format: no",
		},
		"algorithm only": {
			UnsupportedKeyFormatError{Algorithm: "RSA"},
			"unsupported RSA key format",
		},
	} {
		if got := tc.err.Error(); got != tc.want {
			t.Errorf("%s: Error() = %q, want %q", name, got, tc.want)
		}
	}
}

// mustECDSAPKIX returns a P-256 public key marshalled as PKIX DER.
func mustECDSAPKIX(t *testing.T) ([]byte, *ecdsa.PublicKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatalf("MarshalPKIXPublicKey: %v", err)
	}
	return der, &key.PublicKey
}

// TestParsePublicKey_RejectsOtherKeyType covers keys that parse fine but are
// not the requested type, reported through describeKey instead of a panic.
func TestParsePublicKey_RejectsOtherKeyType(t *testing.T) {
	der, _ := mustECDSAPKIX(t)

	kp := NewEd25519KeyPair()
	kp.PublicKey = pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	_, err := kp.ParsePublicKey()
	var unsupported UnsupportedKeyFormatError
	if !errors.As(err, &unsupported) {
		t.Fatalf("Ed25519 with an ECDSA key: got %T, want UnsupportedKeyFormatError", err)
	}
	if !strings.Contains(err.Error(), "an ECDSA key, not an Ed25519 key") {
		t.Fatalf("Ed25519 error %q does not name both algorithms", err)
	}

	kp2 := NewRsaKeyPair()
	kp2.PublicKey = der
	_, err = kp2.ParsePublicKey()
	if !errors.As(err, &unsupported) {
		t.Fatalf("RSA with an ECDSA key: got %T, want UnsupportedKeyFormatError", err)
	}
	if !strings.Contains(err.Error(), "an ECDSA key, not an RSA key") {
		t.Fatalf("RSA error %q does not name both algorithms", err)
	}
}

// TestParsePrivateKey_RejectsOtherKeyType covers a private key of another
// algorithm inside a generic PKCS#8 block.
func TestParsePrivateKey_RejectsOtherKeyType(t *testing.T) {
	_, ed25519Private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(ed25519Private)
	if err != nil {
		t.Fatalf("MarshalPKCS8PrivateKey: %v", err)
	}

	kp := NewRsaKeyPair()
	kp.PrivateKey = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	_, err = kp.ParsePrivateKey()
	var unsupported UnsupportedKeyFormatError
	if !errors.As(err, &unsupported) {
		t.Fatalf("RSA with an Ed25519 key: got %T, want UnsupportedKeyFormatError", err)
	}
	if !strings.Contains(err.Error(), "an Ed25519 key, not an RSA key") {
		t.Fatalf("error %q does not name both algorithms", err)
	}
}

// TestParsePrivateKey_RejectsGarbage covers unparseable key material.
func TestParsePrivateKey_RejectsGarbage(t *testing.T) {
	kp := NewEd25519KeyPair()
	kp.PrivateKey = []byte("this is not a key")
	pri, err := kp.ParsePrivateKey()
	if err == nil || pri != nil {
		t.Fatalf("ParsePrivateKey accepted garbage, err = %v", err)
	}
	var invalid InvalidPrivateKeyError
	if !errors.As(err, &invalid) {
		t.Fatalf("error type = %T, want InvalidPrivateKeyError", err)
	}
}

// TestParsePrivateKey_RejectsPublicKeyBlock covers a public key PEM handed to
// ParsePrivateKey, the direction TestParseKeys_RejectWrongDirection does not.
func TestParsePrivateKey_RejectsPublicKeyBlock(t *testing.T) {
	source := NewEd25519KeyPair()
	if err := source.GenKeyPair(); err != nil {
		t.Fatalf("GenKeyPair: %v", err)
	}

	kp := NewEd25519KeyPair()
	kp.PrivateKey = source.PublicKey
	_, err := kp.ParsePrivateKey()
	var unsupported UnsupportedKeyFormatError
	if !errors.As(err, &unsupported) {
		t.Fatalf("error type = %T, want UnsupportedKeyFormatError", err)
	}
	if !strings.Contains(err.Error(), "expected a private key") {
		t.Fatalf("error %q does not explain the direction mismatch", err)
	}
}

// TestParsePublicKey_RejectsOtherAlgorithmBlock covers a PEM block labelled for
// another algorithm, for example an "EC PUBLIC KEY" block in an Ed25519 pair.
func TestParsePublicKey_RejectsOtherAlgorithmBlock(t *testing.T) {
	der, _ := mustECDSAPKIX(t)

	kp := NewEd25519KeyPair()
	kp.PublicKey = pem.EncodeToMemory(&pem.Block{Type: "EC PUBLIC KEY", Bytes: der})
	_, err := kp.ParsePublicKey()
	var unsupported UnsupportedKeyFormatError
	if !errors.As(err, &unsupported) {
		t.Fatalf("error type = %T, want UnsupportedKeyFormatError", err)
	}
	if !strings.Contains(err.Error(), `an EC key, not an Ed25519 key`) {
		t.Fatalf("error %q does not name the block algorithm", err)
	}
}

// TestEd25519_AcceptsRawPrivateKey covers a raw 64 byte ed25519.PrivateKey,
// the larger of the two bare encodings accepted next to the 32 byte seed.
func TestEd25519_AcceptsRawPrivateKey(t *testing.T) {
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	kp := NewEd25519KeyPair()
	kp.PrivateKey = private
	parsed, err := kp.ParsePrivateKey()
	if err != nil {
		t.Fatalf("ParsePrivateKey: %v", err)
	}
	if !bytes.Equal(parsed, private) {
		t.Fatal("parsed private key does not match the input")
	}
}

// TestCompressKey_StripsBrokenArmor covers inputs whose PEM armor is damaged so
// that pem.Decode fails: the armor lines are stripped instead.
func TestCompressKey_StripsBrokenArmor(t *testing.T) {
	broken := "-----BEGIN PUBLIC KEY-----\n!!!!\n-----END PUBLIC KEY-----"

	kp := NewRsaKeyPair()
	if compressed := string(kp.CompressPublicKey([]byte(broken))); compressed != "!!!!" {
		t.Fatalf("CompressPublicKey = %q, want the body %q", compressed, "!!!!")
	}
}
