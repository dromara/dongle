package keypair

import (
	"bytes"
	"crypto/ecdsa"
	crand "crypto/rand"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"testing"

	"github.com/dromara/dongle/crypto/internal/sm2"
	"github.com/dromara/dongle/internal/mock"
)

func TestNewSm2KeyPair_Defaults(t *testing.T) {
	kp := NewSm2KeyPair()
	if kp.Order != C1C3C2 || kp.Window != 4 {
		t.Fatalf("defaults not set: %+v", kp)
	}
}

func TestSetOrderAndWindow_Clamp(t *testing.T) {
	kp := NewSm2KeyPair()
	kp.SetOrder(C1C2C3)
	if kp.Order != C1C2C3 {
		t.Fatalf("order not set")
	}

	kp.SetWindow(1)
	if kp.Window != 2 {
		t.Fatalf("window clamp low: %d", kp.Window)
	}
	kp.SetWindow(7)
	if kp.Window != 6 {
		t.Fatalf("window clamp high: %d", kp.Window)
	}
	kp.SetWindow(5)
	if kp.Window != 5 {
		t.Fatalf("window set exact: %d", kp.Window)
	}
}

func TestGenParseAndCompressKeys(t *testing.T) {
	kp := NewSm2KeyPair()
	if err := kp.GenKeyPair(); err != nil {
		t.Fatalf("GenKeyPair: %v", err)
	}

	pub, err := kp.ParsePublicKey()
	if err != nil || pub == nil {
		t.Fatalf("ParsePublicKey: %v", err)
	}
	pri, err := kp.ParsePrivateKey()
	if err != nil || pri == nil {
		t.Fatalf("ParsePrivateKey: %v", err)
	}

	if s := string(kp.CompressPublicKey(kp.PublicKey)); bytes.Contains([]byte(s), []byte("BEGIN")) {
		t.Fatalf("CompressPublicKey still contains headers")
	}
	if s := string(kp.CompressPrivateKey(kp.PrivateKey)); bytes.Contains([]byte(s), []byte("BEGIN")) {
		t.Fatalf("CompressPrivateKey still contains headers")
	}
}

func TestFormatAndSetKeys(t *testing.T) {
	kp := NewSm2KeyPair()
	if err := kp.GenKeyPair(); err != nil {
		t.Fatalf("GenKeyPair: %v", err)
	}

	pubBlock, _ := pem.Decode(kp.PublicKey)
	priBlock, _ := pem.Decode(kp.PrivateKey)
	if pubBlock == nil || priBlock == nil {
		t.Fatalf("pem decode failed")
	}

	pubB64 := base64.StdEncoding.EncodeToString(pubBlock.Bytes)
	priB64 := base64.StdEncoding.EncodeToString(priBlock.Bytes)

	outPub, err := kp.FormatPublicKey([]byte(pubB64))
	if err != nil || len(outPub) == 0 {
		t.Fatalf("FormatPublicKey: %v", err)
	}
	outPri, err := kp.FormatPrivateKey([]byte(priB64))
	if err != nil || len(outPri) == 0 {
		t.Fatalf("FormatPrivateKey: %v", err)
	}

	if err := kp.SetPublicKey([]byte(pubB64)); err != nil {
		t.Fatalf("SetPublicKey: %v", err)
	}
	if err := kp.SetPrivateKey([]byte(priB64)); err != nil {
		t.Fatalf("SetPrivateKey: %v", err)
	}

	if _, err := kp.FormatPublicKey(nil); err == nil {
		t.Fatalf("FormatPublicKey expected error for nil")
	}
	if _, err := kp.FormatPrivateKey(nil); err == nil {
		t.Fatalf("FormatPrivateKey expected error for nil")
	}
	if _, err := kp.FormatPublicKey([]byte("???")); err == nil {
		t.Fatalf("FormatPublicKey expected invalid base64 error")
	}
	if _, err := kp.FormatPrivateKey([]byte("???")); err == nil {
		t.Fatalf("FormatPrivateKey expected invalid base64 error")
	}
	if err := kp.SetPublicKey([]byte("???")); err == nil {
		t.Fatalf("SetPublicKey expected error")
	}
	if err := kp.SetPrivateKey([]byte("???")); err == nil {
		t.Fatalf("SetPrivateKey expected error")
	}
}

func TestParseKey_ErrorPaths(t *testing.T) {
	kp := NewSm2KeyPair()
	if _, err := kp.ParsePublicKey(); err == nil {
		t.Fatalf("ParsePublicKey expected empty error")
	}
	if _, err := kp.ParsePrivateKey(); err == nil {
		t.Fatalf("ParsePrivateKey expected empty error")
	}

	kp.PublicKey = pem.EncodeToMemory(&pem.Block{Type: "XXX", Bytes: []byte{1}})
	if _, err := kp.ParsePublicKey(); err == nil {
		t.Fatalf("ParsePublicKey expected invalid block type")
	}

	kp.PrivateKey = pem.EncodeToMemory(&pem.Block{Type: "XXX", Bytes: []byte{1}})
	if _, err := kp.ParsePrivateKey(); err == nil {
		t.Fatalf("ParsePrivateKey expected invalid block type")
	}

	kp.PublicKey = []byte("not pem")
	if _, err := kp.ParsePublicKey(); err == nil {
		t.Fatalf("expected invalid public key block error")
	}

	kp.PrivateKey = []byte("not pem")
	if _, err := kp.ParsePrivateKey(); err == nil {
		t.Fatalf("expected invalid private key block error")
	}

	badPub := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: []byte{0xff, 0x00}})
	kp.PublicKey = badPub
	if _, err := kp.ParsePublicKey(); err == nil {
		t.Fatalf("expected inner public key parse error")
	}

	badPri := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte{0xff, 0x00}})
	kp.PrivateKey = badPri
	if _, err := kp.ParsePrivateKey(); err == nil {
		t.Fatalf("expected inner private key parse error")
	}
}

func TestGenKeyPair_RandError(t *testing.T) {
	kp := NewSm2KeyPair()
	old := crand.Reader
	crand.Reader = mock.NewErrorFile(io.ErrUnexpectedEOF)
	defer func() { crand.Reader = old }()

	if err := kp.GenKeyPair(); err == nil {
		t.Fatalf("GenKeyPair expected error with failing random reader")
	}
}

func TestCompressKeys_WithVariousWhitespace(t *testing.T) {
	kp := NewSm2KeyPair()
	if err := kp.GenKeyPair(); err != nil {
		t.Fatalf("GenKeyPair: %v", err)
	}

	pubWithSpaces := append([]byte{}, kp.PublicKey...)
	pubWithSpaces = append(pubWithSpaces, []byte("\n\r\t ")...)
	compressed := kp.CompressPublicKey(pubWithSpaces)
	if bytes.Contains(compressed, []byte("\n")) || bytes.Contains(compressed, []byte(" ")) {
		t.Fatalf("CompressPublicKey did not remove all whitespace")
	}

	priWithEncryptedHeader := []byte("-----BEGIN ENCRYPTED PRIVATE KEY-----\n")
	priWithEncryptedHeader = append(priWithEncryptedHeader, kp.PrivateKey...)
	priWithEncryptedHeader = append(priWithEncryptedHeader, []byte("-----END ENCRYPTED PRIVATE KEY-----\n")...)
	compressed = kp.CompressPrivateKey(priWithEncryptedHeader)
	if bytes.Contains(compressed, []byte("BEGIN")) || bytes.Contains(compressed, []byte("END")) {
		t.Fatalf("CompressPrivateKey did not remove encrypted headers")
	}
}

func TestParsePublicKey_RawDer(t *testing.T) {
	kp := NewSm2KeyPair()
	c := sm2.NewCurve()
	p := c.Params()
	coordLen := (p.BitSize + 7) / 8
	pad := func(v *big.Int) []byte {
		out := make([]byte, coordLen)
		copy(out[coordLen-len(v.Bytes()):], v.Bytes())
		return out
	}

	valid := make([]byte, 1+2*coordLen)
	valid[0] = 0x04
	copy(valid[1:], pad(p.Gx))
	copy(valid[1+coordLen:], pad(p.Gy))
	kp.PublicKey = valid
	pub, err := kp.ParsePublicKey()
	if err != nil {
		t.Fatalf("ParsePublicKey raw valid: %v", err)
	}
	if pub.X.Cmp(p.Gx) != 0 || pub.Y.Cmp(p.Gy) != 0 {
		t.Fatalf("ParsePublicKey raw returned unexpected point")
	}

	badPrefix := make([]byte, 1+2*coordLen)
	badPrefix[0] = 0x03
	copy(badPrefix[1:], pad(p.Gx))
	copy(badPrefix[1+coordLen:], pad(p.Gy))
	kp.PublicKey = badPrefix
	if _, err := kp.ParsePublicKey(); err == nil {
		t.Fatalf("ParsePublicKey raw expected error for invalid prefix")
	} else {
		var target InvalidPublicKeyError
		if !errors.As(err, &target) {
			t.Fatalf("ParsePublicKey raw error type = %T", err)
		}
		if target.Err == nil {
			t.Fatalf("ParsePublicKey raw error missing underlying cause")
		}
	}

	bad := append([]byte{}, valid...)
	yy := new(big.Int).Add(p.Gy, big.NewInt(1))
	yy.Mod(yy, p.P)
	copy(bad[1+coordLen:], pad(yy))
	kp.PublicKey = bad
	if _, err := kp.ParsePublicKey(); err == nil {
		t.Fatalf("ParsePublicKey raw expected error for point not on curve")
	} else {
		var target InvalidPublicKeyError
		if !errors.As(err, &target) {
			t.Fatalf("ParsePublicKey raw error type = %T", err)
		}
		if target.Err == nil {
			t.Fatalf("ParsePublicKey raw error missing underlying cause")
		}
	}
}

func TestParsePrivateKey_RawDer(t *testing.T) {
	kp := NewSm2KeyPair()
	p := sm2.NewCurve().Params()
	coordLen := (p.BitSize + 7) / 8
	raw := make([]byte, coordLen)
	raw[coordLen-1] = 1
	kp.PrivateKey = raw
	pri, err := kp.ParsePrivateKey()
	if err != nil {
		t.Fatalf("ParsePrivateKey raw valid: %v", err)
	}
	if pri.D.Cmp(big.NewInt(1)) != 0 {
		t.Fatalf("ParsePrivateKey raw unexpected scalar: %v", pri.D)
	}
	if pri.X == nil || pri.Y == nil {
		t.Fatalf("ParsePrivateKey raw missing public point")
	}

	oldFunc := bitStringPrivateKeyParser
	defer func() { bitStringPrivateKeyParser = oldFunc }()

	testErr := errors.New("test error from ParseDerPrivateKey")
	bitStringPrivateKeyParser = func(der []byte) (*ecdsa.PrivateKey, error) {
		return nil, testErr
	}

	kp.PrivateKey = raw
	_, err = kp.ParsePrivateKey()
	if err == nil {
		t.Fatalf("ParsePrivateKey expected error when ParseDerPrivateKey fails")
	}
	var target InvalidPrivateKeyError
	if !errors.As(err, &target) {
		t.Fatalf("ParsePrivateKey error type = %T, expected InvalidPrivateKeyError", err)
	}
	if target.Err == nil {
		t.Fatalf("ParsePrivateKey error missing underlying cause")
	}
	if target.Err.Error() != testErr.Error() {
		t.Fatalf("ParsePrivateKey error cause = %v, expected %v", target.Err, testErr)
	}
}

func TestSetUID(t *testing.T) {
	kp := NewSm2KeyPair()

	// Test setting non-empty UID
	uid := []byte("test-uid-12345678")
	kp.SetUID(uid)
	if !bytes.Equal(kp.UID, uid) {
		t.Fatalf("SetUID: expected %v, got %v", uid, kp.UID)
	}

	// Test setting nil UID
	kp.SetUID(nil)
	if kp.UID != nil {
		t.Fatalf("SetUID: expected nil, got %v", kp.UID)
	}

	// Test setting empty UID
	kp.SetUID([]byte{})
	if len(kp.UID) != 0 {
		t.Fatalf("SetUID: expected empty, got %v", kp.UID)
	}

	// Test setting another UID
	uid2 := []byte("another-uid")
	kp.SetUID(uid2)
	if !bytes.Equal(kp.UID, uid2) {
		t.Fatalf("SetUID: expected %v, got %v", uid2, kp.UID)
	}
}
