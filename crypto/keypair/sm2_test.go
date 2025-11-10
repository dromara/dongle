package keypair

import (
	"bytes"
	"crypto/ecdsa"
	crand "crypto/rand"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"io"
	"io/fs"
	"math/big"
	"testing"

	"encoding/asn1"
	"github.com/dromara/dongle/crypto/internal/sm2curve"
	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"
)

// mockFile implements fs.File and returns a configured error on Read.
type mockFile struct{ readErr error }

func (m mockFile) Stat() (fs.FileInfo, error) { return nil, errors.New("no stat") }
func (m mockFile) Read(p []byte) (int, error) { return 0, m.readErr }
func (m mockFile) Close() error               { return nil }

// fileWrap adapts an io.ReadCloser to fs.File for ReadAll.
type rc struct{ io.ReadCloser }
type fileWrap struct{ rc }

func (f fileWrap) Stat() (fs.FileInfo, error) { return nil, errors.New("no stat") }

// TestNewSm2KeyPair_Defaults verifies default values are set correctly.
func TestNewSm2KeyPair_Defaults(t *testing.T) {
	kp := NewSm2KeyPair()
	if kp.Order != C1C3C2 || kp.Window != 4 {
		t.Fatalf("defaults not set: %+v", kp)
	}
}

// TestSetOrderAndWindow_Clamp tests window size clamping to valid range [2, 6].
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

// TestGenParseAndCompressKeys tests key generation, parsing, and compression.
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

// TestFormatAndSetKeys tests key formatting and setting from base64-encoded DER.
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

// TestLoadPublicPrivateKey tests loading keys from fs.File interface.
func TestLoadPublicPrivateKey(t *testing.T) {
	kp := NewSm2KeyPair()
	if err := kp.GenKeyPair(); err != nil {
		t.Fatalf("GenKeyPair: %v", err)
	}

	pubTmp := bytes.NewBuffer(kp.PublicKey)
	priTmp := bytes.NewBuffer(kp.PrivateKey)

	if err := kp.LoadPublicKey(fileWrap{rc{io.NopCloser(bytes.NewReader(pubTmp.Bytes()))}}); err != nil {
		t.Fatalf("LoadPublicKey: %v", err)
	}
	if err := kp.LoadPrivateKey(fileWrap{rc{io.NopCloser(bytes.NewReader(priTmp.Bytes()))}}); err != nil {
		t.Fatalf("LoadPrivateKey: %v", err)
	}

	if err := kp.LoadPublicKey(mockFile{readErr: errors.New("boom")}); err == nil {
		t.Fatalf("LoadPublicKey expected error")
	}
	if err := kp.LoadPrivateKey(mockFile{readErr: errors.New("boom")}); err == nil {
		t.Fatalf("LoadPrivateKey expected error")
	}
}

// TestParseKey_ErrorPaths tests error handling in key parsing.
func TestParseKey_ErrorPaths(t *testing.T) {
	kp := NewSm2KeyPair()
	if _, err := kp.ParsePublicKey(); err == nil {
		t.Fatalf("ParsePublicKey expected empty error")
	}
	if _, err := kp.ParsePrivateKey(); err == nil {
		t.Fatalf("ParsePrivateKey expected empty error")
	}

	if _, err := kp.ParsePublicKeyWithBytes(pem.EncodeToMemory(&pem.Block{Type: "XXX", Bytes: []byte{1}})); err == nil {
		t.Fatalf("ParsePublicKey expected invalid block type")
	}
	if _, err := kp.ParsePrivateKeyWithBytes(pem.EncodeToMemory(&pem.Block{Type: "XXX", Bytes: []byte{1}})); err == nil {
		t.Fatalf("ParsePrivateKey expected invalid block type")
	}
}

func (k *Sm2KeyPair) ParsePublicKeyWithBytes(pemBytes []byte) (*ecdsa.PublicKey, error) {
	k.PublicKey = pemBytes
	return k.ParsePublicKey()
}
func (k *Sm2KeyPair) ParsePrivateKeyWithBytes(pemBytes []byte) (*ecdsa.PrivateKey, error) {
	k.PrivateKey = pemBytes
	return k.ParsePrivateKey()
}

// TestCurveParamsAndOps tests SM2 curve operations and edge cases.
func TestCurveParamsAndOps(t *testing.T) {
	c := sm2curve.New()
	p := c.Params()
	if !c.IsOnCurve(p.Gx, p.Gy) {
		t.Fatalf("G not on curve")
	}
	if c.IsOnCurve(nil, nil) {
		t.Fatalf("nil point should not be on curve")
	}

	one := big.NewInt(1)
	l := (p.BitSize + 7) / 8
	xb := one.Bytes()
	got := make([]byte, l)
	copy(got[l-len(xb):], xb)
	if len(got) != l || got[len(got)-1] != 1 {
		t.Fatalf("padBytes unexpected: %x", got)
	}

	if x, y := c.Add(nil, nil, p.Gx, p.Gy); x.Cmp(p.Gx) != 0 || y.Cmp(p.Gy) != 0 {
		t.Fatalf("Add identity failed")
	}
	if x, y := c.Add(p.Gx, p.Gy, nil, nil); x.Cmp(p.Gx) != 0 || y.Cmp(p.Gy) != 0 {
		t.Fatalf("Add identity2 failed")
	}

	negY := new(big.Int).Neg(p.Gy)
	negY.Mod(negY, p.P)
	if x, y := c.Add(p.Gx, p.Gy, p.Gx, negY); x != nil || y != nil {
		t.Fatalf("Add inverse not infinity")
	}

	if x, y := c.Double(p.Gx, big.NewInt(0)); x != nil || y != nil {
		t.Fatalf("Double at y=0 not infinity")
	}
	xD, yD := c.Double(p.Gx, p.Gy)
	xA, yA := c.Add(p.Gx, p.Gy, p.Gx, p.Gy)
	if xD.Cmp(xA) != 0 || yD.Cmp(yA) != 0 {
		t.Fatalf("Add same point != Double")
	}
	xG, yG := p.Gx, p.Gy
	xSum, ySum := c.Add(xG, yG, xD, yD)
	if xSum == nil || ySum == nil {
		t.Fatalf("Add general branch failed")
	}

	if x, y := c.ScalarMult(p.Gx, p.Gy, make([]byte, 32)); x != nil || y != nil {
		t.Fatalf("ScalarMult zero should be nil,nil")
	}

	k := make([]byte, 32)
	k[31] = 1
	x1, y1 := c.ScalarBaseMult(k)
	if x1.Cmp(p.Gx) != 0 || y1.Cmp(p.Gy) != 0 {
		t.Fatalf("ScalarBaseMult(1) != G")
	}
}

// TestASN1MarshalParsePublicPrivate tests ASN.1 marshaling and parsing roundtrip.
func TestASN1MarshalParsePublicPrivate(t *testing.T) {
	c := sm2curve.New()
	d := big.NewInt(12345)
	x, y := c.ScalarBaseMult(d.Bytes())
	pri := &ecdsa.PrivateKey{PublicKey: ecdsa.PublicKey{Curve: c, X: x, Y: y}, D: d}

	derPri, err := sm2curve.MarshalPKCS8(pri)
	if err != nil {
		t.Fatalf("marshalPrivateKey: %v", err)
	}
	gotPri, err := sm2curve.ParsePKCS8(derPri)
	if err != nil || gotPri.D.Cmp(d) != 0 {
		t.Fatalf("parsePrivateKey: %v", err)
	}

	derPub, err := sm2curve.MarshalSPKI(&pri.PublicKey)
	if err != nil {
		t.Fatalf("marshaPublicKey: %v", err)
	}
	gotPub, err := sm2curve.ParseSPKI(derPub)
	if err != nil || gotPub.X.Cmp(x) != 0 || gotPub.Y.Cmp(y) != 0 {
		t.Fatalf("parsePublicKey: %v", err)
	}
}

// TestMarshalOIDPaths verifies marshalPublicKey/marshalPrivateKey produce parsable DER.
func TestMarshalOIDPaths(t *testing.T) {
	c := sm2curve.New()
	d := big.NewInt(2)
	x, y := c.ScalarBaseMult(d.Bytes())
	pri := &ecdsa.PrivateKey{PublicKey: ecdsa.PublicKey{Curve: c, X: x, Y: y}, D: d}
	derPub, err := sm2curve.MarshalSPKI(&pri.PublicKey)
	if err != nil || len(derPub) == 0 {
		t.Fatalf("marshaPublicKey: %v", err)
	}
	if _, err := sm2curve.ParseSPKI(derPub); err != nil {
		t.Fatalf("parsePublicKey back: %v", err)
	}
	derPri, err := sm2curve.MarshalPKCS8(pri)
	if err != nil || len(derPri) == 0 {
		t.Fatalf("marshalPrivateKey: %v", err)
	}
	if _, err := sm2curve.ParsePKCS8(derPri); err != nil {
		t.Fatalf("parsePrivateKey back: %v", err)
	}
}

type errReader struct{}

func (errReader) Read(p []byte) (int, error) { return 0, io.ErrUnexpectedEOF }

// TestGenKeyPair_RandError tests error handling when random reader fails.
func TestGenKeyPair_RandError(t *testing.T) {
	kp := NewSm2KeyPair()
	old := crand.Reader
	crand.Reader = errReader{}
	defer func() { crand.Reader = old }()

	// GenKeyPair should return error when random reader fails
	if err := kp.GenKeyPair(); err == nil {
		t.Fatalf("GenKeyPair expected error with failing random reader")
	}
}

// TestGenKeyPair_MultipleGenerations tests multiple key pair generations.
func TestGenKeyPair_MultipleGenerations(t *testing.T) {
	kp := NewSm2KeyPair()
	for i := 0; i < 3; i++ {
		if err := kp.GenKeyPair(); err != nil {
			t.Fatalf("GenKeyPair iteration %d failed: %v", i, err)
		}
		if len(kp.PublicKey) == 0 || len(kp.PrivateKey) == 0 {
			t.Fatalf("GenKeyPair iteration %d: keys not set", i)
		}
		if _, err := kp.ParsePublicKey(); err != nil {
			t.Fatalf("ParsePublicKey iteration %d failed: %v", i, err)
		}
		if _, err := kp.ParsePrivateKey(); err != nil {
			t.Fatalf("ParsePrivateKey iteration %d failed: %v", i, err)
		}
	}
}

// TestCompressKeys_WithVariousWhitespace tests key compression with various whitespace.
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

// TestFormatKeys_EmptyInput tests key formatting with empty input.
func TestFormatKeys_EmptyInput(t *testing.T) {
	kp := NewSm2KeyPair()

	if _, err := kp.FormatPublicKey([]byte{}); err == nil {
		t.Fatalf("FormatPublicKey expected error for empty input")
	}
	if _, err := kp.FormatPrivateKey([]byte{}); err == nil {
		t.Fatalf("FormatPrivateKey expected error for empty input")
	}
}

// TestGenKeyPair_FullCoverage tests GenKeyPair complete workflow.
func TestGenKeyPair_FullCoverage(t *testing.T) {
	for i := 0; i < 5; i++ {
		kp := NewSm2KeyPair()
		if err := kp.GenKeyPair(); err != nil {
			t.Fatalf("iteration %d: GenKeyPair failed: %v", i, err)
		}

		if len(kp.PublicKey) == 0 {
			t.Fatalf("iteration %d: PublicKey not generated", i)
		}
		if len(kp.PrivateKey) == 0 {
			t.Fatalf("iteration %d: PrivateKey not generated", i)
		}

		pub, err := kp.ParsePublicKey()
		if err != nil {
			t.Fatalf("iteration %d: ParsePublicKey failed: %v", i, err)
		}
		pri, err := kp.ParsePrivateKey()
		if err != nil {
			t.Fatalf("iteration %d: ParsePrivateKey failed: %v", i, err)
		}

		if pub.X.Cmp(pri.X) != 0 || pub.Y.Cmp(pri.Y) != 0 {
			t.Fatalf("iteration %d: public key mismatch", i)
		}

		c := sm2curve.New()
		if !c.IsOnCurve(pub.X, pub.Y) {
			t.Fatalf("iteration %d: public key not on curve", i)
		}
	}
}

// TestMarshalFunctions_DirectCall tests marshal functions directly.
func TestMarshalFunctions_DirectCall(t *testing.T) {
	c := sm2curve.New()
	d := big.NewInt(12345)
	x, y := c.ScalarBaseMult(d.Bytes())
	pri := &ecdsa.PrivateKey{PublicKey: ecdsa.PublicKey{Curve: c, X: x, Y: y}, D: d}

	derPri, err := sm2curve.MarshalPKCS8(pri)
	if err != nil {
		t.Fatalf("MarshalPKCS8 failed: %v", err)
	}
	if len(derPri) == 0 {
		t.Fatalf("MarshalPKCS8 returned empty result")
	}

	derPub, err := sm2curve.MarshalSPKI(&pri.PublicKey)
	if err != nil {
		t.Fatalf("MarshalSPKI failed: %v", err)
	}
	if len(derPub) == 0 {
		t.Fatalf("MarshalSPKI returned empty result")
	}

	gotPri, err := sm2curve.ParsePKCS8(derPri)
	if err != nil || gotPri.D.Cmp(d) != 0 {
		t.Fatalf("ParsePKCS8 failed: %v", err)
	}

	gotPub, err := sm2curve.ParseSPKI(derPub)
	if err != nil || gotPub.X.Cmp(x) != 0 || gotPub.Y.Cmp(y) != 0 {
		t.Fatalf("ParseSPKI failed: %v", err)
	}
}

// TestParsePublicKey_ErrorBranches tests error paths in SPKI parsing.
func TestParsePublicKey_ErrorBranches(t *testing.T) {
	c := sm2curve.New()
	p := c.Params()
	pLen := (p.BitSize + 7) / 8
	var b cryptobyte.Builder
	b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
			b.AddASN1ObjectIdentifier(asn1.ObjectIdentifier{1, 2, 3})
		})
		b.AddASN1(cbasn1.BIT_STRING, func(b *cryptobyte.Builder) {
			b.AddUint8(0)
			b.AddBytes([]byte{0x04, 0x00})
		})
	})
	der, _ := b.Bytes()
	if _, err := sm2curve.ParseSPKI(der); err == nil {
		t.Fatalf("expected algo OID error")
	}

	if _, err := sm2curve.ParseSPKI([]byte{0xff, 0x00}); err == nil {
		t.Fatalf("expected unmarshal error")
	}

	var b2 cryptobyte.Builder
	b2.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
			b.AddASN1ObjectIdentifier(asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1})
			b.AddASN1ObjectIdentifier(asn1.ObjectIdentifier{1, 2, 156, 10197, 1, 301})
		})
		b.AddASN1(cbasn1.BIT_STRING, func(b *cryptobyte.Builder) {
			b.AddUint8(0)
			bad := make([]byte, 1+2*pLen)
			bad[0] = 0x02
			b.AddBytes(bad)
		})
	})
	der, _ = b2.Bytes()
	if _, err := sm2curve.ParseSPKI(der); err == nil {
		t.Fatalf("expected point prefix error")
	}

	var b3 cryptobyte.Builder
	b3.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
			b.AddASN1ObjectIdentifier(asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1})
			b.AddASN1ObjectIdentifier(asn1.ObjectIdentifier{1, 2, 156, 10197, 1, 301})
		})
		b.AddASN1(cbasn1.BIT_STRING, func(b *cryptobyte.Builder) {
			b.AddUint8(0)
			b.AddBytes([]byte{0x04, 1, 2, 3})
		})
	})
	der, _ = b3.Bytes()
	if _, err := sm2curve.ParseSPKI(der); err == nil {
		t.Fatalf("expected length error")
	}

	xb := make([]byte, pLen)
	copy(xb[pLen-len(p.Gx.Bytes()):], p.Gx.Bytes())
	yb := make([]byte, pLen)
	yy := new(big.Int).Add(p.Gy, big.NewInt(1))
	yy.Mod(yy, p.P)
	copy(yb[pLen-len(yy.Bytes()):], yy.Bytes())
	raw := append(append([]byte{0x04}, xb...), yb...)
	var b4 cryptobyte.Builder
	b4.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
			b.AddASN1ObjectIdentifier(asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1})
			b.AddASN1ObjectIdentifier(asn1.ObjectIdentifier{1, 2, 156, 10197, 1, 301})
		})
		b.AddASN1(cbasn1.BIT_STRING, func(b *cryptobyte.Builder) {
			b.AddUint8(0)
			b.AddBytes(raw)
		})
	})
	der, _ = b4.Bytes()
	if _, err := sm2curve.ParseSPKI(der); err == nil {
		t.Fatalf("expected not on curve error")
	}
}

// TestParsePrivateKey_ErrorBranches tests error paths in PKCS8 parsing.
func TestParsePrivateKey_ErrorBranches(t *testing.T) {
	if _, err := sm2curve.ParsePKCS8([]byte{0xff, 0xff}); err == nil {
		t.Fatalf("expected unmarshal error")
	}

	var inner cryptobyte.Builder
	inner.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1Int64(1)
		b.AddASN1OctetString([]byte{1})
	})
	ecDer, _ := inner.Bytes()
	var p8 cryptobyte.Builder
	p8.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1Int64(0)
		b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
			b.AddASN1ObjectIdentifier(asn1.ObjectIdentifier{1, 2, 3})
		})
		b.AddASN1(cbasn1.OCTET_STRING, func(b *cryptobyte.Builder) { b.AddBytes(ecDer) })
	})
	der, _ := p8.Bytes()
	if _, err := sm2curve.ParsePKCS8(der); err == nil {
		t.Fatalf("expected algo OID error")
	}

	var p82 cryptobyte.Builder
	p82.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1Int64(0)
		b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
			b.AddASN1ObjectIdentifier(asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1})
			b.AddASN1ObjectIdentifier(asn1.ObjectIdentifier{1, 2, 156, 10197, 1, 301})
		})
		b.AddASN1(cbasn1.OCTET_STRING, func(b *cryptobyte.Builder) { b.AddBytes([]byte{0xff}) })
	})
	der, _ = p82.Bytes()
	if _, err := sm2curve.ParsePKCS8(der); err == nil {
		t.Fatalf("expected inner unmarshal error")
	}
}

// TestSm2KeyPair_ParseBlockNilCases tests parsing with invalid PEM blocks.
func TestSm2KeyPair_ParseBlockNilCases(t *testing.T) {
	kp := NewSm2KeyPair()
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
