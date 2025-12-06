package sm2curve

import (
	"crypto/ecdsa"
	"crypto/rand"
	encodingAsn1 "encoding/asn1"
	"math/big"
	"testing"

	"golang.org/x/crypto/cryptobyte"
	cryptoAsn1 "golang.org/x/crypto/cryptobyte/asn1"
)

// genKey generates a test SM2 key pair
func genKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	cv := NewCurve()
	d, err := RandScalar(cv, rand.Reader)
	if err != nil {
		t.Fatalf("RandScalar: %v", err)
	}
	x, y := cv.ScalarBaseMult(d.Bytes())
	return &ecdsa.PrivateKey{PublicKey: ecdsa.PublicKey{Curve: cv, X: x, Y: y}, D: d}
}

func TestASN1_RoundTrip(t *testing.T) {
	pri := genKey(t)
	spki, err := MarshalSPKIPublicKey(&pri.PublicKey)
	if err != nil {
		t.Fatalf("spki: %v", err)
	}
	p8, err := MarshalPKCS8PrivateKey(pri)
	if err != nil {
		t.Fatalf("p8: %v", err)
	}

	pub2, err := ParseSPKIPublicKey(spki)
	if err != nil {
		t.Fatalf("parse spki: %v", err)
	}
	if pub2.X.Cmp(pri.X) != 0 || pub2.Y.Cmp(pri.Y) != 0 {
		t.Fatalf("pub mismatch")
	}
	pri2, err := ParsePKCS8PrivateKey(p8)
	if err != nil {
		t.Fatalf("parse p8: %v", err)
	}
	if pri2.D.Cmp(pri.D) != 0 {
		t.Fatalf("pri mismatch")
	}
}

func TestASN1_ParseSPKIPublicKey_CompressedAndErrors(t *testing.T) {
	cv := NewCurve()
	p := cv.Params()
	coordLen := (p.BitSize + 7) / 8

	// Wrong algorithm OID
	var b cryptobyte.Builder
	b.AddASN1(cryptoAsn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1(cryptoAsn1.SEQUENCE, func(b *cryptobyte.Builder) {
			b.AddASN1ObjectIdentifier(encodingAsn1.ObjectIdentifier{1, 2, 3})
		})
		b.AddASN1(cryptoAsn1.BIT_STRING, func(b *cryptobyte.Builder) { b.AddUint8(0); b.AddBytes([]byte{0x04, 0x00}) })
	})
	bad, _ := b.Bytes()
	if _, err := ParseSPKIPublicKey(bad); err == nil {
		t.Fatalf("expect algo OID error")
	}

	// Compressed encoding is not supported
	xb := make([]byte, coordLen)
	copy(xb[coordLen-len(p.Gx.Bytes()):], p.Gx.Bytes())
	comp := append([]byte{0x02}, xb...)
	var bc cryptobyte.Builder
	bc.AddASN1(cryptoAsn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1(cryptoAsn1.SEQUENCE, func(b *cryptobyte.Builder) {
			b.AddASN1ObjectIdentifier(oidEcPublicKey)
			b.AddASN1ObjectIdentifier(oidSM2P256v1)
		})
		b.AddASN1(cryptoAsn1.BIT_STRING, func(b *cryptobyte.Builder) { b.AddUint8(0); b.AddBytes(comp) })
	})
	der, _ := bc.Bytes()
	if _, err := ParseSPKIPublicKey(der); err == nil {
		t.Fatalf("expect unsupported or invalid EC point")
	}

	// Unsupported first byte
	comp[0] = 0x05
	var bu cryptobyte.Builder
	bu.AddASN1(cryptoAsn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1(cryptoAsn1.SEQUENCE, func(b *cryptobyte.Builder) {
			b.AddASN1ObjectIdentifier(oidEcPublicKey)
			b.AddASN1ObjectIdentifier(oidSM2P256v1)
		})
		b.AddASN1(cryptoAsn1.BIT_STRING, func(b *cryptobyte.Builder) { b.AddUint8(0); b.AddBytes(comp) })
	})
	der, _ = bu.Bytes()
	if _, err := ParseSPKIPublicKey(der); err == nil {
		t.Fatalf("expect unsupported point format")
	}

	// Empty public key point
	var be cryptobyte.Builder
	be.AddASN1(cryptoAsn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1(cryptoAsn1.SEQUENCE, func(b *cryptobyte.Builder) {
			b.AddASN1ObjectIdentifier(oidEcPublicKey)
			b.AddASN1ObjectIdentifier(oidSM2P256v1)
		})
		b.AddASN1(cryptoAsn1.BIT_STRING, func(b *cryptobyte.Builder) { b.AddUint8(0) })
	})
	der, _ = be.Bytes()
	if _, err := ParseSPKIPublicKey(der); err == nil {
		t.Fatalf("expect unsupported or invalid EC point")
	}

	// Invalid uncompressed length
	var bl cryptobyte.Builder
	bl.AddASN1(cryptoAsn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1(cryptoAsn1.SEQUENCE, func(b *cryptobyte.Builder) {
			b.AddASN1ObjectIdentifier(oidEcPublicKey)
			b.AddASN1ObjectIdentifier(oidSM2P256v1)
		})
		b.AddASN1(cryptoAsn1.BIT_STRING, func(b *cryptobyte.Builder) {
			b.AddUint8(0)
			bad := make([]byte, 1+2*coordLen-1)
			bad[0] = 0x04
			b.AddBytes(bad)
		})
	})
	der, _ = bl.Bytes()
	if _, err := ParseSPKIPublicKey(der); err == nil {
		t.Fatalf("expect invalid point len")
	}

	// Invalid compressed length
	var bc2 cryptobyte.Builder
	bc2.AddASN1(cryptoAsn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1(cryptoAsn1.SEQUENCE, func(b *cryptobyte.Builder) {
			b.AddASN1ObjectIdentifier(oidEcPublicKey)
			b.AddASN1ObjectIdentifier(oidSM2P256v1)
		})
		b.AddASN1(cryptoAsn1.BIT_STRING, func(b *cryptobyte.Builder) { b.AddUint8(0); b.AddBytes([]byte{0x02}) })
	})
	der, _ = bc2.Bytes()
	if _, err := ParseSPKIPublicKey(der); err == nil {
		t.Fatalf("expect unsupported or invalid EC point")
	}

	// Point not on curve
	raw := make([]byte, 1+2*coordLen)
	raw[0] = 0x04
	copy(raw[1+(coordLen-len(p.Gx.Bytes())):1+coordLen], p.Gx.Bytes())
	yy := new(big.Int).Add(p.Gy, big.NewInt(1))
	yy.Mod(yy, p.P)
	copy(raw[1+coordLen+(coordLen-len(yy.Bytes())):], yy.Bytes())
	var bnc cryptobyte.Builder
	bnc.AddASN1(cryptoAsn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1(cryptoAsn1.SEQUENCE, func(b *cryptobyte.Builder) {
			b.AddASN1ObjectIdentifier(oidEcPublicKey)
			b.AddASN1ObjectIdentifier(oidSM2P256v1)
		})
		b.AddASN1(cryptoAsn1.BIT_STRING, func(b *cryptobyte.Builder) { b.AddUint8(0); b.AddBytes(raw) })
	})
	der, _ = bnc.Bytes()
	if _, err := ParseSPKIPublicKey(der); err == nil {
		t.Fatalf("expect not on curve")
	}

	// Missing algorithm OID
	var bmiss cryptobyte.Builder
	bmiss.AddASN1(cryptoAsn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1(cryptoAsn1.SEQUENCE, func(b *cryptobyte.Builder) {})
		b.AddASN1(cryptoAsn1.BIT_STRING, func(b *cryptobyte.Builder) { b.AddUint8(0); b.AddBytes([]byte{0x04, 0x00}) })
	})
	der, _ = bmiss.Bytes()
	if _, err := ParseSPKIPublicKey(der); err == nil {
		t.Fatalf("expect missing algo OID")
	}

	// Top-level not a SEQUENCE
	if _, err := ParseSPKIPublicKey([]byte{0xff}); err == nil {
		t.Fatalf("expect invalid top-level SPKI")
	}

	// Top-level trailing bytes
	var okspki cryptobyte.Builder
	okspki.AddASN1(cryptoAsn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1(cryptoAsn1.SEQUENCE, func(b *cryptobyte.Builder) {
			b.AddASN1ObjectIdentifier(oidEcPublicKey)
			b.AddASN1ObjectIdentifier(oidSM2P256v1)
		})
		b.AddASN1(cryptoAsn1.BIT_STRING, func(b *cryptobyte.Builder) { b.AddUint8(0); b.AddBytes([]byte{0x04, 0x00}) })
	})
	der, _ = okspki.Bytes()
	der = append(der, 0x00)
	if _, err := ParseSPKIPublicKey(der); err == nil {
		t.Fatalf("expect invalid SubjectPublicKeyInfo")
	}

	// Missing BIT STRING
	var nobs cryptobyte.Builder
	nobs.AddASN1(cryptoAsn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1(cryptoAsn1.SEQUENCE, func(b *cryptobyte.Builder) {
			b.AddASN1ObjectIdentifier(oidEcPublicKey)
			b.AddASN1ObjectIdentifier(oidSM2P256v1)
		})
	})
	der, _ = nobs.Bytes()
	if _, err := ParseSPKIPublicKey(der); err == nil {
		t.Fatalf("expect invalid subjectPublicKey")
	}

	// BIT STRING empty
	var nobyte cryptobyte.Builder
	nobyte.AddASN1(cryptoAsn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1(cryptoAsn1.SEQUENCE, func(b *cryptobyte.Builder) {
			b.AddASN1ObjectIdentifier(oidEcPublicKey)
			b.AddASN1ObjectIdentifier(oidSM2P256v1)
		})
		b.AddASN1(cryptoAsn1.BIT_STRING, func(b *cryptobyte.Builder) {})
	})
	der, _ = nobyte.Bytes()
	if _, err := ParseSPKIPublicKey(der); err == nil {
		t.Fatalf("expect invalid BIT STRING")
	}
}

func TestASN1_ParsePKCS8PrivateKey_ErrorBranches(t *testing.T) {
	// Malformed top-level
	if _, err := ParsePKCS8PrivateKey([]byte{0xff}); err == nil {
		t.Fatalf("expect malformed p8")
	}

	// Wrong algorithm OID
	var inner cryptobyte.Builder
	inner.AddASN1(cryptoAsn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1Int64(1)
		b.AddASN1OctetString([]byte{1})
	})
	ecDer, _ := inner.Bytes()
	var p8 cryptobyte.Builder
	p8.AddASN1(cryptoAsn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1Int64(0)
		b.AddASN1(cryptoAsn1.SEQUENCE, func(b *cryptobyte.Builder) { b.AddASN1ObjectIdentifier(encodingAsn1.ObjectIdentifier{1, 2, 3}) })
		b.AddASN1(cryptoAsn1.OCTET_STRING, func(b *cryptobyte.Builder) { b.AddBytes(ecDer) })
	})
	der, _ := p8.Bytes()
	if _, err := ParsePKCS8PrivateKey(der); err == nil {
		t.Fatalf("expect algo OID error")
	}

	// Wrong curve OID
	var p8cOID cryptobyte.Builder
	p8cOID.AddASN1(cryptoAsn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1Int64(0)
		b.AddASN1(cryptoAsn1.SEQUENCE, func(b *cryptobyte.Builder) {
			b.AddASN1ObjectIdentifier(oidEcPublicKey)
			b.AddASN1ObjectIdentifier(encodingAsn1.ObjectIdentifier{1, 2, 3})
		})
		b.AddASN1(cryptoAsn1.OCTET_STRING, func(b *cryptobyte.Builder) {
			b.AddASN1(cryptoAsn1.SEQUENCE, func(b *cryptobyte.Builder) {
				b.AddASN1Int64(1)
				b.AddASN1OctetString([]byte{1})
			})
		})
	})
	der, _ = p8cOID.Bytes()
	if _, err := ParsePKCS8PrivateKey(der); err == nil {
		t.Fatalf("expect curve OID error")
	}

	// Invalid inner EC structure
	var p82 cryptobyte.Builder
	p82.AddASN1(cryptoAsn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1Int64(0)
		b.AddASN1(cryptoAsn1.SEQUENCE, func(b *cryptobyte.Builder) {
			b.AddASN1ObjectIdentifier(oidEcPublicKey)
			b.AddASN1ObjectIdentifier(oidSM2P256v1)
		})
		b.AddASN1(cryptoAsn1.OCTET_STRING, func(b *cryptobyte.Builder) { b.AddBytes([]byte{0xff}) })
	})
	der, _ = p82.Bytes()
	if _, err := ParsePKCS8PrivateKey(der); err == nil {
		t.Fatalf("expect inner unmarshal error")
	}

	// [0] parameters ignored
	pri := genKey(t)
	var ec cryptobyte.Builder
	ec.AddASN1(cryptoAsn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1Int64(1)
		b.AddASN1OctetString(pri.D.Bytes())
		b.AddASN1(cryptoAsn1.Tag(0).ContextSpecific().Constructed(), func(b *cryptobyte.Builder) {
			b.AddASN1ObjectIdentifier(encodingAsn1.ObjectIdentifier{1, 2, 3})
		})
	})
	ecDER, _ := ec.Bytes()
	var p83 cryptobyte.Builder
	p83.AddASN1(cryptoAsn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1Int64(0)
		b.AddASN1(cryptoAsn1.SEQUENCE, func(b *cryptobyte.Builder) {
			b.AddASN1ObjectIdentifier(oidEcPublicKey)
			b.AddASN1ObjectIdentifier(oidSM2P256v1)
		})
		b.AddASN1(cryptoAsn1.OCTET_STRING, func(b *cryptobyte.Builder) { b.AddBytes(ecDER) })
	})
	der, _ = p83.Bytes()
	if _, err := ParsePKCS8PrivateKey(der); err != nil {
		t.Fatalf("unexpected error for ignored [0]: %v", err)
	}

	// [1] publicKey ignored
	cv := NewCurve()
	x, y := cv.ScalarBaseMult([]byte{2})
	plen := (cv.Params().BitSize + 7) / 8
	pt := make([]byte, 1+2*plen)
	pt[0] = 0x04
	copy(pt[1+(plen-len(x.Bytes())):1+plen], x.Bytes())
	copy(pt[1+plen+(plen-len(y.Bytes())):], y.Bytes())
	var ec2 cryptobyte.Builder
	ec2.AddASN1(cryptoAsn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1Int64(1)
		b.AddASN1OctetString(pri.D.Bytes())
		b.AddASN1(cryptoAsn1.Tag(1).ContextSpecific().Constructed(), func(b *cryptobyte.Builder) { b.AddASN1BitString(pt) })
	})
	ecDER2, _ := ec2.Bytes()
	var p84 cryptobyte.Builder
	p84.AddASN1(cryptoAsn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1Int64(0)
		b.AddASN1(cryptoAsn1.SEQUENCE, func(b *cryptobyte.Builder) {
			b.AddASN1ObjectIdentifier(oidEcPublicKey)
			b.AddASN1ObjectIdentifier(oidSM2P256v1)
		})
		b.AddASN1(cryptoAsn1.OCTET_STRING, func(b *cryptobyte.Builder) { b.AddBytes(ecDER2) })
	})
	der, _ = p84.Bytes()
	if _, err := ParsePKCS8PrivateKey(der); err != nil {
		t.Fatalf("unexpected error for ignored [1]: %v", err)
	}

	// Missing version
	var p85 cryptobyte.Builder
	p85.AddASN1(cryptoAsn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1(cryptoAsn1.SEQUENCE, func(b *cryptobyte.Builder) {
			b.AddASN1ObjectIdentifier(oidEcPublicKey)
			b.AddASN1ObjectIdentifier(oidSM2P256v1)
		})
		b.AddASN1(cryptoAsn1.OCTET_STRING, func(b *cryptobyte.Builder) { b.AddBytes([]byte{0x30, 0x00}) })
	})
	der, _ = p85.Bytes()
	if _, err := ParsePKCS8PrivateKey(der); err == nil {
		t.Fatalf("expect missing version")
	}

	// Missing AlgorithmIdentifier
	var p86 cryptobyte.Builder
	p86.AddASN1(cryptoAsn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1Int64(0)
		b.AddASN1(cryptoAsn1.OCTET_STRING, func(b *cryptobyte.Builder) { b.AddBytes([]byte{0x30, 0x00}) })
	})
	der, _ = p86.Bytes()
	if _, err := ParsePKCS8PrivateKey(der); err == nil {
		t.Fatalf("expect missing AI")
	}

	// Missing algorithm OID
	var p87 cryptobyte.Builder
	p87.AddASN1(cryptoAsn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1Int64(0)
		b.AddASN1(cryptoAsn1.SEQUENCE, func(b *cryptobyte.Builder) {})
		b.AddASN1(cryptoAsn1.OCTET_STRING, func(b *cryptobyte.Builder) { b.AddBytes([]byte{0x30, 0x00}) })
	})
	der, _ = p87.Bytes()
	if _, err := ParsePKCS8PrivateKey(der); err == nil {
		t.Fatalf("expect missing algo OID")
	}

	// Missing privateKey
	var p88 cryptobyte.Builder
	p88.AddASN1(cryptoAsn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1Int64(0)
		b.AddASN1(cryptoAsn1.SEQUENCE, func(b *cryptobyte.Builder) {
			b.AddASN1ObjectIdentifier(oidEcPublicKey)
			b.AddASN1ObjectIdentifier(oidSM2P256v1)
		})
	})
	der, _ = p88.Bytes()
	if _, err := ParsePKCS8PrivateKey(der); err == nil {
		t.Fatalf("expect missing privateKey")
	}

	// Invalid ECPrivateKey version
	var ecBad cryptobyte.Builder
	ecBad.AddASN1(cryptoAsn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1Int64(2)
	})
	ecDERBad, _ := ecBad.Bytes()
	var p89 cryptobyte.Builder
	p89.AddASN1(cryptoAsn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1Int64(0)
		b.AddASN1(cryptoAsn1.SEQUENCE, func(b *cryptobyte.Builder) {
			b.AddASN1ObjectIdentifier(oidEcPublicKey)
			b.AddASN1ObjectIdentifier(oidSM2P256v1)
		})
		b.AddASN1(cryptoAsn1.OCTET_STRING, func(b *cryptobyte.Builder) { b.AddBytes(ecDERBad) })
	})
	der, _ = p89.Bytes()
	if _, err := ParsePKCS8PrivateKey(der); err == nil {
		t.Fatalf("expect bad EC version")
	}

	// [1] invalid structure ignored
	var ecBad2 cryptobyte.Builder
	ecBad2.AddASN1(cryptoAsn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1Int64(1)
		b.AddASN1OctetString([]byte{1})
		b.AddASN1(cryptoAsn1.Tag(1).ContextSpecific().Constructed(), func(b *cryptobyte.Builder) {
			b.AddASN1(cryptoAsn1.SEQUENCE, func(b *cryptobyte.Builder) { b.AddASN1Int64(1) })
		})
	})
	ecDERBad2, _ := ecBad2.Bytes()
	var p8a cryptobyte.Builder
	p8a.AddASN1(cryptoAsn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1Int64(0)
		b.AddASN1(cryptoAsn1.SEQUENCE, func(b *cryptobyte.Builder) {
			b.AddASN1ObjectIdentifier(oidEcPublicKey)
			b.AddASN1ObjectIdentifier(oidSM2P256v1)
		})
		b.AddASN1(cryptoAsn1.OCTET_STRING, func(b *cryptobyte.Builder) { b.AddBytes(ecDERBad2) })
	})
	der, _ = p8a.Bytes()
	if _, err := ParsePKCS8PrivateKey(der); err != nil {
		t.Fatalf("unexpected error for ignored [1] structure: %v", err)
	}

	// [1] padding ignored
	var ecBad3 cryptobyte.Builder
	ecBad3.AddASN1(cryptoAsn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1Int64(1)
		b.AddASN1OctetString([]byte{1})
		b.AddASN1(cryptoAsn1.Tag(1).ContextSpecific().Constructed(), func(b *cryptobyte.Builder) {
			b.AddASN1(cryptoAsn1.BIT_STRING, func(b *cryptobyte.Builder) { b.AddUint8(1); b.AddBytes([]byte{0x00}) })
		})
	})
	ecDERBad3, _ := ecBad3.Bytes()
	var p8b cryptobyte.Builder
	p8b.AddASN1(cryptoAsn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1Int64(0)
		b.AddASN1(cryptoAsn1.SEQUENCE, func(b *cryptobyte.Builder) {
			b.AddASN1ObjectIdentifier(oidEcPublicKey)
			b.AddASN1ObjectIdentifier(oidSM2P256v1)
		})
		b.AddASN1(cryptoAsn1.OCTET_STRING, func(b *cryptobyte.Builder) { b.AddBytes(ecDERBad3) })
	})
	der, _ = p8b.Bytes()
	if _, err := ParsePKCS8PrivateKey(der); err != nil {
		t.Fatalf("unexpected error for ignored [1] padding: %v", err)
	}

	// [0] invalid ignored
	var ecBad0 cryptobyte.Builder
	ecBad0.AddASN1(cryptoAsn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1Int64(1)
		b.AddASN1OctetString([]byte{1})
		b.AddASN1(cryptoAsn1.Tag(0).ContextSpecific().Constructed(), func(b *cryptobyte.Builder) {})
	})
	ecBad0DER, _ := ecBad0.Bytes()
	var p8c cryptobyte.Builder
	p8c.AddASN1(cryptoAsn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1Int64(0)
		b.AddASN1(cryptoAsn1.SEQUENCE, func(b *cryptobyte.Builder) {
			b.AddASN1ObjectIdentifier(oidEcPublicKey)
			b.AddASN1ObjectIdentifier(oidSM2P256v1)
		})
		b.AddASN1(cryptoAsn1.OCTET_STRING, func(b *cryptobyte.Builder) { b.AddBytes(ecBad0DER) })
	})
	der, _ = p8c.Bytes()
	if _, err := ParsePKCS8PrivateKey(der); err != nil {
		t.Fatalf("unexpected error for ignored [0]: %v", err)
	}

	// Missing privateKey OCTET_STRING
	var ecNoKey cryptobyte.Builder
	ecNoKey.AddASN1(cryptoAsn1.SEQUENCE, func(b *cryptobyte.Builder) { b.AddASN1Int64(1) })
	ecNoKeyDER, _ := ecNoKey.Bytes()
	var p8d cryptobyte.Builder
	p8d.AddASN1(cryptoAsn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1Int64(0)
		b.AddASN1(cryptoAsn1.SEQUENCE, func(b *cryptobyte.Builder) {
			b.AddASN1ObjectIdentifier(oidEcPublicKey)
			b.AddASN1ObjectIdentifier(oidSM2P256v1)
		})
		b.AddASN1(cryptoAsn1.OCTET_STRING, func(b *cryptobyte.Builder) { b.AddBytes(ecNoKeyDER) })
	})
	der, _ = p8d.Bytes()
	if _, err := ParsePKCS8PrivateKey(der); err == nil {
		t.Fatalf("expect missing EC privateKey")
	}
}
