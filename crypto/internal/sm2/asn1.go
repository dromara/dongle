package sm2

import (
	"crypto/ecdsa"
	encodingAsn1 "encoding/asn1"
	"math/big"

	"golang.org/x/crypto/cryptobyte"
	cryptoAsn1 "golang.org/x/crypto/cryptobyte/asn1"
)

// MarshalSPKIPublicKey encodes a SubjectPublicKeyInfo (SPKI) for the given SM2 public key.
func MarshalSPKIPublicKey(pub *ecdsa.PublicKey) ([]byte, error) {
	pLen := (pub.Curve.Params().BitSize + 7) / 8
	point := make([]byte, 1+2*pLen)
	point[0] = 0x04
	xb := pub.X.Bytes()
	yb := pub.Y.Bytes()
	copy(point[1+(pLen-len(xb)):1+pLen], xb)
	copy(point[1+pLen+(pLen-len(yb)):1+2*pLen], yb)

	var b cryptobyte.Builder
	b.AddASN1(cryptoAsn1.SEQUENCE, func(b *cryptobyte.Builder) {
		// AlgorithmIdentifier
		b.AddASN1(cryptoAsn1.SEQUENCE, func(b *cryptobyte.Builder) {
			b.AddASN1ObjectIdentifier(oidEcPublicKey)
			b.AddASN1ObjectIdentifier(oidSM2P256v1)
		})
		// subjectPublicKey BIT STRING
		b.AddASN1BitString(point)
	})
	return b.Bytes()
}

// MarshalPKCS8PrivateKey encodes a PKCS#8 PrivateKeyInfo for the given SM2 private key.
func MarshalPKCS8PrivateKey(pri *ecdsa.PrivateKey) ([]byte, error) {
	pLen := (pri.Params().BitSize + 7) / 8
	point := make([]byte, 1+2*pLen)
	point[0] = 0x04
	xb := pri.X.Bytes()
	yb := pri.Y.Bytes()
	copy(point[1+(pLen-len(xb)):1+pLen], xb)
	copy(point[1+pLen+(pLen-len(yb)):1+2*pLen], yb)

	var p8 cryptobyte.Builder
	p8.AddASN1(cryptoAsn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1Int64(0) // version
		b.AddASN1(cryptoAsn1.SEQUENCE, func(b *cryptobyte.Builder) {
			b.AddASN1ObjectIdentifier(oidEcPublicKey)
			b.AddASN1ObjectIdentifier(oidSM2P256v1)
		})
		// privateKey OCTET STRING wrapping ECPrivateKey
		b.AddASN1(cryptoAsn1.OCTET_STRING, func(b *cryptobyte.Builder) {
			b.AddASN1(cryptoAsn1.SEQUENCE, func(b *cryptobyte.Builder) {
				b.AddASN1Int64(1) // ec version
				b.AddASN1OctetString(pri.D.Bytes())
				// [0] parameters namedCurve OID (explicit)
				b.AddASN1(cryptoAsn1.Tag(0).ContextSpecific().Constructed(), func(b *cryptobyte.Builder) {
					b.AddASN1ObjectIdentifier(oidSM2P256v1)
				})
				// [1] publicKey BIT STRING (explicit)
				b.AddASN1(cryptoAsn1.Tag(1).ContextSpecific().Constructed(), func(b *cryptobyte.Builder) {
					b.AddASN1BitString(point)
				})
			})
		})
	})
	return p8.Bytes()
}

// ParseSPKIPublicKey parses a SubjectPublicKeyInfo (SPKI) and returns an SM2 public key.
func ParseSPKIPublicKey(der []byte) (*ecdsa.PublicKey, error) {
	in := cryptobyte.String(der)
	var spki, ai, bitStr cryptobyte.String
	var alg, curveOID encodingAsn1.ObjectIdentifier
	var unused uint8
	if !(in.ReadASN1(&spki, cryptoAsn1.SEQUENCE) && in.Empty() &&
		spki.ReadASN1(&ai, cryptoAsn1.SEQUENCE) &&
		ai.ReadASN1ObjectIdentifier(&alg) && alg.Equal(oidEcPublicKey) &&
		ai.ReadASN1ObjectIdentifier(&curveOID) && curveOID.Equal(oidSM2P256v1) &&
		spki.ReadASN1(&bitStr, cryptoAsn1.BIT_STRING) &&
		bitStr.ReadUint8(&unused)) {
		return nil, encodingAsn1.SyntaxError{Msg: "invalid SubjectPublicKeyInfo"}
	}
	var point []byte
	_ = bitStr.ReadBytes(&point, len(bitStr))
	return ParseBitStringPublicKey(point)
}

// ParsePKCS8PrivateKey parses a PKCS#8 PrivateKeyInfo and returns an SM2 private key.
// Simplified: ignores optional parameters/publicKey fields inside ECPrivateKey.
func ParsePKCS8PrivateKey(der []byte) (*ecdsa.PrivateKey, error) {
	in := cryptobyte.String(der)
	var p8 cryptobyte.String
	if !in.ReadASN1(&p8, cryptoAsn1.SEQUENCE) || !in.Empty() {
		return nil, encodingAsn1.SyntaxError{Msg: "invalid PKCS#8 PrivateKeyInfo"}
	}
	var ver int64
	if !p8.ReadASN1Int64WithTag(&ver, cryptoAsn1.INTEGER) {
		return nil, encodingAsn1.SyntaxError{Msg: "missing version"}
	}
	var ai cryptobyte.String
	if !p8.ReadASN1(&ai, cryptoAsn1.SEQUENCE) {
		return nil, encodingAsn1.SyntaxError{Msg: "missing AlgorithmIdentifier"}
	}
	var alg encodingAsn1.ObjectIdentifier
	if !ai.ReadASN1ObjectIdentifier(&alg) || !alg.Equal(oidEcPublicKey) {
		return nil, encodingAsn1.StructuralError{Msg: "unexpected algorithm OID (want ecPublicKey)"}
	}
	var curveOID encodingAsn1.ObjectIdentifier
	if !ai.ReadASN1ObjectIdentifier(&curveOID) || !curveOID.Equal(oidSM2P256v1) {
		return nil, encodingAsn1.StructuralError{Msg: "unexpected or missing curve OID (want sm2p256v1)"}
	}
	var priOct cryptobyte.String
	if !p8.ReadASN1(&priOct, cryptoAsn1.OCTET_STRING) {
		return nil, encodingAsn1.SyntaxError{Msg: "missing privateKey"}
	}
	// ECPrivateKey (version, d)
	ec := priOct
	var ecSeq cryptobyte.String
	if !ec.ReadASN1(&ecSeq, cryptoAsn1.SEQUENCE) || !ec.Empty() {
		return nil, encodingAsn1.SyntaxError{Msg: "invalid ECPrivateKey"}
	}
	var ecVer int64
	if !ecSeq.ReadASN1Int64WithTag(&ecVer, cryptoAsn1.INTEGER) || ecVer != 1 {
		return nil, encodingAsn1.SyntaxError{Msg: "invalid ECPrivateKey version"}
	}
	var keyOct cryptobyte.String
	if !ecSeq.ReadASN1(&keyOct, cryptoAsn1.OCTET_STRING) {
		return nil, encodingAsn1.SyntaxError{Msg: "missing EC privateKey"}
	}
	return ParseBitStringPrivateKey(keyOct)
}

// ParseBitStringPublicKey parses a BIT_STRING PublicKeyInfo and returns an SM2 public key.
//
//go:inline
func ParseBitStringPublicKey(key []byte) (*ecdsa.PublicKey, error) {
	cv := NewCurve()
	pLen := (cv.Params().BitSize + 7) / 8
	if len(key) != 1+2*pLen || key[0] != 0x04 {
		return nil, encodingAsn1.SyntaxError{Msg: "unsupported or invalid EC point"}
	}
	x := new(big.Int).SetBytes(key[1 : 1+pLen])
	y := new(big.Int).SetBytes(key[1+pLen:])
	if !cv.IsOnCurve(x, y) {
		return nil, encodingAsn1.StructuralError{Msg: "point not on curve"}
	}
	return &ecdsa.PublicKey{Curve: cv, X: x, Y: y}, nil
}

// ParseBitStringPrivateKey parses a BIT_STRING PrivateKeyInfo and returns an SM2 private key.
//
//go:inline
func ParseBitStringPrivateKey(key []byte) (*ecdsa.PrivateKey, error) {
	cv := NewCurve()
	d := new(big.Int).SetBytes(key)
	x, y := cv.ScalarBaseMult(key)
	return &ecdsa.PrivateKey{PublicKey: ecdsa.PublicKey{Curve: cv, X: x, Y: y}, D: d}, nil
}
