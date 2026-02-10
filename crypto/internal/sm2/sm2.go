package sm2

import (
	"crypto/ecdsa"
	"crypto/rand"
	"errors"
	"io"
	"math/big"

	"github.com/dromara/dongle/hash/sm3"
	"github.com/dromara/dongle/internal/utils"
	"golang.org/x/crypto/cryptobyte"
	cryptoAsn1 "golang.org/x/crypto/cryptobyte/asn1"
)

var (
	// defaultUID is the default user identifier as specified in GM/T 0009-2012
	defaultUID = []byte("1234567812345678")
)

const (
	// c1c2c3 represents ciphertext mode: C1 || C2 || C3 in bytes
	c1c2c3 = "c1c2c3"
	// c1c3c2 represents ciphertext mode: C1 || C3 || C2 in bytes
	c1c3c2 = "c1c3c2"
	// asn1_c1c2c3 represents ciphertext mode: C1 || C2 || C3 in ASN1
	asn1_c1c2c3 = "asn1_c1c2c3"
	// asn1_c1c3c2 represents ciphertext mode: C1 || C3 || C2 in ASN1
	asn1_c1c3c2 = "asn1_c1c3c2"

	sm2SignASN1  uint8 = 0
	sm2SignBytes uint8 = 1
)

// sm2Cipher represents an SM2 ciphertext structure
type sm2Cipher struct {
	keyX *big.Int
	keyY *big.Int
	text []byte // C2
	hash []byte // C3
}

func sm2CipherFromBytes(mode string, payload []byte, coordLen int) (*sm2Cipher, error) {
	src := new(sm2Cipher)
	switch mode {
	case asn1_c1c2c3, asn1_c1c3c2:
		child := cryptobyte.String(payload)
		if !child.ReadASN1(&child, cryptoAsn1.SEQUENCE) || child.Empty() {
			return nil, errors.New("unexpected data")
		}

		keyX, keyY, text, hash := new(cryptobyte.String), new(cryptobyte.String), new(cryptobyte.String), new(cryptobyte.String)
		if !(child.ReadASN1(keyX, cryptoAsn1.INTEGER) &&
			child.ReadASN1(keyY, cryptoAsn1.INTEGER) &&
			child.ReadASN1(text, cryptoAsn1.OCTET_STRING) &&
			child.ReadASN1(hash, cryptoAsn1.OCTET_STRING)) {
			return nil, errors.New("unexpected data")
		}
		src.keyX, src.keyY = new(big.Int).SetBytes(*keyX), new(big.Int).SetBytes(*keyY)

		if mode == asn1_c1c2c3 {
			src.text = *text
			src.hash = *hash
		} else {
			src.text = *hash
			src.hash = *text
		}
	case c1c2c3, c1c3c2:
		src.keyX = new(big.Int).SetBytes(payload[:coordLen])
		src.keyY = new(big.Int).SetBytes(payload[coordLen : 2*coordLen])
		if mode == c1c2c3 {
			src.text = payload[2*coordLen : len(payload)-32]
			src.hash = payload[len(payload)-32:]
		} else {
			src.text = payload[2*coordLen+32:]
			src.hash = payload[2*coordLen : 2*coordLen+32]
		}
	default:
		return nil, errors.New("unsupported option")
	}
	return src, nil
}

func (s *sm2Cipher) toBytes(mode string, coordLen int) ([]byte, error) {
	switch mode {
	case asn1_c1c2c3, asn1_c1c3c2:
		var payload cryptobyte.Builder
		payload.AddASN1(cryptoAsn1.SEQUENCE, func(child *cryptobyte.Builder) {
			child.AddASN1BigInt(s.keyX)
			child.AddASN1BigInt(s.keyY)
			if mode == asn1_c1c2c3 {
				child.AddASN1OctetString(s.text)
				child.AddASN1OctetString(s.hash)
			} else {
				child.AddASN1OctetString(s.hash)
				child.AddASN1OctetString(s.text)
			}
		})
		return payload.Bytes()
	case c1c2c3, c1c3c2:
		payload := make([]byte, 0, 1+coordLen*2+len(s.text)+32)
		payload = append(payload, 0x04)
		payload = append(payload, padLeft(s.keyX.Bytes(), coordLen)...)
		payload = append(payload, padLeft(s.keyY.Bytes(), coordLen)...)
		if mode == c1c2c3 {
			payload = append(payload, s.text...)
			payload = append(payload, s.hash...)
		} else {
			payload = append(payload, s.hash...)
			payload = append(payload, s.text...)
		}
		return payload, nil
	default:
		return nil, errors.New("unsupported option")
	}
}

// signature represents an SM2 signature in ASN.1 format
type sm2Sign struct {
	R, S *big.Int
}

func sm2SignFromBytes(mode uint8, sign []byte, coordLen int) (*sm2Sign, error) {
	src := new(sm2Sign)
	switch mode {
	case sm2SignASN1:
		child := cryptobyte.String(sign)
		if !child.ReadASN1(&child, cryptoAsn1.SEQUENCE) || child.Empty() {
			return nil, errors.New("unexpected data")
		}

		R, S := new(cryptobyte.String), new(cryptobyte.String)
		if !(child.ReadASN1(R, cryptoAsn1.INTEGER) &&
			child.ReadASN1(S, cryptoAsn1.INTEGER)) {
			return nil, errors.New("unexpected data")
		}
		src.R, src.S = new(big.Int).SetBytes(*R), new(big.Int).SetBytes(*S)

		return src, nil
	case sm2SignBytes:
		if len(sign) != 2*coordLen {
			return nil, errors.New("unexpected data")
		}
		src.R = new(big.Int).SetBytes(sign[:coordLen])
		src.S = new(big.Int).SetBytes(sign[coordLen : 2*coordLen])
		return src, nil
	default:
		return nil, errors.New("unsupported option")
	}
}

func (s *sm2Sign) toBytes(mode uint8, coordLen int) ([]byte, error) {
	switch mode {
	case sm2SignASN1:
		var payload cryptobyte.Builder
		payload.AddASN1(cryptoAsn1.SEQUENCE, func(child *cryptobyte.Builder) {
			child.AddASN1BigInt(s.R)
			child.AddASN1BigInt(s.S)
		})
		return payload.Bytes()
	case sm2SignBytes:
		payload := make([]byte, 0, 2*coordLen)
		payload = append(payload, padLeft(s.R.Bytes(), coordLen)...)
		payload = append(payload, padLeft(s.S.Bytes(), coordLen)...)
		return payload, nil
	default:
		return nil, errors.New("unsupported option")
	}
}

func EncryptWithPublicKey(pub *ecdsa.PublicKey, plaintext []byte, window int, mode string) ([]byte, error) {
	if pub == nil {
		return nil, io.ErrUnexpectedEOF
	}

	src := sm2Cipher{keyX: new(big.Int), keyY: new(big.Int), text: append([]byte{}, plaintext...)}
	if len(src.text) == 0 {
		return src.toBytes(mode, 0)
	}

	curve := NewCurve()
	if window >= 2 && window <= 6 {
		SetWindow(curve, window)
	}
	coordLen := (curve.Params().BitSize + 7) / 8

	k, err := RandScalar(curve, rand.Reader)
	if err != nil {
		return nil, err
	}

	src.keyX, src.keyY = curve.ScalarBaseMult(k.Bytes())
	x2, y2 := curve.ScalarMult(pub.X, pub.Y, k.Bytes())

	x2b := padLeft(x2.Bytes(), coordLen)
	y2b := padLeft(y2.Bytes(), coordLen)

	// C3 = SM3(x2 || M || y2)
	macInput := make([]byte, 0, len(x2b)+len(src.text)+len(y2b))
	macInput = append(macInput, x2b...)
	macInput = append(macInput, plaintext...)
	macInput = append(macInput, y2b...)
	hh := sm3.New()
	hh.Write(macInput)
	src.hash = hh.Sum(nil)

	// C2 = M XOR KDF(x2||y2)
	mask, _ := sm3KDF(len(src.text), x2b, y2b)
	for i := range src.text {
		src.text[i] ^= mask[i]
	}

	return src.toBytes(mode, coordLen)
}

func DecryptWithPrivateKey(pri *ecdsa.PrivateKey, ciphertext []byte, window int, mode string) ([]byte, error) {
	if pri == nil {
		return nil, io.ErrUnexpectedEOF
	}

	if len(ciphertext) < 1 {
		return nil, io.ErrUnexpectedEOF
	}

	if ciphertext[0] == 0x04 {
		ciphertext = ciphertext[1:]
	}

	curve := NewCurve()
	if window >= 2 && window <= 6 {
		SetWindow(curve, window)
	}
	coordLen := (curve.Params().BitSize + 7) / 8

	if len(ciphertext) < 2*coordLen+32 {
		return nil, io.ErrUnexpectedEOF
	}

	src, err := sm2CipherFromBytes(mode, ciphertext, coordLen)
	if err != nil {
		return nil, err
	}

	x2, y2 := curve.ScalarMult(src.keyX, src.keyY, pri.D.Bytes())
	x2b := padLeft(x2.Bytes(), coordLen)
	y2b := padLeft(y2.Bytes(), coordLen)

	// Decrypt C2
	mask, _ := sm3KDF(len(src.text), x2b, y2b)
	for i := range src.text {
		src.text[i] ^= mask[i]
	}

	// Verify C3
	macInput := make([]byte, 0, len(x2b)+len(src.text)+len(y2b))
	macInput = append(macInput, x2b...)
	macInput = append(macInput, src.text...)
	macInput = append(macInput, y2b...)
	hh := sm3.New()
	hh.Write(macInput)
	if !bytesEqual(hh.Sum(nil), src.hash) {
		return nil, io.ErrUnexpectedEOF
	}

	return src.text, nil
}

// SignWithPrivateKey generates an SM2 signature for the given message
// It internally calculates ZA and digest (e = SM3(ZA || M))
func SignWithPrivateKey(pri *ecdsa.PrivateKey, message []byte, uid []byte, mode uint8) ([]byte, error) {
	curve := pri.Curve
	params := curve.Params()
	n := params.N

	if pri.D.Sign() == 0 || pri.D.Cmp(n) >= 0 {
		return nil, errors.New("invalid private key")
	}

	// Calculate ZA = SM3(ENTLA || IDA || a || b || xG || yG || xA || yA)
	zaInput := getZA(&pri.PublicKey, uid)
	h := sm3.New()
	h.Write(zaInput)
	za := h.Sum(nil)

	// Calculate e = SM3(ZA || M)
	h.Reset()
	h.Write(za)
	h.Write(message)
	digest := h.Sum(nil)

	// Convert digest to integer e
	e := new(big.Int).SetBytes(digest)

	src := new(sm2Sign)

	// The retry loop for signature generation has been canceled here,
	// because the probability of generating an invalid signature is very small,
	// the probability of r.Sign() == 0 or s.Sign() == 0 occurring is
	// 1/115792089210356248756420345214020892766061623724957744567843809356293439045923
	// If an invalid signature is really generated, then you absolutely have to buy a lottery ticket!!!

	// Generate random k ∈ [1, n-1]
	k, err := RandScalar(curve, rand.Reader)
	if err != nil {
		return nil, err
	}

	// Compute (x1, y1) = k·G
	x1, _ := curve.ScalarBaseMult(k.Bytes())

	// Compute r = (e + x1) mod n
	src.R = new(big.Int).Add(e, x1)
	src.R.Mod(src.R, n)

	// Compute s = d^(-1) · (k - r·d) mod n
	// Equivalently: s = (k - r·d) · d^(-1) mod n
	// Or using formula: s = d^(-1) · k - r mod n (after simplification)

	// Compute d + 1
	dPlus1 := new(big.Int).Add(pri.D, big.NewInt(1))
	// Compute (d + 1)^(-1) mod n
	dPlus1Inv := new(big.Int).ModInverse(dPlus1, n)

	// Compute r·d mod n
	rd := new(big.Int).Mul(src.R, pri.D)
	rd.Mod(rd, n)

	// Compute k - r·d mod n
	kMinusRd := new(big.Int).Sub(k, rd)
	kMinusRd.Mod(kMinusRd, n)

	// Compute s = (d+1)^(-1) · (k - r·d) mod n
	src.S = new(big.Int).Mul(dPlus1Inv, kMinusRd)
	src.S.Mod(src.S, n)

	return src.toBytes(mode, (params.BitSize+7)/8)
}

// VerifyWithPublicKey verifies an SM2 signature
// It internally calculates ZA and digest (e = SM3(ZA || M))
func VerifyWithPublicKey(pub *ecdsa.PublicKey, message []byte, uid []byte, sig []byte, mode uint8) bool {
	curve := pub.Curve
	params := curve.Params()
	n := params.N

	sign, err := sm2SignFromBytes(mode, sig, (params.BitSize+7)/8)
	if err != nil {
		return false
	}

	// Check r, s ∈ [1, n-1]
	if sign.R.Sign() <= 0 || sign.R.Cmp(n) >= 0 {
		return false
	}
	if sign.S.Sign() <= 0 || sign.S.Cmp(n) >= 0 {
		return false
	}

	// Calculate ZA = SM3(ENTLA || IDA || a || b || xG || yG || xA || yA)
	zaInput := getZA(pub, uid)
	h := sm3.New()
	h.Write(zaInput)
	za := h.Sum(nil)

	// Calculate e = SM3(ZA || M)
	h.Reset()
	h.Write(za)
	h.Write(message)
	digest := h.Sum(nil)

	// Convert digest to integer e
	e := new(big.Int).SetBytes(digest)

	// Compute t = (r + s) mod n
	t := new(big.Int).Add(sign.R, sign.S)
	t.Mod(t, n)

	// Check t ≠ 0
	if t.Sign() == 0 {
		return false
	}

	// Compute (x1, y1) = s·G + t·PA
	// First compute s·G
	x1, y1 := curve.ScalarBaseMult(sign.S.Bytes())

	// Then compute t·PA
	x2, y2 := curve.ScalarMult(pub.X, pub.Y, t.Bytes())

	// Add the two points
	x1, y1 = curve.Add(x1, y1, x2, y2)

	// Compute v = (e + x1) mod n
	v := new(big.Int).Add(e, x1)
	v.Mod(v, n)

	// Verify v == r
	return v.Cmp(sign.R) == 0
}

// padLeft left-pads b with zeros to reach size bytes.
func padLeft(b []byte, size int) []byte {
	if len(b) >= size {
		return b
	}
	out := make([]byte, size)
	copy(out[size-len(b):], b)
	return out
}

// sm3KDF derives length bytes using SM3 over the provided parts.
func sm3KDF(length int, parts ...[]byte) (out []byte, ok bool) {
	out = make([]byte, length) // Pre-allocate output buffer
	ct := 1
	h := sm3.New()
	blocks := (length + 31) / 32
	for i := range blocks {
		h.Reset()
		for _, p := range parts {
			h.Write(p)
		}
		h.Write(utils.Int2Bytes(ct))
		sum := h.Sum(nil)
		start := i * 32
		end := min(start+32, length)
		copy(out[start:end], sum[:end-start])
		ct++
	}
	return out, true
}

// bytesEqual compares two byte slices in constant time.
func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var v byte
	for i := range a {
		v |= a[i] ^ b[i]
	}
	return v == 0
}

// getZA computes the ZA value for SM2 signature
// ZA = SM3(ENTLA || IDA || a || b || xG || yG || xA || yA)
func getZA(pub *ecdsa.PublicKey, uid []byte) []byte {
	if len(uid) == 0 {
		uid = defaultUID
	}

	params := pub.Curve.Params()
	coordLen := (params.BitSize + 7) / 8

	// For SM2 curve, a = p - 3
	a := new(big.Int).Sub(params.P, big.NewInt(3))

	// Build ZA input
	za := make([]byte, 0, 2+len(uid)+coordLen*6)

	// ENTLA: bit length of IDA (2 bytes)
	entla := uint16(len(uid) * 8)
	za = append(za, byte(entla>>8), byte(entla))

	// IDA: user identifier
	za = append(za, uid...)

	// a: curve coefficient (padded to coordLen)
	aBytes := a.Bytes()
	za = append(za, padLeft(aBytes, coordLen)...)

	// b: curve coefficient
	bBytes := params.B.Bytes()
	za = append(za, padLeft(bBytes, coordLen)...)

	// xG, yG: base point coordinates
	gxBytes := params.Gx.Bytes()
	gyBytes := params.Gy.Bytes()
	za = append(za, padLeft(gxBytes, coordLen)...)
	za = append(za, padLeft(gyBytes, coordLen)...)

	// xA, yA: public key coordinates
	xBytes := pub.X.Bytes()
	yBytes := pub.Y.Bytes()
	za = append(za, padLeft(xBytes, coordLen)...)
	za = append(za, padLeft(yBytes, coordLen)...)

	// Return the prepared data that needs to be hashed with SM3
	return za
}
