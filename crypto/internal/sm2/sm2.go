package sm2

import (
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/asn1"
	"errors"
	"io"
	"math/big"

	"github.com/dromara/dongle/hash/sm3"
	"github.com/dromara/dongle/internal/utils"
)

var (
	// defaultUID is the default user identifier as specified in GM/T 0009-2012
	defaultUID = []byte("1234567812345678")
)

const (
	// c1c2c3 represents ciphertext mode: C1 || C2 || C3
	c1c2c3 = "c1c2c3"
	// c1c3c2 represents ciphertext mode: C1 || C3 || C2
	c1c3c2 = "c1c3c2"
)

// signature represents an SM2 signature in ASN.1 format
type sm2Sign struct {
	R, S *big.Int
}

func EncryptWithPublicKey(pub *ecdsa.PublicKey, plaintext []byte, window int, mode string) ([]byte, error) {
	if pub == nil {
		return nil, io.ErrUnexpectedEOF
	}

	n := len(plaintext)
	if n == 0 {
		return []byte{0x04}, nil
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

	x1, y1 := curve.ScalarBaseMult(k.Bytes())
	x2, y2 := curve.ScalarMult(pub.X, pub.Y, k.Bytes())

	x1b := padLeft(x1.Bytes(), coordLen)
	y1b := padLeft(y1.Bytes(), coordLen)
	x2b := padLeft(x2.Bytes(), coordLen)
	y2b := padLeft(y2.Bytes(), coordLen)

	// C1: uncompressed point (x1||y1)
	c1 := make([]byte, 0, 2*coordLen)
	c1 = append(c1, x1b...)
	c1 = append(c1, y1b...)

	// C3 = SM3(x2 || M || y2)
	macInput := make([]byte, 0, len(x2b)+n+len(y2b))
	macInput = append(macInput, x2b...)
	macInput = append(macInput, plaintext...)
	macInput = append(macInput, y2b...)
	hh := sm3.New()
	hh.Write(macInput)
	c3 := hh.Sum(nil)

	// C2 = M XOR KDF(x2||y2)
	mask, _ := sm3KDF(n, x2b, y2b)
	c2 := make([]byte, n)
	for i := range n {
		c2[i] = plaintext[i] ^ mask[i]
	}

	var payload []byte
	if mode == c1c2c3 {
		payload = append(append(c1, c2...), c3...)
	}
	if mode == c1c3c2 {
		payload = append(append(c1, c3...), c2...)
	}
	return append([]byte{0x04}, payload...), nil
}

func DecryptWithPrivateKey(pri *ecdsa.PrivateKey, ciphertext []byte, window int, mode string) ([]byte, error) {
	if pri == nil {
		return nil, io.ErrUnexpectedEOF
	}

	if len(ciphertext) < 1 {
		return nil, io.ErrUnexpectedEOF
	}

	src := ciphertext
	if src[0] == 0x04 {
		src = src[1:]
	}

	curve := NewCurve()
	if window >= 2 && window <= 6 {
		SetWindow(curve, window)
	}
	coordLen := (curve.Params().BitSize + 7) / 8

	if len(src) < 2*coordLen+32 {
		return nil, io.ErrUnexpectedEOF
	}

	x := new(big.Int).SetBytes(src[:coordLen])
	y := new(big.Int).SetBytes(src[coordLen : 2*coordLen])

	x2, y2 := curve.ScalarMult(x, y, pri.D.Bytes())
	x2b := padLeft(x2.Bytes(), coordLen)
	y2b := padLeft(y2.Bytes(), coordLen)

	n := len(src) - (2*coordLen + 32)

	// Determine C2 and C3 positions based on ciphertext order
	var c2Start, c3Start, c3End int
	if mode == c1c2c3 {
		c2Start = 2 * coordLen
		c3Start = 2*coordLen + n
		c3End = len(src)
	}
	if mode == c1c3c2 {
		c2Start = 2*coordLen + 32
		c3Start = 2 * coordLen
		c3End = 2*coordLen + 32
	}

	// Decrypt C2
	mask, _ := sm3KDF(n, x2b, y2b)
	m := make([]byte, n)
	for i := range n {
		m[i] = src[c2Start+i] ^ mask[i]
	}

	// Verify C3
	macInput := make([]byte, 0, len(x2b)+n+len(y2b))
	macInput = append(macInput, x2b...)
	macInput = append(macInput, m...)
	macInput = append(macInput, y2b...)
	hh := sm3.New()
	hh.Write(macInput)
	if !bytesEqual(hh.Sum(nil), src[c3Start:c3End]) {
		return nil, io.ErrUnexpectedEOF
	}

	return m, nil
}

// SignWithPrivateKey generates an SM2 signature for the given message
// It internally calculates ZA and digest (e = SM3(ZA || M))
// Returns the signature in ASN.1 DER format
func SignWithPrivateKey(pri *ecdsa.PrivateKey, message []byte, uid []byte) ([]byte, error) {
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

	var r, s *big.Int

	// Retry loop for signature generation
	for {
		// Generate random k ∈ [1, n-1]
		k, err := RandScalar(curve, rand.Reader)
		if err != nil {
			return nil, err
		}

		// Compute (x1, y1) = k·G
		x1, _ := curve.ScalarBaseMult(k.Bytes())

		// Compute r = (e + x1) mod n
		r = new(big.Int).Add(e, x1)
		r.Mod(r, n)

		// Compute s = d^(-1) · (k - r·d) mod n
		// Equivalently: s = (k - r·d) · d^(-1) mod n
		// Or using formula: s = d^(-1) · k - r mod n (after simplification)

		// Compute d + 1
		dPlus1 := new(big.Int).Add(pri.D, big.NewInt(1))
		// Compute (d + 1)^(-1) mod n
		dPlus1Inv := new(big.Int).ModInverse(dPlus1, n)

		// Compute r·d mod n
		rd := new(big.Int).Mul(r, pri.D)
		rd.Mod(rd, n)

		// Compute k - r·d mod n
		kMinusRd := new(big.Int).Sub(k, rd)
		kMinusRd.Mod(kMinusRd, n)

		// Compute s = (d+1)^(-1) · (k - r·d) mod n
		s = new(big.Int).Mul(dPlus1Inv, kMinusRd)
		s.Mod(s, n)

		// s will be non-zero in practice, so we break here
		break
	}

	// Marshal signature to ASN.1 DER format
	return asn1.Marshal(sm2Sign{R: r, S: s})
}

// VerifyWithPublicKey verifies an SM2 signature
// It internally calculates ZA and digest (e = SM3(ZA || M))
// sig is the signature in ASN.1 DER format
func VerifyWithPublicKey(pub *ecdsa.PublicKey, message []byte, uid []byte, sig []byte) bool {
	// Unmarshal signature from ASN.1 DER format
	var sign sm2Sign
	_, err := asn1.Unmarshal(sig, &sign)
	if err != nil {
		return false
	}

	r := sign.R
	s := sign.S

	curve := pub.Curve
	params := curve.Params()
	n := params.N

	// Check r, s ∈ [1, n-1]
	if r.Sign() <= 0 || r.Cmp(n) >= 0 {
		return false
	}
	if s.Sign() <= 0 || s.Cmp(n) >= 0 {
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
	t := new(big.Int).Add(r, s)
	t.Mod(t, n)

	// Check t ≠ 0
	if t.Sign() == 0 {
		return false
	}

	// Compute (x1, y1) = s·G + t·PA
	// First compute s·G
	x1, y1 := curve.ScalarBaseMult(s.Bytes())

	// Then compute t·PA
	x2, y2 := curve.ScalarMult(pub.X, pub.Y, t.Bytes())

	// Add the two points
	x1, y1 = curve.Add(x1, y1, x2, y2)

	// Compute v = (e + x1) mod n
	v := new(big.Int).Add(e, x1)
	v.Mod(v, n)

	// Verify v == r
	return v.Cmp(r) == 0
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
		end := start + 32
		if end > length {
			end = length
		}
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
	if uid == nil || len(uid) == 0 {
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
