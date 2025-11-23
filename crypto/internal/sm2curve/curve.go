package sm2curve

import (
	"crypto/elliptic"
	"crypto/rand"
	"encoding/asn1"
	"io"
	"math/big"
	"sync"
)

// Ensure *curve implements elliptic.Curve interface.
var _ elliptic.Curve = (*curve)(nil)

// ASN.1 OIDs for SM2.
var (
	oidEcPublicKey = asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}
	oidSM2P256v1   = asn1.ObjectIdentifier{1, 2, 156, 10197, 1, 301}
)

// curve implements SM2-P-256 using Jacobian coordinates with wNAF acceleration.
type curve struct {
	params elliptic.CurveParams
	a      *big.Int // Curve coefficient a = p - 3
	w      int      // wNAF window size (2-6)
}

// pointField represents a Jacobian point using field elements.
// Affine coordinates: (x, y) = (X/Z², Y/Z³).
type pointField struct {
	x, y, z field
}

// New returns a new SM2-P-256 curve instance.
func New() elliptic.Curve {
	p, _ := new(big.Int).SetString("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF", 16)
	a := new(big.Int).Sub(new(big.Int).Set(p), big.NewInt(3))
	b, _ := new(big.Int).SetString("28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93", 16)
	n, _ := new(big.Int).SetString("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123", 16)
	gx, _ := new(big.Int).SetString("32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7", 16)
	gy, _ := new(big.Int).SetString("BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0", 16)
	c := &curve{params: elliptic.CurveParams{}}
	c.params.P = p
	c.params.N = n
	c.params.B = b
	c.params.Gx = gx
	c.params.Gy = gy
	c.params.BitSize = 256
	c.params.Name = "SM2-P-256"
	c.a = a
	c.w = 4
	return c
}

// Params returns the curve parameters.
func (c *curve) Params() *elliptic.CurveParams { return &c.params }

// mod computes x mod p.
func (c *curve) mod(x *big.Int) *big.Int { return x.Mod(x, c.params.P) }

// add computes (x + y) mod p.
func (c *curve) add(x, y *big.Int) *big.Int {
	bigInt := getBigInt()
	bigInt.Add(x, y)
	return c.mod(bigInt)
}

// sub computes (x - y) mod p.
func (c *curve) sub(x, y *big.Int) *big.Int {
	bigInt := getBigInt()
	bigInt.Sub(x, y)
	return c.mod(bigInt)
}

// mul computes (x × y) mod p.
func (c *curve) mul(x, y *big.Int) *big.Int {
	bigInt := getBigInt()
	bigInt.Mul(x, y)
	return c.mod(bigInt)
}

// sqr computes x² mod p.
func (c *curve) sqr(x *big.Int) *big.Int { return c.mul(x, x) }

// inv computes x⁻¹ mod p.
func (c *curve) inv(x *big.Int) *big.Int {
	bigInt := getBigInt()
	bigInt.ModInverse(x, c.params.P)
	return bigInt
}

// IsOnCurve checks if point (x, y) satisfies the curve equation y^2 = x^3 + ax + b.
func (c *curve) IsOnCurve(x, y *big.Int) bool {
	if x == nil || y == nil {
		return false
	}
	y2 := c.sqr(y)
	x3 := c.mul(c.sqr(x), x)
	ax := c.mul(c.a, x)
	rhs := c.add(c.add(x3, ax), c.params.B)
	return y2.Cmp(rhs) == 0
}

// Add computes (x1, y1) + (x2, y2) in affine coordinates.
// Returns (nil, nil) for point at infinity.
func (c *curve) Add(x1, y1, x2, y2 *big.Int) (*big.Int, *big.Int) {
	if x1 == nil || y1 == nil {
		return new(big.Int).Set(x2), new(big.Int).Set(y2)
	}
	if x2 == nil || y2 == nil {
		return new(big.Int).Set(x1), new(big.Int).Set(y1)
	}
	if x1.Cmp(x2) == 0 {
		ySum := new(big.Int).Add(y1, y2)
		ySum.Mod(ySum, c.params.P)
		if ySum.Sign() == 0 {
			return nil, nil
		}
		return c.Double(x1, y1)
	}
	num := c.sub(y2, y1)
	den := c.sub(x2, x1)
	denInv := c.inv(den)
	lam := c.mul(num, denInv)
	x3 := c.sub(c.sub(c.sqr(lam), x1), x2)
	y3 := c.sub(c.mul(lam, c.sub(x1, x3)), y1)
	return x3, y3
}

// Double computes 2×(x1, y1) in affine coordinates.
// Returns (nil, nil) for point at infinity.
func (c *curve) Double(x1, y1 *big.Int) (*big.Int, *big.Int) {
	if y1 == nil || y1.Sign() == 0 {
		return nil, nil
	}
	slope := c.mul(big.NewInt(3), c.sqr(x1))
	num := c.add(slope, c.a)
	den := c.add(y1, y1)
	denInv := c.inv(den)
	lam := c.mul(num, denInv)
	x3 := c.sub(c.sqr(lam), c.add(x1, x1))
	y3 := c.sub(c.mul(lam, c.sub(x1, x3)), y1)
	return x3, y3
}

// ScalarBaseMult computes k×G using wNAF with precomputed table.
func (c *curve) ScalarBaseMult(k []byte) (*big.Int, *big.Int) {
	if len(k) == 0 {
		return nil, nil
	}

	kInt := new(big.Int).SetBytes(k)
	if kInt.Sign() == 0 {
		return nil, nil
	}

	w := c.w
	if w < 2 || w > 6 {
		w = 4
	}

	table := c.getBaseTable(w)
	naf := toWNAF(kInt, w)
	result := c.scalarMultWNAFField(table, naf)
	return c.jacToAffine(&result)
}

// ScalarMult computes k×B using wNAF.
// Returns (nil, nil) for point at infinity.
func (c *curve) ScalarMult(Bx, By *big.Int, k []byte) (*big.Int, *big.Int) {
	if len(k) == 0 {
		return nil, nil
	}

	kInt := new(big.Int).SetBytes(k)
	if kInt.Sign() == 0 {
		return nil, nil
	}

	w := c.w
	if w < 2 || w > 6 {
		w = 4
	}

	table := c.precomputeTable(Bx, By, w)
	naf := toWNAF(kInt, w)
	result := c.scalarMultWNAFField(table, naf)

	return c.jacToAffine(&result)
}

var (
	baseTableCache     = make(map[int][][3]field)
	baseTableCacheLock sync.RWMutex
)

// getBaseTable returns cached or creates base point table.
func (c *curve) getBaseTable(w int) [][3]field {
	baseTableCacheLock.Lock()
	defer baseTableCacheLock.Unlock()

	table, exists := baseTableCache[w]
	if exists {
		return table
	}
	table = c.precomputeTable(c.params.Gx, c.params.Gy, w)
	baseTableCache[w] = table

	return table
}

// precomputeTable creates table of odd multiples: B, 3B, 5B, ..., (2^(w-1)-1)×B.
func (c *curve) precomputeTable(Bx, By *big.Int, w int) [][3]field {
	tableSize := 1 << uint(w-1)
	table := make([][3]field, tableSize)

	bx := *fromBigInt(Bx)
	by := *fromBigInt(By)
	bz := field{limbs: [4]uint64{1, 0, 0, 0}}
	table[0] = [3]field{bx, by, bz}

	var twoB pointField
	c.pointDoubleField(&twoB, &pointField{bx, by, bz})
	for i := 1; i < tableSize; i++ {
		var curr pointField
		curr.x, curr.y, curr.z = table[i-1][0], table[i-1][1], table[i-1][2]

		var next pointField
		c.pointAddField(&next, &curr, &twoB)

		table[i] = [3]field{next.x, next.y, next.z}
	}

	return table
}

// scalarMultWNAFField performs wNAF scalar multiplication.
func (c *curve) scalarMultWNAFField(table [][3]field, naf []int8) pointField {
	var result pointField

	for i := len(naf) - 1; i >= 0; i-- {
		if !result.z.isZero() {
			c.pointDoubleField(&result, &result)
		}

		digit := naf[i]
		if digit != 0 {
			abs := int(digit)
			if abs < 0 {
				abs = -abs
			}
			idx := (abs - 1) / 2

			if digit > 0 {
				if result.z.isZero() {
					result.x = table[idx][0]
					result.y = table[idx][1]
					result.z = table[idx][2]
				} else {
					tablePoint := pointField{table[idx][0], table[idx][1], table[idx][2]}
					c.pointAddField(&result, &result, &tablePoint)
				}
			} else {
				var negY field
				negY.neg(&table[idx][1])
				tablePoint := pointField{table[idx][0], negY, table[idx][2]}
				c.pointAddField(&result, &result, &tablePoint)
			}
		}
	}

	return result
}

// pointAddField computes out = p1 + p2 in Jacobian coordinates.
func (c *curve) pointAddField(out, p1, p2 *pointField) {
	if p1.z.isZero() {
		*out = *p2
		return
	}
	if p2.z.isZero() {
		*out = *p1
		return
	}

	p1x, p1y, p1z := p1.x, p1.y, p1.z
	p2x, p2y, p2z := p2.x, p2.y, p2.z

	var z1z1, z2z2, u1, u2, s1, s2, h, r field

	z1z1.mul(&p1z, &p1z)
	z2z2.mul(&p2z, &p2z)

	u1.mul(&p1x, &z2z2)
	u2.mul(&p2x, &z1z1)

	var t field
	t.mul(&p2z, &z2z2)
	s1.mul(&p1y, &t)

	t.mul(&p1z, &z1z1)
	s2.mul(&p2y, &t)

	h.sub(&u2, &u1)
	r.sub(&s2, &s1)

	if h.isZero() {
		if r.isZero() {
			c.pointDoubleField(out, p1)
		} else {
			*out = pointField{}
		}
		return
	}

	var hh, hhh, v field
	hh.mul(&h, &h)
	hhh.mul(&h, &hh)
	v.mul(&u1, &hh)

	var rr, vv field
	rr.mul(&r, &r)
	vv.add(&v, &v) // 2*v

	out.x.sub(&rr, &hhh)
	out.x.sub(&out.x, &vv)

	var t1, t2 field
	t1.sub(&v, &out.x)
	t2.mul(&r, &t1)
	t1.mul(&s1, &hhh)
	out.y.sub(&t2, &t1)

	t1.mul(&p1z, &p2z)
	out.z.mul(&t1, &h)
}

// pointDoubleField computes 2×p in Jacobian coordinates.
func (c *curve) pointDoubleField(out, p *pointField) {
	if p.y.isZero() || p.z.isZero() {
		*out = pointField{}
		return
	}

	px, py, pz := p.x, p.y, p.z

	// B = Y1^2
	var b field
	b.mul(&py, &py)

	// C = B^2 = Y1^4
	var cc field
	cc.mul(&b, &b)

	// S = 4*X1*B
	var xb field
	xb.mul(&px, &b)
	var s field
	s.add(&xb, &xb) // 2*X1*B
	s.add(&s, &s)   // 4*X1*B

	// M = 3*(X1-Z1^2)*(X1+Z1^2) for a=-3
	var z1sq field
	z1sq.mul(&pz, &pz)
	var xMinusZ, xPlusZ field
	xMinusZ.sub(&px, &z1sq)
	xPlusZ.add(&px, &z1sq)
	var temp field
	temp.mul(&xMinusZ, &xPlusZ)
	var m field
	m.add(&temp, &temp) // 2*temp
	m.add(&m, &temp)    // 3*temp

	// X3 = M^2 - 2*S
	var mm field
	mm.mul(&m, &m)
	var twoS field
	twoS.add(&s, &s)
	out.x.sub(&mm, &twoS)

	// Y3 = M*(S - X3) - 8*C
	var sMinusX3 field
	sMinusX3.sub(&s, &out.x)
	out.y.mul(&m, &sMinusX3)
	var eightC field
	eightC.add(&cc, &cc)         // 2*C
	eightC.add(&eightC, &eightC) // 4*C
	eightC.add(&eightC, &eightC) // 8*C
	out.y.sub(&out.y, &eightC)

	// Z3 = 2*Y1*Z1
	temp.mul(&py, &pz)
	out.z.add(&temp, &temp)
}

// jacToAffine converts Jacobian coordinates to affine.
func (c *curve) jacToAffine(p *pointField) (*big.Int, *big.Int) {
	if p.z.isZero() {
		return nil, nil
	}

	var zInv, zInv2, zInv3 field
	zInv.inv(&p.z)
	zInv2.mul(&zInv, &zInv)
	zInv3.mul(&zInv2, &zInv)

	var x, y field
	x.mul(&p.x, &zInv2)
	y.mul(&p.y, &zInv3)

	return toBigInt(&x), toBigInt(&y)
}

// toWNAF converts scalar k to wNAF form.
// Returns int8 slice with values in [-2^(w-1), 2^(w-1)], all odd.
func toWNAF(k *big.Int, w int) []int8 {
	if k.Sign() == 0 {
		return nil
	}
	if w < 2 || w > 6 {
		w = 4 // default
	}

	maxLen := max(k.BitLen()+1, 256)
	naf := make([]int8, 0, maxLen)

	kCopy := new(big.Int).Set(k)
	windowMask := big.NewInt((1 << uint(w)) - 1) // 2^w - 1
	halfWindow := big.NewInt(1 << uint(w-1))     // 2^(w-1)
	windowSize := big.NewInt(1 << uint(w))       // 2^w

	for kCopy.Sign() > 0 {
		if kCopy.Bit(0) == 0 {
			naf = append(naf, 0)
			kCopy.Rsh(kCopy, 1)
		} else {
			word := new(big.Int).And(kCopy, windowMask)

			if word.Cmp(halfWindow) < 0 {
				// kCopy = kCopy + word - 2^w
				naf = append(naf, int8(word.Int64()))
				kCopy.Sub(kCopy, word)
			} else {
				// kCopy = kCopy - word + 2^w
				negWord := new(big.Int).Sub(word, windowSize)
				naf = append(naf, int8(negWord.Int64()))
				kCopy.Sub(kCopy, negWord)
			}
			kCopy.Rsh(kCopy, 1)
		}
	}

	return naf
}

// SetWindow sets wNAF window size (2-6).
func SetWindow(cv elliptic.Curve, w int) {
	if c, ok := cv.(*curve); ok {
		if w >= 2 && w <= 6 {
			c.w = w
		}
	}
}

// RandScalar generates random scalar in [1, N-1] using rejection sampling.
func RandScalar(curve elliptic.Curve, random io.Reader) (*big.Int, error) {
	if random == nil {
		random = rand.Reader
	}
	params := curve.Params()
	byteLen := (params.BitSize + 7) / 8
	d := new(big.Int)
	for {
		b := make([]byte, byteLen)
		if _, err := io.ReadFull(random, b); err != nil {
			return nil, err
		}
		d.SetBytes(b)
		if d.Sign() != 0 && d.Cmp(params.N) < 0 {
			return d, nil
		}
	}
}
