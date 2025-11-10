package sm2curve

import (
	"crypto/elliptic"
	"crypto/rand"
	"encoding/asn1"
	"io"
	"math/big"
	"sync"
)

// OID constants for SM2 keys and curve.
var (
	oidEcPublicKey = asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}
	oidSM2P256v1   = asn1.ObjectIdentifier{1, 2, 156, 10197, 1, 301}
)

// curve implements SM2-P-256 using Jacobian coordinates with optional wNAF acceleration.
type curve struct {
	params elliptic.CurveParams
	a      *big.Int // curve coefficient a = p - 3
	w      int      // desired wNAF window (2..6)
	// Precomputed table for base point (lazy initialization)
	baseTable [][]*big.Int // [w][2^(w-1)] precomputed points in Jacobian coordinates
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

// SetWindow sets the wNAF window size (2..6) on the given curve.
func SetWindow(cv elliptic.Curve, w int) {
	if c, ok := cv.(*curve); ok {
		// Validate window size (2..6)
		if w >= 2 && w <= 6 {
			c.w = w
			// Clear base table to force recomputation with new window size
			c.baseTable = nil
		}
	}
}

// ensure that *Curve implements elliptic.Curve
var _ elliptic.Curve = (*curve)(nil)

// Params returns the curve parameters.
func (c *curve) Params() *elliptic.CurveParams { return &c.params }

// Field arithmetic helpers (optimized with object pool)
func (c *curve) mod(x *big.Int) *big.Int { return x.Mod(x, c.params.P) }
func (c *curve) add(x, y *big.Int) *big.Int {
	bigInt := getBigInt()
	bigInt.Add(x, y)
	return c.mod(bigInt)
}
func (c *curve) sub(x, y *big.Int) *big.Int {
	bigInt := getBigInt()
	bigInt.Sub(x, y)
	return c.mod(bigInt)
}
func (c *curve) mul(x, y *big.Int) *big.Int {
	bigInt := getBigInt()
	bigInt.Mul(x, y)
	return c.mod(bigInt)
}
func (c *curve) sqr(x *big.Int) *big.Int { return c.mul(x, x) }
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

// Add computes point addition (x1, y1) + (x2, y2) in affine coordinates.
// Returns point at infinity (nil, nil) if the result is the identity element.
func (c *curve) Add(x1, y1, x2, y2 *big.Int) (*big.Int, *big.Int) {
	if x1 == nil || y1 == nil {
		return new(big.Int).Set(x2), new(big.Int).Set(y2)
	}
	if x2 == nil || y2 == nil {
		return new(big.Int).Set(x1), new(big.Int).Set(y1)
	}
	if x1.Cmp(x2) == 0 {
		yy := new(big.Int).Add(y1, y2)
		yy.Mod(yy, c.params.P)
		if yy.Sign() == 0 {
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

// Double computes point doubling 2*(x1, y1) in affine coordinates.
// Returns (nil, nil) if y1 is zero or nil (point at infinity).
func (c *curve) Double(x1, y1 *big.Int) (*big.Int, *big.Int) {
	if y1 == nil || y1.Sign() == 0 {
		return nil, nil
	}
	threeX2 := c.mul(big.NewInt(3), c.sqr(x1))
	num := c.add(threeX2, c.a)
	den := c.add(y1, y1)
	denInv := c.inv(den)
	lam := c.mul(num, denInv)
	x3 := c.sub(c.sqr(lam), c.add(x1, x1))
	y3 := c.sub(c.mul(lam, c.sub(x1, x3)), y1)
	return x3, y3
}

// toJac converts affine coordinates (x, y) to Jacobian coordinates (X, Y, Z) where x=X/Z^2, y=Y/Z^3.
func (c *curve) toJac(x, y *big.Int) (*big.Int, *big.Int, *big.Int) {
	if x == nil || y == nil {
		return nil, nil, nil
	}
	return new(big.Int).Set(x), new(big.Int).Set(y), big.NewInt(1)
}

// fromJac converts Jacobian coordinates (X, Y, Z) to affine coordinates (x, y).
// Returns (nil, nil) for point at infinity (Z=0).
func (c *curve) fromJac(X, Y, Z *big.Int) (*big.Int, *big.Int) {
	if X == nil || Y == nil || Z == nil || Z.Sign() == 0 {
		return nil, nil
	}
	zInv := c.inv(Z)
	z2 := c.sqr(zInv)
	z3 := c.mul(z2, zInv)
	x := c.mul(X, z2)
	y := c.mul(Y, z3)
	return x, y
}

// jDouble performs point doubling in Jacobian coordinates.
// Returns (nil, nil, nil) for point at infinity.
func (c *curve) jDouble(X1, Y1, Z1 *big.Int) (*big.Int, *big.Int, *big.Int) {
	if Y1 == nil || Y1.Sign() == 0 || Z1 == nil {
		return nil, nil, nil
	}

	// Allocate temporary variables from pool
	B := c.sqr(Y1)
	C := c.sqr(B)

	tmp1 := c.mul(X1, B)
	S := c.mul(big.NewInt(4), tmp1)
	putBigInt(tmp1)

	Z1sq := c.sqr(Z1)
	xMinusZ := c.sub(X1, Z1sq)
	xPlusZ := c.add(X1, Z1sq)
	tmp2 := c.mul(xMinusZ, xPlusZ)
	M := c.mul(big.NewInt(3), tmp2)
	putBigInts(xMinusZ, xPlusZ, tmp2, Z1sq)

	tmp3 := c.sqr(M)
	tmp4 := c.mul(big.NewInt(2), S)
	X3 := c.sub(tmp3, tmp4)
	putBigInts(tmp3, tmp4)

	tmp5 := c.sub(S, X3)
	tmp6 := c.mul(M, tmp5)
	tmp7 := c.mul(big.NewInt(8), C)
	Y3 := c.sub(tmp6, tmp7)
	putBigInts(tmp5, tmp6, tmp7, B, C, S)

	tmp8 := c.mul(Y1, Z1)
	Z3 := c.mul(big.NewInt(2), tmp8)
	putBigInt(tmp8)

	return X3, Y3, Z3
}

// jAdd performs point addition in Jacobian coordinates.
// Handles special cases: identity elements and point doubling.
func (c *curve) jAdd(X1, Y1, Z1, X2, Y2, Z2 *big.Int) (*big.Int, *big.Int, *big.Int) {
	if Z1 == nil || Z1.Sign() == 0 {
		return new(big.Int).Set(X2), new(big.Int).Set(Y2), new(big.Int).Set(Z2)
	}
	if Z2 == nil || Z2.Sign() == 0 {
		return new(big.Int).Set(X1), new(big.Int).Set(Y1), new(big.Int).Set(Z1)
	}

	Z1Z1 := c.sqr(Z1)
	Z2Z2 := c.sqr(Z2)
	U1 := c.mul(X1, Z2Z2)
	U2 := c.mul(X2, Z1Z1)

	tmp1 := c.mul(Z2, Z2Z2)
	S1 := c.mul(Y1, tmp1)
	putBigInt(tmp1)

	tmp2 := c.mul(Z1, Z1Z1)
	S2 := c.mul(Y2, tmp2)
	putBigInt(tmp2)

	H := c.sub(U2, U1)
	R := c.sub(S2, S1)

	if H.Sign() == 0 {
		rIsZero := R.Sign() == 0
		putBigInts(Z1Z1, Z2Z2, U1, U2, S1, S2, H, R)
		if rIsZero {
			return c.jDouble(X1, Y1, Z1)
		}
		return nil, nil, nil
	}

	HH := c.sqr(H)
	HHH := c.mul(H, HH)
	V := c.mul(U1, HH)

	tmp3 := c.sqr(R)
	tmp4 := c.mul(big.NewInt(2), V)
	tmp5 := c.sub(tmp3, HHH)
	X3 := c.sub(tmp5, tmp4)
	putBigInts(tmp3, tmp4, tmp5)

	tmp6 := c.sub(V, X3)
	tmp7 := c.mul(R, tmp6)
	tmp8 := c.mul(S1, HHH)
	Y3 := c.sub(tmp7, tmp8)
	putBigInts(tmp6, tmp7, tmp8)

	tmp9 := c.mul(Z1, Z2)
	Z3 := c.mul(H, tmp9)
	putBigInts(tmp9)

	putBigInts(Z1Z1, Z2Z2, U1, U2, S1, S2, H, R, HH, HHH, V)

	return X3, Y3, Z3
}

// toWNAF converts a scalar k to its wNAF (windowed Non-Adjacent Form) representation.
// Returns a slice of int8 values, each in the range [-2^(w-1), 2^(w-1)] and odd.
func toWNAF(k *big.Int, w int) []int8 {
	if k.Sign() == 0 {
		return nil
	}
	if w < 2 || w > 6 {
		w = 4 // default
	}

	// Maximum length needed: bit length + 1 (for potential carry)
	maxLen := k.BitLen() + 1
	if maxLen < 256 {
		maxLen = 256
	}
	naf := make([]int8, 0, maxLen)

	kCopy := new(big.Int).Set(k)
	windowMask := big.NewInt((1 << uint(w)) - 1) // 2^w - 1
	halfWindow := big.NewInt(1 << uint(w-1))     // 2^(w-1)
	windowSize := big.NewInt(1 << uint(w))       // 2^w

	for kCopy.Sign() > 0 {
		if kCopy.Bit(0) == 0 {
			// Even: output 0
			naf = append(naf, 0)
			kCopy.Rsh(kCopy, 1)
		} else {
			// Odd: extract w bits
			word := new(big.Int).And(kCopy, windowMask)
			// Since kCopy.Bit(0)==1, word is guaranteed to be odd

			if word.Cmp(halfWindow) < 0 {
				// Positive odd number in range [1, 2^(w-1)-1]
				naf = append(naf, int8(word.Int64()))
				kCopy.Sub(kCopy, word)
			} else {
				// Negative odd number: subtract 2^w to get range [-2^(w-1)+1, -1]
				negWord := new(big.Int).Sub(word, windowSize)
				naf = append(naf, int8(negWord.Int64()))
				kCopy.Add(kCopy, negWord)
			}
			kCopy.Rsh(kCopy, 1)
		}
	}

	return naf
}

// ScalarBaseMult computes k*G using wNAF optimization with precomputed base table.
func (c *curve) ScalarBaseMult(k []byte) (*big.Int, *big.Int) {
	if len(k) == 0 {
		return nil, nil
	}

	// Use optimized implementation with field elements
	kInt := new(big.Int).SetBytes(k)
	if kInt.Sign() == 0 {
		return nil, nil
	}

	// Use fieldElement optimized scalar multiplication
	return c.optimizedScalarBaseMult(k)
}

// ScalarMult computes k*B using wNAF optimization.
// Returns (nil, nil) for k=0 (point at infinity).
func (c *curve) ScalarMult(Bx, By *big.Int, k []byte) (*big.Int, *big.Int) {
	if len(k) == 0 {
		return nil, nil
	}

	// Use optimized implementation with field elements
	kInt := new(big.Int).SetBytes(k)
	if kInt.Sign() == 0 {
		return nil, nil
	}

	// Use fieldElement optimized scalar multiplication
	return c.optimizedScalarMult(Bx, By, k)
}

// scalarMultWNAF performs scalar multiplication using wNAF representation.
// If useBaseTable is true and B is the base point, uses precomputed table.
func (c *curve) scalarMultWNAF(Bx, By *big.Int, k *big.Int, useBaseTable bool) (*big.Int, *big.Int) {
	w := c.w
	if w < 2 || w > 6 {
		w = 4
	}

	// Convert scalar to wNAF
	naf := toWNAF(k, w)
	if len(naf) == 0 {
		return nil, nil
	}

	// Precompute odd multiples of B: B, 3B, 5B, ..., (2^(w-1)-1)B
	tableSize := 1 << uint(w-1) // 2^(w-1)
	var table [][]*big.Int      // Jacobian coordinates [X, Y, Z] for each multiple

	if useBaseTable && Bx.Cmp(c.params.Gx) == 0 && By.Cmp(c.params.Gy) == 0 {
		// Use cached base table if available
		if len(c.baseTable) == 0 {
			c.precomputeBaseTable(w)
		}
		table = c.baseTable
	}

	// If no cached table, compute on the fly
	if table == nil {
		table = make([][]*big.Int, tableSize)
		BX, BY, BZ := c.toJac(Bx, By)
		table[0] = []*big.Int{new(big.Int).Set(BX), new(big.Int).Set(BY), new(big.Int).Set(BZ)}

		// Compute 2B, 3B, 4B, ...
		twoBX, twoBY, twoBZ := c.jDouble(BX, BY, BZ)
		for i := 1; i < tableSize; i++ {
			var x3, y3, z3 *big.Int
			if i == 1 {
				// 3B = 2B + B
				x3, y3, z3 = c.jAdd(twoBX, twoBY, twoBZ, BX, BY, BZ)
			} else {
				// (2i+1)B = (2i-1)B + 2B
				x3, y3, z3 = c.jAdd(table[i-1][0], table[i-1][1], table[i-1][2], twoBX, twoBY, twoBZ)
			}
			table[i] = []*big.Int{x3, y3, z3}
		}
	}

	// Initialize result to point at infinity (nil in Jacobian)
	var RX, RY, RZ *big.Int

	// Process wNAF from most significant to least significant
	for i := len(naf) - 1; i >= 0; i-- {
		if RX != nil {
			// Double the result
			RX, RY, RZ = c.jDouble(RX, RY, RZ)
		}

		digit := naf[i]
		if digit != 0 {
			absDigit := int(digit)
			if absDigit < 0 {
				absDigit = -absDigit
			}
			// Convert digit to table index: 1->0, 3->1, 5->2, 7->3, ...
			// For negative: -1->0, -3->1, -5->2, -7->3, ...
			idx := (absDigit - 1) / 2

			if digit > 0 {
				// Add table[idx]
				if RX == nil {
					RX = new(big.Int).Set(table[idx][0])
					RY = new(big.Int).Set(table[idx][1])
					RZ = new(big.Int).Set(table[idx][2])
				} else {
					RX, RY, RZ = c.jAdd(RX, RY, RZ, table[idx][0], table[idx][1], table[idx][2])
				}
			} else {
				// Subtract: add negative (add point with negated Y)
				// Note: The highest non-zero wNAF digit is always positive due to the algorithm,
				// so RX is never nil when processing negative digits
				negY := new(big.Int).Neg(table[idx][1])
				negY.Mod(negY, c.params.P)
				RX, RY, RZ = c.jAdd(RX, RY, RZ, table[idx][0], negY, table[idx][2])
			}
		}
	}

	// Convert from Jacobian to affine coordinates
	return c.fromJac(RX, RY, RZ)
}

// precomputeBaseTable precomputes odd multiples of the base point G.
func (c *curve) precomputeBaseTable(w int) {
	if w < 2 || w > 6 {
		w = 4
	}

	tableSize := 1 << uint(w-1) // 2^(w-1)
	c.baseTable = make([][]*big.Int, tableSize)

	GX, GY, GZ := c.toJac(c.params.Gx, c.params.Gy)
	c.baseTable[0] = []*big.Int{new(big.Int).Set(GX), new(big.Int).Set(GY), new(big.Int).Set(GZ)}

	// Compute 2G
	twoGX, twoGY, twoGZ := c.jDouble(GX, GY, GZ)

	// Compute 3G, 5G, 7G, ..., (2^(w-1)-1)G
	for i := 1; i < tableSize; i++ {
		var x3, y3, z3 *big.Int
		if i == 1 {
			// 3G = 2G + G
			x3, y3, z3 = c.jAdd(twoGX, twoGY, twoGZ, GX, GY, GZ)
		} else {
			// (2i+1)G = (2i-1)G + 2G
			x3, y3, z3 = c.jAdd(c.baseTable[i-1][0], c.baseTable[i-1][1], c.baseTable[i-1][2], twoGX, twoGY, twoGZ)
		}
		c.baseTable[i] = []*big.Int{x3, y3, z3}
	}
}

// RandScalar generates a random scalar d in [1, N-1] for the given curve.
// It uses rejection sampling with high-bit masking to avoid modulo bias.
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
		// Note: SM2 has BitSize=256, which is divisible by 8, so no masking needed
		d.SetBytes(b)
		if d.Sign() != 0 && d.Cmp(params.N) < 0 {
			return d, nil
		}
	}
}

// =============================================================================
// Optimized implementation using fieldElement arithmetic
// =============================================================================

// pointFelem represents a point in Jacobian coordinates using field elements.
// X, Y, Z are Jacobian coordinates where affine (x,y) = (X/Z^2, Y/Z^3).
type pointFelem struct {
	x, y, z felem
}

var (
	// Cache for precomputed base point tables (per window size)
	baseTableCache     = make(map[int][][3]felem)
	baseTableCacheLock sync.RWMutex
)

// optimizedScalarBaseMult performs k*G using field element arithmetic.
func (c *curve) optimizedScalarBaseMult(k []byte) (*big.Int, *big.Int) {
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

	// Get or create precomputed table
	table := c.getBaseTable(w)

	// Convert scalar to wNAF (never empty for non-zero k)
	naf := toWNAF(kInt, w)

	// Perform scalar multiplication using wNAF
	result := c.scalarMultWNAFFelem(table, naf)

	// Convert back to affine coordinates
	return c.jacToAffine(&result)
}

// optimizedScalarMult performs k*B using field element arithmetic.
func (c *curve) optimizedScalarMult(Bx, By *big.Int, k []byte) (*big.Int, *big.Int) {
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

	// Precompute table for this point
	table := c.precomputeTable(Bx, By, w)

	// Convert scalar to wNAF (never empty for non-zero k)
	naf := toWNAF(kInt, w)

	// Perform scalar multiplication
	result := c.scalarMultWNAFFelem(table, naf)

	return c.jacToAffine(&result)
}

// getBaseTable gets or creates the precomputed base point table.
func (c *curve) getBaseTable(w int) [][3]felem {
	baseTableCacheLock.Lock()
	defer baseTableCacheLock.Unlock()

	// Check if table exists
	table, exists := baseTableCache[w]
	if exists {
		return table
	}

	// Create new table
	table = c.precomputeTable(c.params.Gx, c.params.Gy, w)
	baseTableCache[w] = table

	return table
}

// precomputeTable creates a table of odd multiples: B, 3B, 5B, ..., (2^(w-1)-1)B
func (c *curve) precomputeTable(Bx, By *big.Int, w int) [][3]felem {
	tableSize := 1 << uint(w-1)
	table := make([][3]felem, tableSize)

	// Convert B to Jacobian field element coordinates
	bx := felemFromBig(Bx)
	by := felemFromBig(By)
	bz := felemOne()

	// table[0] = B
	table[0] = [3]felem{bx, by, bz}

	// Compute 2B
	var twoB pointFelem
	c.pointDoubleFelem(&twoB, &pointFelem{bx, by, bz})

	// Compute 3B, 5B, 7B, ...
	for i := 1; i < tableSize; i++ {
		var curr pointFelem
		curr.x, curr.y, curr.z = table[i-1][0], table[i-1][1], table[i-1][2]

		var next pointFelem
		c.pointAddFelem(&next, &curr, &twoB)

		table[i] = [3]felem{next.x, next.y, next.z}
	}

	return table
}

// scalarMultWNAFFelem performs wNAF scalar multiplication using field elements.
func (c *curve) scalarMultWNAFFelem(table [][3]felem, naf []int8) pointFelem {
	var result pointFelem
	// Start with point at infinity (z = 0)

	for i := len(naf) - 1; i >= 0; i-- {
		// Double if not at infinity
		if !result.z.isZero() {
			c.pointDoubleFelem(&result, &result)
		}

		digit := naf[i]
		if digit != 0 {
			absDigit := int(digit)
			if absDigit < 0 {
				absDigit = -absDigit
			}
			idx := (absDigit - 1) / 2

			if digit > 0 {
				// Add table[idx]
				if result.z.isZero() {
					// First point
					result.x = table[idx][0]
					result.y = table[idx][1]
					result.z = table[idx][2]
				} else {
					tablePoint := pointFelem{table[idx][0], table[idx][1], table[idx][2]}
					c.pointAddFelem(&result, &result, &tablePoint)
				}
			} else {
				// Subtract: add with negated Y
				var negY felem
				felemNeg(&negY, &table[idx][1])
				tablePoint := pointFelem{table[idx][0], negY, table[idx][2]}
				c.pointAddFelem(&result, &result, &tablePoint)
			}
		}
	}

	return result
}

// pointAddFelem performs Jacobian point addition using field elements.
// Computes out = p1 + p2 in Jacobian coordinates.
func (c *curve) pointAddFelem(out, p1, p2 *pointFelem) {
	// Handle point at infinity cases
	if p1.z.isZero() {
		*out = *p2
		return
	}
	if p2.z.isZero() {
		*out = *p1
		return
	}

	// Copy inputs in case of aliasing
	p1x, p1y, p1z := p1.x, p1.y, p1.z
	p2x, p2y, p2z := p2.x, p2.y, p2.z

	// Optimized Jacobian addition formulas
	var z1z1, z2z2, u1, u2, s1, s2, h, r felem

	felemSquare(&z1z1, &p1z)
	felemSquare(&z2z2, &p2z)

	felemMul(&u1, &p1x, &z2z2)
	felemMul(&u2, &p2x, &z1z1)

	var t felem
	felemMul(&t, &p2z, &z2z2)
	felemMul(&s1, &p1y, &t)

	felemMul(&t, &p1z, &z1z1)
	felemMul(&s2, &p2y, &t)

	felemSub(&h, &u2, &u1)
	felemSub(&r, &s2, &s1)

	// Check if points are equal or inverse
	if h.isZero() {
		if r.isZero() {
			// Points are equal, use doubling
			c.pointDoubleFelem(out, p1)
		} else {
			// Points are inverse, result is infinity
			*out = pointFelem{}
		}
		return
	}

	var hh, hhh, v felem
	felemSquare(&hh, &h)
	felemMul(&hhh, &h, &hh)
	felemMul(&v, &u1, &hh)

	var rr, vv felem
	felemSquare(&rr, &r)
	felemAdd(&vv, &v, &v) // 2*v

	felemSub(&out.x, &rr, &hhh)
	felemSub(&out.x, &out.x, &vv)

	var t1, t2 felem
	felemSub(&t1, &v, &out.x)
	felemMul(&t2, &r, &t1)
	felemMul(&t1, &s1, &hhh)
	felemSub(&out.y, &t2, &t1)

	felemMul(&t1, &p1z, &p2z)
	felemMul(&out.z, &t1, &h)
}

// pointDoubleFelem performs Jacobian point doubling using field elements.
// Formula matches the standard jDouble implementation exactly.
func (c *curve) pointDoubleFelem(out, p *pointFelem) {
	if p.y.isZero() || p.z.isZero() {
		*out = pointFelem{}
		return
	}

	// Copy input in case out == p (aliasing)
	px, py, pz := p.x, p.y, p.z

	// B = Y1^2
	var b felem
	felemSquare(&b, &py)

	// C = B^2 = Y1^4
	var cc felem
	felemSquare(&cc, &b)

	// S = 4*X1*B
	var xb felem
	felemMul(&xb, &px, &b)
	var s felem
	felemAdd(&s, &xb, &xb) // 2*X1*B
	felemAdd(&s, &s, &s)   // 4*X1*B

	// M = 3*(X1-Z1^2)*(X1+Z1^2) for a=-3
	var z1sq felem
	felemSquare(&z1sq, &pz)
	var xMinusZ, xPlusZ felem
	felemSub(&xMinusZ, &px, &z1sq)
	felemAdd(&xPlusZ, &px, &z1sq)
	var temp felem
	felemMul(&temp, &xMinusZ, &xPlusZ)
	var m felem
	felemAdd(&m, &temp, &temp) // 2*temp
	felemAdd(&m, &m, &temp)    // 3*temp

	// X3 = M^2 - 2*S
	var mm felem
	felemSquare(&mm, &m)
	var twoS felem
	felemAdd(&twoS, &s, &s)
	felemSub(&out.x, &mm, &twoS)

	// Y3 = M*(S - X3) - 8*C
	var sMinusX3 felem
	felemSub(&sMinusX3, &s, &out.x)
	felemMul(&out.y, &m, &sMinusX3)
	var eightC felem
	felemAdd(&eightC, &cc, &cc)         // 2*C
	felemAdd(&eightC, &eightC, &eightC) // 4*C
	felemAdd(&eightC, &eightC, &eightC) // 8*C
	felemSub(&out.y, &out.y, &eightC)

	// Z3 = 2*Y1*Z1
	felemMul(&temp, &py, &pz)
	felemAdd(&out.z, &temp, &temp)
}

// jacToAffine converts Jacobian coordinates to affine.
func (c *curve) jacToAffine(p *pointFelem) (*big.Int, *big.Int) {
	if p.z.isZero() {
		return nil, nil
	}

	var zInv, zInv2, zInv3 felem
	felemInv(&zInv, &p.z)
	felemSquare(&zInv2, &zInv)
	felemMul(&zInv3, &zInv2, &zInv)

	var x, y felem
	felemMul(&x, &p.x, &zInv2)
	felemMul(&y, &p.y, &zInv3)

	return x.toBig(), y.toBig()
}
