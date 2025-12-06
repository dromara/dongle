package sm2curve

import (
	"math/big"
	"testing"
)

func TestFelemConversion(t *testing.T) {
	pBig := toBigInt(&prime)
	testCases := []*big.Int{
		big.NewInt(0),
		big.NewInt(1),
		big.NewInt(42),
		big.NewInt(0xFFFFFFFF),
		pBig,
		new(big.Int).Sub(pBig, big.NewInt(1)),
	}

	for _, tc := range testCases {
		// Reduce modulo p
		tc = new(big.Int).Mod(tc, pBig)

		// Convert to field and back
		fe := *fromBigInt(tc)
		result := toBigInt(&fe)

		if result.Cmp(tc) != 0 {
			t.Errorf("Conversion failed for %s: got %s", tc.String(), result.String())
		}
	}
}

func TestFelemAdd(t *testing.T) {
	a := *fromBigInt(big.NewInt(123))
	b := *fromBigInt(big.NewInt(456))
	var c field
	c.add(&a, &b)

	result := toBigInt(&c)
	expected := big.NewInt(579)

	if result.Cmp(expected) != 0 {
		t.Errorf("felemAdd: expected %s, got %s", expected.String(), result.String())
	}
}

func TestFelemSub(t *testing.T) {
	a := *fromBigInt(big.NewInt(456))
	b := *fromBigInt(big.NewInt(123))
	var c field
	c.sub(&a, &b)

	result := toBigInt(&c)
	expected := big.NewInt(333)

	if result.Cmp(expected) != 0 {
		t.Errorf("felemSub: expected %s, got %s", expected.String(), result.String())
	}
}

func TestFelemMul(t *testing.T) {
	a := *fromBigInt(big.NewInt(123))
	b := *fromBigInt(big.NewInt(456))
	var c field
	c.mul(&a, &b)

	result := toBigInt(&c)
	expected := new(big.Int).Mul(big.NewInt(123), big.NewInt(456))
	expected.Mod(expected, toBigInt(&prime))

	if result.Cmp(expected) != 0 {
		t.Errorf("felemMul: expected %s, got %s", expected.String(), result.String())
	}
}

func TestFelemInv(t *testing.T) {
	a := *fromBigInt(big.NewInt(123))
	var b field
	b.inv(&a)

	// Verify a * b ≡ 1 (mod p)
	var c field
	c.mul(&a, &b)

	result := toBigInt(&c)
	expected := big.NewInt(1)

	if result.Cmp(expected) != 0 {
		t.Errorf("felemInv: a * a^-1 should be 1, got %s", result.String())
	}
}

func TestFelemBasePointConversion(t *testing.T) {
	c := NewCurve()
	p := c.Params()

	// Test base point coordinates
	gx := *fromBigInt(p.Gx)
	gy := *fromBigInt(p.Gy)

	gxBack := toBigInt(&gx)
	gyBack := toBigInt(&gy)

	if gxBack.Cmp(p.Gx) != 0 {
		t.Errorf("Base point Gx conversion failed")
	}
	if gyBack.Cmp(p.Gy) != 0 {
		t.Errorf("Base point Gy conversion failed")
	}
}

// TestFelemFromBig_EdgeCases tests edge cases for fromBigInt
func TestFelemFromBig_EdgeCases(t *testing.T) {
	// Test nil input
	fe := *fromBigInt(nil)
	if !fe.isZero() {
		t.Errorf("felemFromBig(nil) should return zero")
	}

	// Test negative input
	fe = *fromBigInt(big.NewInt(-1))
	if !fe.isZero() {
		t.Errorf("fromBigInt(negative) should return zero")
	}

	// Test value >= p (should be reduced)
	bigVal := new(big.Int).Add(toBigInt(&prime), big.NewInt(42))
	fe = *fromBigInt(bigVal)
	result := toBigInt(&fe)
	expected := big.NewInt(42)
	if result.Cmp(expected) != 0 {
		t.Errorf("fromBigInt should reduce mod p: expected %s, got %s", expected, result)
	}

	// Test small bytes (< 32 bytes)
	smallVal := big.NewInt(255)
	fe = *fromBigInt(smallVal)
	result = toBigInt(&fe)
	if result.Cmp(smallVal) != 0 {
		t.Errorf("fromBigInt with small value failed: expected %s, got %s", smallVal, result)
	}
}

// TestFelemZero tests zero field element
func TestFelemZero(t *testing.T) {
	zero := field{}
	if !zero.isZero() {
		t.Errorf("field{} should return zero element")
	}

	// Verify all limbs are zero
	for i := range 4 {
		if zero.limbs[i] != 0 {
			t.Errorf("field{} limb[%d] should be 0, got %d", i, zero.limbs[i])
		}
	}
}

// TestFelemNeg tests fieldNeg function
func TestFelemNeg(t *testing.T) {
	// Test negation of zero
	zero := field{}
	var negZero field
	negZero.neg(&zero)
	if !negZero.isZero() {
		t.Errorf("Negation of zero should be zero")
	}

	// Test negation of non-zero value
	a := *fromBigInt(big.NewInt(123))
	var negA field
	negA.neg(&a)

	// Verify a + (-a) = 0
	var sum field
	sum.add(&a, &negA)
	if !sum.isZero() {
		t.Errorf("a + (-a) should be zero, got %s", toBigInt(&sum))
	}

	// Verify -a = p - a
	expected := new(big.Int).Sub(toBigInt(&prime), big.NewInt(123))
	result := toBigInt(&negA)
	if result.Cmp(expected) != 0 {
		t.Errorf("fieldNeg: expected %s, got %s", expected, result)
	}
}

// TestFelemInv_Zero tests fieldInv with zero input
func TestFelemInv_Zero(t *testing.T) {
	zero := field{}
	var invZero field
	invZero.inv(&zero)

	// Inverse of zero should be zero (by convention)
	if !invZero.isZero() {
		t.Errorf("Inverse of zero should be zero")
	}
}

// TestFelemReduce tests fieldReduce256 function
func TestFelemReduce(t *testing.T) {
	// Test with value that needs reduction
	var a field
	// Set to p (should reduce to 0)
	a = prime
	a.reduce256()

	if !a.isZero() {
		t.Errorf("Reducing p should give zero, got %s", toBigInt(&a))
	}

	// Test with a value that's already reduced
	a = *fromBigInt(big.NewInt(42))
	a.reduce256()

	result := toBigInt(&a)
	expected := big.NewInt(42)
	if result.Cmp(expected) != 0 {
		t.Errorf("Reducing 42 should give 42, got %s", result)
	}

	// Test with p-1 (should stay as p-1)
	pMinus1 := new(big.Int).Sub(toBigInt(&prime), big.NewInt(1))
	a = *fromBigInt(pMinus1)
	a.reduce256()

	result = toBigInt(&a)
	if result.Cmp(pMinus1) != 0 {
		t.Errorf("Reducing p-1 should give p-1, got %s", result)
	}
}

// TestFelemReduceCarry tests fieldReduce512 function
func TestFelemReduceCarry(t *testing.T) {
	// fieldReduce512 takes *[8]uint64 (intermediate multiplication result)
	// Test with a simple case: create an 8-limb intermediate result
	var p [8]uint64
	// Set a small value in the lower limbs
	p[0] = 42
	p[1] = 0
	p[2] = 0
	p[3] = 0
	p[4] = 0
	p[5] = 0
	p[6] = 0
	p[7] = 0

	var result field
	result.reduce512(&p)

	resultBig := toBigInt(&result)
	expected := big.NewInt(42)

	if resultBig.Cmp(expected) != 0 {
		t.Errorf("fieldReduce512 failed: expected %s, got %s", expected, resultBig)
	}

	// Test with larger value spanning multiple limbs
	p[0] = 0xFFFFFFFFFFFFFFFF
	p[1] = 0xFFFFFFFFFFFFFFFF
	p[2] = 0
	p[3] = 0
	p[4] = 0
	p[5] = 0
	p[6] = 0
	p[7] = 0

	result.reduce512(&p)

	// Verify result is reduced mod p
	resultBig = toBigInt(&result)
	expectedBytes := make([]byte, 16)
	for i := range 16 {
		expectedBytes[i] = 0xFF
	}
	expectedBig := new(big.Int).SetBytes(expectedBytes)
	expectedBig.Mod(expectedBig, toBigInt(&prime))

	if resultBig.Cmp(expectedBig) != 0 {
		t.Errorf("fieldReduce512 with large value failed: expected %s, got %s", expectedBig, resultBig)
	}
}

// TestFelemOperations_Comprehensive tests comprehensive field operations
func TestFelemOperations_Comprehensive(t *testing.T) {
	// Test: (a + b) - b = a
	a := *fromBigInt(big.NewInt(12345))
	b := *fromBigInt(big.NewInt(67890))

	var sum field
	sum.add(&a, &b)

	var diff field
	diff.sub(&sum, &b)

	if toBigInt(&diff).Cmp(toBigInt(&a)) != 0 {
		t.Errorf("(a+b)-b should equal a")
	}

	// Test: a * 1 = a
	one := field{limbs: [4]uint64{1, 0, 0, 0}}
	var prod field
	prod.mul(&a, &one)

	if toBigInt(&prod).Cmp(toBigInt(&a)) != 0 {
		t.Errorf("a*1 should equal a")
	}

	// Test: a * a^(-1) = 1
	var inv field
	inv.inv(&a)
	prod.mul(&a, &inv)

	if toBigInt(&prod).Cmp(big.NewInt(1)) != 0 {
		t.Errorf("a * a^(-1) should equal 1")
	}
}
