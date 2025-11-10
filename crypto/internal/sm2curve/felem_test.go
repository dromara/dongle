package sm2curve

import (
	"math/big"
	"testing"
)

func TestFelemConversion(t *testing.T) {
	testCases := []*big.Int{
		big.NewInt(0),
		big.NewInt(1),
		big.NewInt(42),
		big.NewInt(0xFFFFFFFF),
		sm2PBig,
		new(big.Int).Sub(sm2PBig, big.NewInt(1)),
	}

	for _, tc := range testCases {
		// Reduce modulo p
		tc = new(big.Int).Mod(tc, sm2PBig)

		// Convert to felem and back
		fe := felemFromBig(tc)
		result := fe.toBig()

		if result.Cmp(tc) != 0 {
			t.Errorf("Conversion failed for %s: got %s", tc.String(), result.String())
		}
	}
}

func TestFelemAdd(t *testing.T) {
	a := felemFromBig(big.NewInt(123))
	b := felemFromBig(big.NewInt(456))
	var c felem
	felemAdd(&c, &a, &b)

	result := c.toBig()
	expected := big.NewInt(579)

	if result.Cmp(expected) != 0 {
		t.Errorf("felemAdd: expected %s, got %s", expected.String(), result.String())
	}
}

func TestFelemSub(t *testing.T) {
	a := felemFromBig(big.NewInt(456))
	b := felemFromBig(big.NewInt(123))
	var c felem
	felemSub(&c, &a, &b)

	result := c.toBig()
	expected := big.NewInt(333)

	if result.Cmp(expected) != 0 {
		t.Errorf("felemSub: expected %s, got %s", expected.String(), result.String())
	}
}

func TestFelemMul(t *testing.T) {
	a := felemFromBig(big.NewInt(123))
	b := felemFromBig(big.NewInt(456))
	var c felem
	felemMul(&c, &a, &b)

	result := c.toBig()
	expected := new(big.Int).Mul(big.NewInt(123), big.NewInt(456))
	expected.Mod(expected, sm2PBig)

	if result.Cmp(expected) != 0 {
		t.Errorf("felemMul: expected %s, got %s", expected.String(), result.String())
	}
}

func TestFelemInv(t *testing.T) {
	a := felemFromBig(big.NewInt(123))
	var b felem
	felemInv(&b, &a)

	// Verify a * b ≡ 1 (mod p)
	var c felem
	felemMul(&c, &a, &b)

	result := c.toBig()
	expected := big.NewInt(1)

	if result.Cmp(expected) != 0 {
		t.Errorf("felemInv: a * a^-1 should be 1, got %s", result.String())
	}
}

func TestFelemBasePointConversion(t *testing.T) {
	c := New()
	p := c.Params()

	// Test base point coordinates
	gx := felemFromBig(p.Gx)
	gy := felemFromBig(p.Gy)

	gxBack := gx.toBig()
	gyBack := gy.toBig()

	if gxBack.Cmp(p.Gx) != 0 {
		t.Errorf("Base point Gx conversion failed")
	}
	if gyBack.Cmp(p.Gy) != 0 {
		t.Errorf("Base point Gy conversion failed")
	}
}

// TestFelemFromBig_EdgeCases tests edge cases for felemFromBig
func TestFelemFromBig_EdgeCases(t *testing.T) {
	// Test nil input
	fe := felemFromBig(nil)
	if !fe.isZero() {
		t.Errorf("felemFromBig(nil) should return zero")
	}

	// Test negative input
	fe = felemFromBig(big.NewInt(-1))
	if !fe.isZero() {
		t.Errorf("felemFromBig(negative) should return zero")
	}

	// Test value >= p (should be reduced)
	bigVal := new(big.Int).Add(sm2PBig, big.NewInt(42))
	fe = felemFromBig(bigVal)
	result := fe.toBig()
	expected := big.NewInt(42)
	if result.Cmp(expected) != 0 {
		t.Errorf("felemFromBig should reduce mod p: expected %s, got %s", expected, result)
	}

	// Test small bytes (< 32 bytes)
	smallVal := big.NewInt(255)
	fe = felemFromBig(smallVal)
	result = fe.toBig()
	if result.Cmp(smallVal) != 0 {
		t.Errorf("felemFromBig with small value failed: expected %s, got %s", smallVal, result)
	}
}

// TestFelemZero tests felemZero function
func TestFelemZero(t *testing.T) {
	zero := felemZero()
	if !zero.isZero() {
		t.Errorf("felemZero should return zero element")
	}

	// Verify all limbs are zero
	for i := 0; i < 4; i++ {
		if zero[i] != 0 {
			t.Errorf("felemZero limb[%d] should be 0, got %d", i, zero[i])
		}
	}
}

// TestFelemNeg tests felemNeg function
func TestFelemNeg(t *testing.T) {
	// Test negation of zero
	zero := felemZero()
	var negZero felem
	felemNeg(&negZero, &zero)
	if !negZero.isZero() {
		t.Errorf("Negation of zero should be zero")
	}

	// Test negation of non-zero value
	a := felemFromBig(big.NewInt(123))
	var negA felem
	felemNeg(&negA, &a)

	// Verify a + (-a) = 0
	var sum felem
	felemAdd(&sum, &a, &negA)
	if !sum.isZero() {
		t.Errorf("a + (-a) should be zero, got %s", sum.toBig())
	}

	// Verify -a = p - a
	expected := new(big.Int).Sub(sm2PBig, big.NewInt(123))
	result := negA.toBig()
	if result.Cmp(expected) != 0 {
		t.Errorf("felemNeg: expected %s, got %s", expected, result)
	}
}

// TestFelemInv_Zero tests felemInv with zero input
func TestFelemInv_Zero(t *testing.T) {
	zero := felemZero()
	var invZero felem
	felemInv(&invZero, &zero)

	// Inverse of zero should be zero (by convention)
	if !invZero.isZero() {
		t.Errorf("Inverse of zero should be zero")
	}
}

// TestFelemSquare tests felemSquare function
func TestFelemSquare(t *testing.T) {
	a := felemFromBig(big.NewInt(123))
	var sq felem
	felemSquare(&sq, &a)

	// Verify square equals multiplication by self
	var mulResult felem
	felemMul(&mulResult, &a, &a)

	sqBig := sq.toBig()
	mulBig := mulResult.toBig()

	if sqBig.Cmp(mulBig) != 0 {
		t.Errorf("felemSquare should equal a*a: square=%s, mul=%s", sqBig, mulBig)
	}

	// Verify against big.Int
	expected := new(big.Int).Mul(big.NewInt(123), big.NewInt(123))
	expected.Mod(expected, sm2PBig)

	if sqBig.Cmp(expected) != 0 {
		t.Errorf("felemSquare: expected %s, got %s", expected, sqBig)
	}
}

// TestFelemReduce tests felemReduce function
func TestFelemReduce(t *testing.T) {
	// Test with value that needs reduction
	var a felem
	// Set to p (should reduce to 0)
	a = sm2P
	felemReduce(&a)

	if !a.isZero() {
		t.Errorf("Reducing p should give zero, got %s", a.toBig())
	}

	// Test with a value that's already reduced
	a = felemFromBig(big.NewInt(42))
	felemReduce(&a)

	result := a.toBig()
	expected := big.NewInt(42)
	if result.Cmp(expected) != 0 {
		t.Errorf("Reducing 42 should give 42, got %s", result)
	}

	// Test with p-1 (should stay as p-1)
	pMinus1 := new(big.Int).Sub(sm2PBig, big.NewInt(1))
	a = felemFromBig(pMinus1)
	felemReduce(&a)

	result = a.toBig()
	if result.Cmp(pMinus1) != 0 {
		t.Errorf("Reducing p-1 should give p-1, got %s", result)
	}
}

// TestFelemReduceCarry tests felemReduceCarry function
func TestFelemReduceCarry(t *testing.T) {
	// felemReduceCarry takes *[8]uint64 (intermediate multiplication result)
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

	var result felem
	felemReduceCarry(&result, &p)

	resultBig := result.toBig()
	expected := big.NewInt(42)

	if resultBig.Cmp(expected) != 0 {
		t.Errorf("felemReduceCarry failed: expected %s, got %s", expected, resultBig)
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

	felemReduceCarry(&result, &p)

	// Verify result is reduced mod p
	resultBig = result.toBig()
	expectedBytes := make([]byte, 16)
	for i := 0; i < 16; i++ {
		expectedBytes[i] = 0xFF
	}
	expectedBig := new(big.Int).SetBytes(expectedBytes)
	expectedBig.Mod(expectedBig, sm2PBig)

	if resultBig.Cmp(expectedBig) != 0 {
		t.Errorf("felemReduceCarry with large value failed: expected %s, got %s", expectedBig, resultBig)
	}
}

// TestFelemOperations_Comprehensive tests comprehensive field operations
func TestFelemOperations_Comprehensive(t *testing.T) {
	// Test: (a + b) - b = a
	a := felemFromBig(big.NewInt(12345))
	b := felemFromBig(big.NewInt(67890))

	var sum felem
	felemAdd(&sum, &a, &b)

	var diff felem
	felemSub(&diff, &sum, &b)

	if diff.toBig().Cmp(a.toBig()) != 0 {
		t.Errorf("(a+b)-b should equal a")
	}

	// Test: a * 1 = a
	one := felemOne()
	var prod felem
	felemMul(&prod, &a, &one)

	if prod.toBig().Cmp(a.toBig()) != 0 {
		t.Errorf("a*1 should equal a")
	}

	// Test: a * a^(-1) = 1
	var inv felem
	felemInv(&inv, &a)
	felemMul(&prod, &a, &inv)

	if prod.toBig().Cmp(big.NewInt(1)) != 0 {
		t.Errorf("a * a^(-1) should equal 1")
	}
}
