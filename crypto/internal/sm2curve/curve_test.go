package sm2curve

import (
	"crypto/elliptic"
	"crypto/rand"
	"io"
	"math/big"
	"testing"
)

// Test helper: sequence reader for deterministic testing
type seqReader struct {
	seq [][]byte
	i   int
}

func (r *seqReader) Read(p []byte) (int, error) {
	if r.i >= len(r.seq) {
		return 0, io.EOF
	}
	n := copy(p, r.seq[r.i])
	r.i++
	return n, nil
}

// Test helper: mask curve for testing SetWindow with invalid curve
type maskCurve struct {
	c elliptic.Curve
}

func (m *maskCurve) Params() *elliptic.CurveParams                    { return m.c.Params() }
func (m *maskCurve) IsOnCurve(x, y *big.Int) bool                     { return m.c.IsOnCurve(x, y) }
func (m *maskCurve) Add(x1, y1, x2, y2 *big.Int) (*big.Int, *big.Int) { return m.c.Add(x1, y1, x2, y2) }
func (m *maskCurve) Double(x1, y1 *big.Int) (*big.Int, *big.Int)      { return m.c.Double(x1, y1) }
func (m *maskCurve) ScalarMult(x1, y1 *big.Int, k []byte) (*big.Int, *big.Int) {
	return m.c.ScalarMult(x1, y1, k)
}
func (m *maskCurve) ScalarBaseMult(k []byte) (*big.Int, *big.Int) { return m.c.ScalarBaseMult(k) }

// TestCurve_Basic tests basic curve operations
func TestCurve_Basic(t *testing.T) {
	c := NewCurve().(*sm2Curve)
	p := c.Params()

	// Test curve parameters
	if p.Name != "SM2-P-256" {
		t.Errorf("Expected SM2-P-256, got %s", p.Name)
	}
	if p.BitSize != 256 {
		t.Errorf("Expected 256 bits, got %d", p.BitSize)
	}

	// Test base point is on curve
	if !c.IsOnCurve(p.Gx, p.Gy) {
		t.Error("Base point not on curve")
	}

	// Test IsOnCurve with nil
	if c.IsOnCurve(nil, p.Gy) {
		t.Error("IsOnCurve should return false for nil x")
	}
	if c.IsOnCurve(p.Gx, nil) {
		t.Error("IsOnCurve should return false for nil y")
	}
}

// TestCurve_Add tests point addition
func TestCurve_Add(t *testing.T) {
	c := NewCurve().(*sm2Curve)
	gx, gy := c.params.Gx, c.params.Gy

	// Test nil cases
	x, y := c.Add(nil, nil, gx, gy)
	if x.Cmp(gx) != 0 || y.Cmp(gy) != 0 {
		t.Error("Add(nil, nil, G) should return G")
	}

	x, y = c.Add(gx, gy, nil, nil)
	if x.Cmp(gx) != 0 || y.Cmp(gy) != 0 {
		t.Error("Add(G, nil, nil) should return G")
	}

	// Test G + G = 2G (doubling case)
	x2, y2 := c.Add(gx, gy, gx, gy)
	x2d, y2d := c.Double(gx, gy)
	if x2.Cmp(x2d) != 0 || y2.Cmp(y2d) != 0 {
		t.Error("G + G should equal 2G")
	}

	// Test G + (-G) = O (inverse case)
	negGy := new(big.Int).Neg(gy)
	negGy.Mod(negGy, c.params.P)
	x, y = c.Add(gx, gy, gx, negGy)
	if x != nil || y != nil {
		t.Error("G + (-G) should return point at infinity")
	}

	// Test normal addition: G + 2G = 3G
	x3, y3 := c.Add(gx, gy, x2, y2)
	if x3 == nil || y3 == nil {
		t.Error("G + 2G should not be nil")
	}
	if !c.IsOnCurve(x3, y3) {
		t.Error("G + 2G not on curve")
	}
}

// TestCurve_Double tests point doubling
func TestCurve_Double(t *testing.T) {
	c := NewCurve().(*sm2Curve)
	gx, gy := c.params.Gx, c.params.Gy

	// Test nil Y
	x, y := c.Double(gx, nil)
	if x != nil || y != nil {
		t.Error("Double with nil y should return nil")
	}

	// Test zero Y
	x, y = c.Double(gx, big.NewInt(0))
	if x != nil || y != nil {
		t.Error("Double with zero y should return nil")
	}

	// Test normal doubling
	x2, y2 := c.Double(gx, gy)
	if x2 == nil || y2 == nil {
		t.Error("2G should not be nil")
	}
	if !c.IsOnCurve(x2, y2) {
		t.Error("2G not on curve")
	}
}

// TestCurve_WNAF tests wNAF conversion
func TestCurve_WNAF(t *testing.T) {
	// Test zero
	naf := toWNAF(big.NewInt(0), 4)
	if naf != nil {
		t.Error("toWNAF(0) should return nil")
	}

	// Test small values
	naf = toWNAF(big.NewInt(1), 4)
	if len(naf) == 0 {
		t.Error("toWNAF(1) should not be empty")
	}

	// Test invalid window (should use default)
	naf = toWNAF(big.NewInt(5), 1)
	if len(naf) == 0 {
		t.Error("toWNAF with w<2 should use default")
	}

	naf = toWNAF(big.NewInt(5), 7)
	if len(naf) == 0 {
		t.Error("toWNAF with w>6 should use default")
	}

	// Test larger number
	naf = toWNAF(big.NewInt(12345), 4)
	if len(naf) == 0 {
		t.Error("toWNAF(12345) should not be empty")
	}
}

// TestCurve_ScalarBaseMult tests scalar multiplication with base point
func TestCurve_ScalarBaseMult(t *testing.T) {
	c := NewCurve().(*sm2Curve)

	// Test empty bytes
	x, y := c.ScalarBaseMult([]byte{})
	if x != nil || y != nil {
		t.Error("ScalarBaseMult([]) should return nil")
	}

	// Test zero
	x, y = c.ScalarBaseMult([]byte{0})
	if x != nil || y != nil {
		t.Error("ScalarBaseMult(0) should return nil")
	}

	// Test k=1 should return G
	x, y = c.ScalarBaseMult([]byte{1})
	if x.Cmp(c.params.Gx) != 0 || y.Cmp(c.params.Gy) != 0 {
		t.Error("1*G should equal G")
	}

	// Test k=2
	x, y = c.ScalarBaseMult([]byte{2})
	if x == nil || y == nil {
		t.Error("2*G should not be nil")
	}
	if !c.IsOnCurve(x, y) {
		t.Error("2*G not on curve")
	}
}

// TestCurve_ScalarMult tests scalar multiplication with arbitrary point
func TestCurve_ScalarMult(t *testing.T) {
	c := NewCurve().(*sm2Curve)
	gx, gy := c.params.Gx, c.params.Gy

	// Test empty bytes
	x, y := c.ScalarMult(gx, gy, []byte{})
	if x != nil || y != nil {
		t.Error("ScalarMult with empty k should return nil")
	}

	// Test zero
	x, y = c.ScalarMult(gx, gy, []byte{0})
	if x != nil || y != nil {
		t.Error("ScalarMult with k=0 should return nil")
	}

	// Test k=1
	x, y = c.ScalarMult(gx, gy, []byte{1})
	if x.Cmp(gx) != 0 || y.Cmp(gy) != 0 {
		t.Error("1*P should equal P")
	}

	// Test k=3
	x, y = c.ScalarMult(gx, gy, []byte{3})
	if x == nil || y == nil {
		t.Error("3*G should not be nil")
	}
	if !c.IsOnCurve(x, y) {
		t.Error("3*G not on curve")
	}
}

// TestCurve_SetWindow tests window size setting
func TestCurve_SetWindow(t *testing.T) {
	c := NewCurve()

	// Test valid window sizes
	for w := 2; w <= 6; w++ {
		SetWindow(c, w)
		cv := c.(*sm2Curve)
		if cv.window != w {
			t.Errorf("SetWindow(%d) failed", w)
		}
	}

	// Test invalid window sizes (should not change)
	SetWindow(c, 1)
	cv := c.(*sm2Curve)
	if cv.window == 1 {
		t.Error("SetWindow(1) should not set window=1")
	}

	SetWindow(c, 7)
	if cv.window == 7 {
		t.Error("SetWindow(7) should not set window=7")
	}

	// Test with invalid curve type
	masked := &maskCurve{c: c}
	SetWindow(masked, 4) // Should not panic
}

// TestCurve_RandScalar tests random scalar generation
func TestCurve_RandScalar(t *testing.T) {
	c := NewCurve()

	// Test with default reader
	d, err := RandScalar(c, nil)
	if err != nil {
		t.Fatalf("RandScalar failed: %v", err)
	}
	if d.Sign() == 0 || d.Cmp(c.Params().N) >= 0 {
		t.Error("RandScalar returned invalid value")
	}

	// Test with custom reader
	d, err = RandScalar(c, rand.Reader)
	if err != nil {
		t.Fatalf("RandScalar with custom reader failed: %v", err)
	}
	if d.Sign() == 0 || d.Cmp(c.Params().N) >= 0 {
		t.Error("RandScalar returned invalid value")
	}

	// Test error case
	badReader := &seqReader{seq: [][]byte{{0xFF}}}
	_, err = RandScalar(c, badReader)
	if err == nil {
		t.Error("RandScalar with bad reader should return error")
	}
}

// TestCurve_OptimizedPaths tests optimized field element paths
func TestCurve_OptimizedPaths(t *testing.T) {
	c := NewCurve().(*sm2Curve)

	// Test ScalarBaseMult with empty k
	x, y := c.ScalarBaseMult([]byte{})
	if x != nil || y != nil {
		t.Error("ScalarBaseMult([]) should return nil")
	}

	// Test ScalarBaseMult with zero k
	x, y = c.ScalarBaseMult([]byte{0})
	if x != nil || y != nil {
		t.Error("ScalarBaseMult(0) should return nil")
	}

	// Test ScalarBaseMult with invalid window
	oldW := c.window
	c.window = 1
	x, y = c.ScalarBaseMult([]byte{2})
	c.window = oldW
	if x == nil || y == nil {
		t.Error("ScalarBaseMult should handle invalid window")
	}

	// Test ScalarMult with empty k
	gx, gy := c.params.Gx, c.params.Gy
	x, y = c.ScalarMult(gx, gy, []byte{})
	if x != nil || y != nil {
		t.Error("ScalarMult([]) should return nil")
	}

	// Test ScalarMult with zero k
	x, y = c.ScalarMult(gx, gy, []byte{0})
	if x != nil || y != nil {
		t.Error("ScalarMult(0) should return nil")
	}

	// Test ScalarMult with invalid window
	c.window = 7
	x, y = c.ScalarMult(gx, gy, []byte{2})
	c.window = oldW
	if x == nil || y == nil {
		t.Error("ScalarMult should handle invalid window")
	}
}

// TestCurve_GetBaseTable tests base table caching
func TestCurve_GetBaseTable(t *testing.T) {
	c := NewCurve().(*sm2Curve)

	// First call should create table
	table1 := c.getBaseTable(4)
	if len(table1) == 0 {
		t.Error("getBaseTable should return non-empty table")
	}

	// Second call should return cached table
	table2 := c.getBaseTable(4)
	if len(table2) != len(table1) {
		t.Error("getBaseTable should return cached table")
	}

	// Different window size should create new table
	table3 := c.getBaseTable(5)
	if len(table3) == len(table1) {
		t.Error("getBaseTable with different w should create new table")
	}
}

// TestCurve_PointAddFelem tests field element point addition edge cases
func TestCurve_PointAddFelem(t *testing.T) {
	c := NewCurve().(*sm2Curve)
	gx, gy := c.params.Gx, c.params.Gy

	// Create test points
	p1 := pointField{
		x: *fromBigInt(gx),
		y: *fromBigInt(gy),
		z: field{limbs: [4]uint64{1, 0, 0, 0}},
	}

	// Test p1.z = 0 (should return p2)
	p1Zero := pointField{}
	var out pointField
	c.pointAddField(&out, &p1Zero, &p1)
	if toBigInt(&out.x).Cmp(gx) != 0 || toBigInt(&out.y).Cmp(gy) != 0 {
		t.Error("pointAddFelem with p1.z=0 should return p2")
	}

	// Test p2.z = 0 (should return p1)
	c.pointAddField(&out, &p1, &p1Zero)
	if toBigInt(&out.x).Cmp(gx) != 0 || toBigInt(&out.y).Cmp(gy) != 0 {
		t.Error("pointAddFelem with p2.z=0 should return p1")
	}

	// Test p1 = p2 (doubling case)
	c.pointAddField(&out, &p1, &p1)
	if out.z.isZero() {
		t.Error("pointAddFelem(P, P) should not return infinity")
	}

	// Test p1 = -p2 (inverse case)
	p1Neg := p1
	var negY field
	negY.neg(&p1.y)
	p1Neg.y = negY
	c.pointAddField(&out, &p1, &p1Neg)
	if !out.z.isZero() {
		t.Error("pointAddFelem(P, -P) should return infinity")
	}
}

// TestCurve_PointDoubleFelem tests field element point doubling edge cases
func TestCurve_PointDoubleFelem(t *testing.T) {
	c := NewCurve().(*sm2Curve)
	gx, gy := c.params.Gx, c.params.Gy

	p := pointField{
		x: *fromBigInt(gx),
		y: *fromBigInt(gy),
		z: field{limbs: [4]uint64{1, 0, 0, 0}},
	}

	// Test with y = 0
	pZeroY := p
	pZeroY.y = field{}
	var out pointField
	c.pointDoubleField(&out, &pZeroY)
	if !out.z.isZero() {
		t.Error("pointDoubleFelem with y=0 should return infinity")
	}

	// Test with z = 0
	pZeroZ := p
	pZeroZ.z = field{}
	c.pointDoubleField(&out, &pZeroZ)
	if !out.z.isZero() {
		t.Error("pointDoubleFelem with z=0 should return infinity")
	}

	// Test normal doubling
	c.pointDoubleField(&out, &p)
	if out.z.isZero() {
		t.Error("pointDoubleFelem should not return infinity for valid point")
	}
}

// TestCurve_JacToAffine tests Jacobian to affine conversion
func TestCurve_JacToAffine(t *testing.T) {
	c := NewCurve().(*sm2Curve)
	gx, gy := c.params.Gx, c.params.Gy

	p := pointField{
		x: *fromBigInt(gx),
		y: *fromBigInt(gy),
		z: field{limbs: [4]uint64{1, 0, 0, 0}},
	}

	// Test normal conversion
	x, y := c.jacToAffine(&p)
	if x.Cmp(gx) != 0 || y.Cmp(gy) != 0 {
		t.Error("jacToAffine failed for normal point")
	}

	// Test with z = 0 (infinity)
	pInf := pointField{}
	x, y = c.jacToAffine(&pInf)
	if x != nil || y != nil {
		t.Error("jacToAffine with z=0 should return nil")
	}
}

// TestCurve_Comprehensive tests comprehensive operations
func TestCurve_Comprehensive(t *testing.T) {
	c := NewCurve()

	// Generate random scalar
	k, err := RandScalar(c, rand.Reader)
	if err != nil {
		t.Fatalf("RandScalar failed: %v", err)
	}

	// Test ScalarBaseMult
	x1, y1 := c.ScalarBaseMult(k.Bytes())
	if x1 == nil || y1 == nil {
		t.Error("ScalarBaseMult returned nil")
	}
	if !c.IsOnCurve(x1, y1) {
		t.Error("ScalarBaseMult result not on curve")
	}

	// Test ScalarMult with base point should match ScalarBaseMult
	gx, gy := c.Params().Gx, c.Params().Gy
	x2, y2 := c.ScalarMult(gx, gy, k.Bytes())
	if x1.Cmp(x2) != 0 || y1.Cmp(y2) != 0 {
		t.Error("ScalarBaseMult and ScalarMult(G) should match")
	}

	// Test multiple operations
	x3, y3 := c.Add(x1, y1, x2, y2)
	if !c.IsOnCurve(x3, y3) {
		t.Error("Add result not on curve")
	}

	x4, y4 := c.Double(x1, y1)
	if !c.IsOnCurve(x4, y4) {
		t.Error("Double result not on curve")
	}
}

// TestCurve_RandScalar_EdgeCases tests edge cases in RandScalar
func TestCurve_RandScalar_EdgeCases(t *testing.T) {
	c := NewCurve()

	// Test with reader that returns values >= N (should retry)
	// Create a reader that first returns N, then a valid value
	nBytes := c.Params().N.Bytes()
	validBytes := big.NewInt(42).Bytes()

	// Pad to correct length
	paddedValid := make([]byte, len(nBytes))
	copy(paddedValid[len(paddedValid)-len(validBytes):], validBytes)

	seqR := &seqReader{
		seq: [][]byte{nBytes, paddedValid},
	}

	d, err := RandScalar(c, seqR)
	if err != nil {
		t.Fatalf("RandScalar should succeed after retry: %v", err)
	}
	if d.Cmp(big.NewInt(42)) != 0 {
		t.Errorf("Expected 42, got %s", d)
	}

	// Test with reader that returns zero (should retry)
	zeroBytes := make([]byte, len(nBytes))
	seqR2 := &seqReader{
		seq: [][]byte{zeroBytes, paddedValid},
	}

	d, err = RandScalar(c, seqR2)
	if err != nil {
		t.Fatalf("RandScalar should succeed after zero: %v", err)
	}
	if d.Sign() == 0 {
		t.Error("RandScalar should not return zero")
	}

	// Test with value that needs bit masking (BitSize % 8 != 0)
	// SM2 has BitSize = 256, which is divisible by 8, but test the logic
	// by using a value with high bits that need masking
	highBits := make([]byte, len(nBytes))
	for i := range highBits {
		highBits[i] = 0xFF
	}
	seqR3 := &seqReader{
		seq: [][]byte{highBits, paddedValid},
	}
	d, err = RandScalar(c, seqR3)
	if err != nil {
		t.Fatalf("RandScalar with high bits: %v", err)
	}
}

// TestCurve_Complete100 tests remaining uncovered lines
func TestCurve_Complete100(t *testing.T) {
	c := NewCurve().(*sm2Curve)
	gx, gy := c.params.Gx, c.params.Gy

	// Test ScalarBaseMult with empty NAF (k generates empty wNAF)
	// This is unlikely but we need to test the check
	result1, result2 := c.ScalarBaseMult([]byte{0})
	if result1 != nil || result2 != nil {
		t.Error("ScalarBaseMult(0) should return nil")
	}

	// Test ScalarMult with empty NAF
	result1, result2 = c.ScalarMult(gx, gy, []byte{0})
	if result1 != nil || result2 != nil {
		t.Error("ScalarMult(0) should return nil")
	}

	// Test ScalarBaseMult with valid small values to cover all paths
	result1, result2 = c.ScalarBaseMult([]byte{1})
	if result1 == nil || result2 == nil {
		t.Error("ScalarBaseMult(1) should return result")
	}

	result1, result2 = c.ScalarMult(gx, gy, []byte{1})
	if result1 == nil || result2 == nil {
		t.Error("ScalarMult(1) should return result")
	}

	// Test getBaseTable with double-check path (concurrent access simulation)
	// First clear cache
	baseTableCacheLock.Lock()
	delete(baseTableCache, 5)
	baseTableCacheLock.Unlock()

	// Get table (will create it)
	table1 := c.getBaseTable(5)
	if len(table1) == 0 {
		t.Error("getBaseTable should create table")
	}

	// Get again (should return cached - tests first exists check)
	table2 := c.getBaseTable(5)
	if len(table2) != len(table1) {
		t.Error("getBaseTable should return cached table")
	}

	// Note: Some lines are unreachable for SM2 specifically:
	// 1. RandScalar: (BitSize % 8 != 0) - SM2 has BitSize=256, 256%8=0
	// 2. ScalarBaseMult/ScalarMult: len(naf)==0 check after k!=0 - toWNAF never returns empty for k!=0
	// 3. getBaseTable: double-check exists in concurrent scenario - hard to trigger deterministically
	// These are defensive programming practices and acceptable for SM2-specific testing.
}

// TestCurve_ConcurrentGetBaseTable tests concurrent access to getBaseTable
func TestCurve_ConcurrentGetBaseTable(t *testing.T) {
	c := NewCurve().(*sm2Curve)

	// Clear cache for window size 3
	baseTableCacheLock.Lock()
	delete(baseTableCache, 3)
	baseTableCacheLock.Unlock()

	// Launch multiple goroutines to access the same table simultaneously
	// This tests the double-check locking mechanism
	const numGoroutines = 10
	results := make(chan [][3]field, numGoroutines)

	for range numGoroutines {
		go func() {
			table := c.getBaseTable(3)
			results <- table
		}()
	}

	// Collect results
	var firstTable [][3]field
	for i := range numGoroutines {
		table := <-results
		if i == 0 {
			firstTable = table
		}
		// All tables should have the same length
		if len(table) != len(firstTable) {
			t.Errorf("Concurrent getBaseTable returned different table sizes")
		}
	}

	if len(firstTable) == 0 {
		t.Error("getBaseTable should return non-empty table")
	}
}
