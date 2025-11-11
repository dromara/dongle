package sm2curve

import (
	"math/big"
	"sync"
	"testing"
)

// TestGetBigInt tests getBigInt function
func TestGetBigInt(t *testing.T) {
	// Get a big.Int from pool
	bi := getBigInt()
	if bi == nil {
		t.Fatal("getBigInt() returned nil")
	}

	// Should be a valid big.Int
	if _, ok := interface{}(bi).(*big.Int); !ok {
		t.Error("getBigInt() did not return *big.Int")
	}

	// Test that it returns a usable big.Int
	bi.SetInt64(123)
	if bi.Int64() != 123 {
		t.Error("returned big.Int is not usable")
	}
}

// TestPutBigInt tests putBigInt function
func TestPutBigInt(t *testing.T) {
	// Test with non-nil big.Int
	bi := new(big.Int).SetInt64(12345)
	putBigInt(bi)

	// Verify it was zeroed
	if bi.Sign() != 0 {
		t.Error("putBigInt() did not zero the big.Int")
	}

	// Test with nil (should not panic)
	putBigInt(nil)

	// Test that we can get it back from pool
	bi2 := getBigInt()
	if bi2 == nil {
		t.Error("getBigInt() after putBigInt() returned nil")
	}
}

// TestPutBigInts tests putBigInts function with multiple values
func TestPutBigInts(t *testing.T) {
	// Create multiple big.Ints with different values
	bi1 := new(big.Int).SetInt64(100)
	bi2 := new(big.Int).SetInt64(200)
	bi3 := new(big.Int).SetInt64(300)

	// Put them all back
	putBigInts(bi1, bi2, bi3)

	// Verify all were zeroed
	if bi1.Sign() != 0 {
		t.Error("putBigInts() did not zero bi1")
	}
	if bi2.Sign() != 0 {
		t.Error("putBigInts() did not zero bi2")
	}
	if bi3.Sign() != 0 {
		t.Error("putBigInts() did not zero bi3")
	}

	// Test with empty slice
	putBigInts()

	// Test with nil values in slice
	putBigInts(nil, bi1, nil, bi2)

	// Test with single value
	bi4 := new(big.Int).SetInt64(999)
	putBigInts(bi4)
	if bi4.Sign() != 0 {
		t.Error("putBigInts() with single value did not zero it")
	}
}

// TestPoolReuse tests that the pool actually reuses objects
func TestPoolReuse(t *testing.T) {
	// Get a big.Int and set a marker value
	bi1 := getBigInt()
	bi1.SetInt64(42)

	// Put it back
	putBigInt(bi1)

	// Get another one - might be the same object (zeroed)
	bi2 := getBigInt()
	if bi2 == nil {
		t.Fatal("getBigInt() returned nil")
	}

	// It should be zeroed
	if bi2.Sign() != 0 {
		t.Error("reused big.Int was not properly zeroed")
	}
}

// TestPoolConcurrency tests concurrent access to the pool
func TestPoolConcurrency(t *testing.T) {
	const goroutines = 100
	const iterations = 1000

	var wg sync.WaitGroup
	wg.Add(goroutines)

	for i := 0; i < goroutines; i++ {
		go func(id int) {
			defer wg.Done()

			for j := 0; j < iterations; j++ {
				// Get from pool
				bi := getBigInt()
				if bi == nil {
					t.Error("getBigInt() returned nil in concurrent test")
					return
				}

				// Use it
				bi.SetInt64(int64(id*iterations + j))

				// Put it back
				putBigInt(bi)
			}
		}(i)
	}

	wg.Wait()
}

// TestPoolNewFunction tests that pool's New function works correctly
func TestPoolNewFunction(t *testing.T) {
	// Create a new pool to test the New function independently
	testPool := sync.Pool{
		New: func() interface{} {
			return new(big.Int)
		},
	}

	// Get from empty pool (should call New)
	bi := testPool.Get().(*big.Int)
	if bi == nil {
		t.Fatal("Pool.New() returned nil")
	}

	// Verify it's a usable big.Int
	bi.SetInt64(789)
	if bi.Int64() != 789 {
		t.Error("big.Int from Pool.New() is not usable")
	}
}

// TestPutBigIntZeroing tests that putBigInt properly zeros various big.Int values
func TestPutBigIntZeroing(t *testing.T) {
	testCases := []struct {
		name  string
		value *big.Int
	}{
		{"positive", big.NewInt(12345)},
		{"negative", big.NewInt(-67890)},
		{"zero", big.NewInt(0)},
		{"large positive", new(big.Int).Lsh(big.NewInt(1), 256)},
		{"large negative", new(big.Int).Neg(new(big.Int).Lsh(big.NewInt(1), 256))},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			bi := new(big.Int).Set(tc.value)
			putBigInt(bi)

			if bi.Sign() != 0 {
				t.Errorf("putBigInt() did not zero %s value", tc.name)
			}
			if bi.BitLen() != 0 {
				t.Errorf("putBigInt() did not properly zero %s value (BitLen=%d)", tc.name, bi.BitLen())
			}
		})
	}
}

// TestGetPutCycle tests multiple get/put cycles
func TestGetPutCycle(t *testing.T) {
	for i := 0; i < 100; i++ {
		bi := getBigInt()
		if bi == nil {
			t.Fatalf("cycle %d: getBigInt() returned nil", i)
		}

		// Set a value
		bi.SetInt64(int64(i))

		// Put it back
		putBigInt(bi)

		// Should be zeroed
		if bi.Sign() != 0 {
			t.Errorf("cycle %d: big.Int not zeroed after putBigInt()", i)
		}
	}
}
