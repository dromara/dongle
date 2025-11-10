package sm2curve

import (
	"math/big"
	"sync"
)

// bigIntPool is a sync.Pool for reusing big.Int objects to reduce allocations.
var bigIntPool = sync.Pool{
	New: func() interface{} {
		return new(big.Int)
	},
}

// getBigInt gets a big.Int from the pool.
func getBigInt() *big.Int {
	return bigIntPool.Get().(*big.Int)
}

// putBigInt returns a big.Int to the pool after zeroing it.
func putBigInt(x *big.Int) {
	if x != nil {
		x.SetInt64(0)
		bigIntPool.Put(x)
	}
}

// putBigInts returns multiple big.Ints to the pool.
func putBigInts(xs ...*big.Int) {
	for _, x := range xs {
		putBigInt(x)
	}
}
