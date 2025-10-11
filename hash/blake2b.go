package hash

import (
	"fmt"
	"hash"

	"golang.org/x/crypto/blake2b"
)

// ByBlake2b computes the BLAKE2b hash or hmac of the input data.
func (h Hasher) ByBlake2b(size int) Hasher {
	if h.Error != nil {
		return h
	}
	var hasher func() hash.Hash
	switch size {
	case 256:
		hasher = func() hash.Hash {
			hashFunc, _ := blake2b.New256(nil)
			return hashFunc
		}
	case 384:
		hasher = func() hash.Hash {
			hashFunc, _ := blake2b.New384(nil)
			return hashFunc
		}
	case 512:
		hasher = func() hash.Hash {
			hashFunc, _ := blake2b.New512(nil)
			return hashFunc
		}
	default:
		h.Error = fmt.Errorf("hash/blake2b: unsupported size: %d, supported sizes are 256, 384, 512", size)
		return h
	}

	// Hmac mode
	if len(h.key) > 0 {
		return h.hmac(hasher)
	}

	// Streaming mode
	if h.reader != nil {
		h.dst, h.Error = h.stream(func() hash.Hash {
			return hasher()
		})
		return h
	}

	// Standard mode
	if len(h.src) > 0 {
		hashFunc := hasher()
		hashFunc.Write(h.src)
		h.dst = hashFunc.Sum(nil)
	}
	return h
}
