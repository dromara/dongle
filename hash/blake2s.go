package hash

import (
	"fmt"
	"hash"

	"golang.org/x/crypto/blake2s"
)

// ByBlake2s encrypts by BLAKE2s with specified size (128, 256) or HMAC-BLAKE2s based on whether key is set.
func (h Hasher) ByBlake2s(size int) Hasher {
	if h.Error != nil {
		return h
	}

	// BLAKE2s-128 requires a key for security reasons
	if size == 128 && len(h.key) == 0 {
		h.Error = fmt.Errorf("hash/blake2s: BLAKE2s-128 requires a key for security reasons")
		return h
	}

	var hasher func() hash.Hash
	switch size {
	case 128:
		hasher = func() hash.Hash {
			hashFunc, _ := blake2s.New128(h.key)
			return hashFunc
		}
	case 256:
		hasher = func() hash.Hash {
			hashFunc, _ := blake2s.New256(nil)
			return hashFunc
		}
	default:
		h.Error = fmt.Errorf("hash/blake2s: unsupported size: %d, supported sizes are 128, 256", size)
		return h
	}
	if len(h.key) > 0 {
		return h.hmac(hasher)
	}
	if h.reader != nil {
		h.dst, h.Error = h.stream(func() hash.Hash {
			return hasher()
		})
		return h
	}
	if len(h.src) > 0 {
		hashFunc := hasher()
		hashFunc.Write(h.src)
		h.dst = hashFunc.Sum(nil)
	}
	return h
}
