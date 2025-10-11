package hash

import (
	"fmt"
	"hash"

	"golang.org/x/crypto/sha3"
)

// BySha3 computes the SHA3 hash or hmac of the input data.
func (h Hasher) BySha3(size int) Hasher {
	if h.Error != nil {
		return h
	}
	var hasher func() hash.Hash
	switch size {
	case 224:
		hasher = sha3.New224
	case 256:
		hasher = sha3.New256
	case 384:
		hasher = sha3.New384
	case 512:
		hasher = sha3.New512
	default:
		h.Error = fmt.Errorf("hash/sha3: unsupported size: %d, supported sizes are 224, 256, 384, 512", size)
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
