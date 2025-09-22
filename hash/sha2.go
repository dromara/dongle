package hash

import (
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"hash"
)

// BySha2 encrypts by SHA2 with specified size (224, 256, 384, 512) or HMAC-SHA2 based on whether key is set.
func (h Hasher) BySha2(size int) Hasher {
	if h.Error != nil {
		return h
	}
	var hasher func() hash.Hash
	switch size {
	case 224:
		hasher = sha256.New224
	case 256:
		hasher = sha256.New
	case 384:
		hasher = sha512.New384
	case 512:
		hasher = sha512.New
	default:
		h.Error = fmt.Errorf("hash/sha2: unsupported size: %d, supported sizes are 224, 256, 384, 512", size)
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
