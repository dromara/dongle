package hash

import (
	"hash"

	"golang.org/x/crypto/md4"
)

// ByMd4 computes the MD4 hash or hmac of the input data.
func (h Hasher) ByMd4() Hasher {
	if h.Error != nil {
		return h
	}
	hasher := md4.New

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
