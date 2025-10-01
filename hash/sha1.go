package hash

import (
	"crypto/sha1"
	"hash"
)

// BySha1 encrypts by SHA1 or HMAC-SHA1 based on whether key is set.
func (h Hasher) BySha1() Hasher {
	if h.Error != nil {
		return h
	}
	hasher := sha1.New

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
		hashSum := sha1.Sum(h.src)
		h.dst = hashSum[:]
	}
	return h
}
