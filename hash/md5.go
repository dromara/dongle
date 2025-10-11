package hash

import (
	"crypto/md5"
	"hash"
)

// ByMd5 computes the MD5 hash or hmac of the input data.
func (h Hasher) ByMd5() Hasher {
	if h.Error != nil {
		return h
	}
	hasher := md5.New

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
		hashSum := md5.Sum(h.src)
		h.dst = hashSum[:]
	}
	return h
}
