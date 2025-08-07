package hash

import (
	"crypto/md5"
	"hash"
)

// ByMd5 encrypts by MD5 or HMAC-MD5 based on whether key is set.
func (h *Hasher) ByMd5() *Hasher {
	if h.Error != nil {
		return h
	}
	hasher := md5.New
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
		hashSum := md5.Sum(h.src)
		h.dst = hashSum[:]
	}
	return h
}
