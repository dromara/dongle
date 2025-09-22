package hash

import (
	"hash"

	"golang.org/x/crypto/md4"
)

// ByMd4 encrypts by MD4 or HMAC-MD4 based on whether key is set.
func (h Hasher) ByMd4() Hasher {
	if h.Error != nil {
		return h
	}
	hasher := md4.New
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
