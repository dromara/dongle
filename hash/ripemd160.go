package hash

import (
	"hash"

	"golang.org/x/crypto/ripemd160"
)

// ByRipemd160 encrypts by RIPEMD160 or HMAC-RIPEMD160 based on whether key is set.
func (h Hasher) ByRipemd160() Hasher {
	if h.Error != nil {
		return h
	}
	hasher := ripemd160.New
	if len(h.key) > 0 {
		return h.hmac(func() hash.Hash {
			return hasher()
		})
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
