package hash

import (
	"hash"

	"github.com/dromara/dongle/hash/sm3"
)

// BySm3 encrypts by SM3 or HMAC-SM3 based on whether key is set.
func (h *Hasher) BySm3() *Hasher {
	if h.Error != nil {
		return h
	}
	hasher := sm3.New
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
