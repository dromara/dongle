package hash

import (
	"hash"

	"github.com/dromara/dongle/hash/md2"
)

// ByMd2 encrypts by MD2 or HMAC-MD2 based on whether key is set.
func (h *Hasher) ByMd2() *Hasher {
	if h.Error != nil {
		return h
	}
	hasher := md2.New
	if len(h.key) > 0 {
		return h.hmac(hasher)
	}
	hashFunc := hasher()
	if h.reader != nil {
		h.dst, h.Error = h.stream(func() hash.Hash {
			return hashFunc
		})
		return h
	}
	if len(h.src) > 0 {
		hashFunc.Write(h.src)
		h.dst = hashFunc.Sum(nil)
	}
	return h
}
