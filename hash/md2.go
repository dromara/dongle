package hash

import (
	"hash"

	"github.com/dromara/dongle/hash/md2"
)

// ByMd2 computes the MD2 hash or hmac of the input data.
func (h Hasher) ByMd2() Hasher {
	if h.Error != nil {
		return h
	}
	hasher := md2.New

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
