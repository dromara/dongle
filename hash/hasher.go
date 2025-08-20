package hash

import (
	"crypto/hmac"
	"fmt"
	"hash"
	"io"
	"io/fs"

	"gitee.com/golang-package/dongle/coding"
	"gitee.com/golang-package/dongle/utils"
)

type Hasher struct {
	src    []byte
	dst    []byte
	key    []byte
	reader io.Reader
	Error  error
}

// NewHasher returns a new Hasher instance.
func NewHasher() *Hasher {
	return &Hasher{}
}

// FromString encrypts from string.
func (h *Hasher) FromString(s string) *Hasher {
	h.src = utils.String2Bytes(s)
	return h
}

// FromBytes encrypts from byte slice.
func (h *Hasher) FromBytes(b []byte) *Hasher {
	h.src = b
	return h
}

func (h *Hasher) FromFile(f fs.File) *Hasher {
	h.reader = f
	return h
}

// WithKey sets the key for HMAC calculation from byte slice.
func (h *Hasher) WithKey(key []byte) *Hasher {
	if len(key) == 0 {
		h.Error = fmt.Errorf("hmac: key cannot be empty")
		return h
	}
	h.key = key
	return h
}

// ToRawString outputs as raw string without encoding.
func (h *Hasher) ToRawString() string {
	return utils.Bytes2String(h.dst)
}

// ToRawBytes outputs as raw byte slice without encoding.
func (h *Hasher) ToRawBytes() []byte {
	return h.dst
}

// ToBase64String outputs as base64 string.
func (h *Hasher) ToBase64String() string {
	return coding.NewEncoder().FromBytes(h.dst).ByBase64().ToString()
}

// ToBase64Bytes outputs as base64 byte slice.
func (h *Hasher) ToBase64Bytes() []byte {
	return coding.NewEncoder().FromBytes(h.dst).ByBase64().ToBytes()
}

// ToHexString outputs as hex string.
func (h *Hasher) ToHexString() string {
	return coding.NewEncoder().FromBytes(h.dst).ByHex().ToString()
}

// ToHexBytes outputs as hex byte slice.
func (h *Hasher) ToHexBytes() []byte {
	return coding.NewEncoder().FromBytes(h.dst).ByHex().ToBytes()
}

// stream encrypts with stream.
func (h *Hasher) stream(fn func() hash.Hash) ([]byte, error) {
	hasher := fn()
	defer hasher.Reset()

	// Read all data from reader and hash it
	n, err := io.Copy(hasher, h.reader)
	if err != nil {
		return nil, err
	}

	// If no data was read, return empty result
	if n == 0 {
		return []byte{}, nil
	}

	// Return the hash result
	return hasher.Sum(nil), nil
}

// hmac calculates HMAC using the given hash function and key
func (h *Hasher) hmac(fn func() hash.Hash) *Hasher {
	if h.Error != nil {
		return h
	}

	// Check if key is set
	if len(h.key) == 0 {
		h.Error = fmt.Errorf("hmac: key not set, please call WithKey() first")
		return h
	}

	// Create HMAC hasher using the hashFunc and key
	hasher := hmac.New(fn, h.key)

	if len(h.src) > 0 {
		// Use source data for HMAC (non-streaming)
		hasher.Write(h.src)
	} else if h.reader != nil {
		// For streaming data, we need to read from the reader
		// Since the reader might have been consumed by previous operations,
		// we need to reset the position if it's a seeker

		// Try to reset the reader position if it's a seeker
		if seeker, ok := h.reader.(io.Seeker); ok {
			seeker.Seek(0, io.SeekStart)
		}

		// Now read from the reader
		n, _ := io.Copy(hasher, h.reader)
		// If no data was read, return empty result
		if n == 0 {
			h.dst = []byte{}
			return h
		}
	} else {
		// If no source data, return empty result
		h.dst = []byte{}
		return h
	}

	h.dst = hasher.Sum(nil)
	return h
}
