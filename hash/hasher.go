// Package hash provides cryptographic hash functions and HMAC operations.
// It supports multiple hash algorithms including MD2, MD4, MD5, SHA1, SHA2, SHA3,
// BLAKE2b, BLAKE2s, RIPEMD160, and SM3, with both standard and streaming modes.
package hash

import (
	"crypto/hmac"
	"fmt"
	"hash"
	"io"
	"io/fs"

	"github.com/dromara/dongle/coding"
	"github.com/dromara/dongle/utils"
)

// BufferSize buffer size for streaming (64KB is a good balance)
var BufferSize = 64 * 1024

type Hasher struct {
	src    []byte
	dst    []byte
	key    []byte
	reader io.Reader
	Error  error
}

// NewHasher returns a new Hasher instance.
func NewHasher() Hasher {
	return Hasher{}
}

// FromString encrypts from string.
func (h Hasher) FromString(s string) Hasher {
	h.src = utils.String2Bytes(s)
	return h
}

// FromBytes encrypts from byte slice.
func (h Hasher) FromBytes(b []byte) Hasher {
	h.src = b
	return h
}

func (h Hasher) FromFile(f fs.File) Hasher {
	h.reader = f
	return h
}

// WithKey sets the key for HMAC calculation from byte slice.
func (h Hasher) WithKey(key []byte) Hasher {
	if len(key) == 0 {
		h.Error = fmt.Errorf("hmac: key cannot be empty")
		return h
	}
	h.key = key
	return h
}

// ToRawString outputs as raw string without encoding.
func (h Hasher) ToRawString() string {
	return utils.Bytes2String(h.dst)
}

// ToRawBytes outputs as raw byte slice without encoding.
func (h Hasher) ToRawBytes() []byte {
	if len(h.dst) == 0 {
		return []byte{}
	}
	return h.dst
}

// ToBase64String outputs as base64 string.
func (h Hasher) ToBase64String() string {
	if len(h.dst) == 0 {
		return ""
	}
	return coding.NewEncoder().FromBytes(h.dst).ByBase64().ToString()
}

// ToBase64Bytes outputs as base64 byte slice.
func (h Hasher) ToBase64Bytes() []byte {
	if len(h.dst) == 0 {
		return []byte{}
	}
	return coding.NewEncoder().FromBytes(h.dst).ByBase64().ToBytes()
}

// ToHexString outputs as hex string.
func (h Hasher) ToHexString() string {
	if len(h.dst) == 0 {
		return ""
	}
	return coding.NewEncoder().FromBytes(h.dst).ByHex().ToString()
}

// ToHexBytes outputs as hex byte slice.
func (h Hasher) ToHexBytes() []byte {
	if len(h.dst) == 0 {
		return []byte{}
	}
	return coding.NewEncoder().FromBytes(h.dst).ByHex().ToBytes()
}

func (h Hasher) stream(fn func() hash.Hash) ([]byte, error) {
	hasher := fn()
	defer hasher.Reset()

	// Try to reset the reader position if it's a seeker
	if seeker, ok := h.reader.(io.Seeker); ok {
		seeker.Seek(0, io.SeekStart)
	}

	copiedN, err := io.CopyBuffer(hasher, h.reader, make([]byte, BufferSize))
	if err != nil && err != io.EOF {
		return []byte{}, fmt.Errorf("hash: stream copy error: %w", err)
	}
	if copiedN == 0 {
		return []byte{}, nil
	}
	return hasher.Sum(nil), nil
}

func (h Hasher) hmac(fn func() hash.Hash) Hasher {
	if h.Error != nil {
		return h
	}

	if len(h.key) == 0 {
		h.Error = fmt.Errorf("hmac: key not set, please call WithKey() first")
		return h
	}

	hasher := hmac.New(fn, h.key)

	// Streaming mode
	if h.reader != nil {
		// Try to reset the reader position if it's a seeker
		if seeker, ok := h.reader.(io.Seeker); ok {
			seeker.Seek(0, io.SeekStart)
		}

		copiedN, err := io.CopyBuffer(hasher, h.reader, make([]byte, BufferSize))
		if err != nil && err != io.EOF {
			h.Error = fmt.Errorf("hmac: stream copy error: %w", err)
			return h
		}
		if copiedN == 0 {
			return h
		}
		h.dst = hasher.Sum(nil)
		return h
	}

	// Standard mode
	if len(h.src) > 0 {
		hasher.Write(h.src)
		h.dst = hasher.Sum(nil)
	}

	return h
}
