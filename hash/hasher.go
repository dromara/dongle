package hash

import (
	"crypto/hmac"
	"fmt"
	"hash"
	"io"
	"io/fs"

	"github.com/dromara/dongle/coding"
	"github.com/dromara/dongle/util"
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
	h.src = util.String2Bytes(s)
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
	return util.Bytes2String(h.dst)
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

// stream encrypts with stream using true streaming processing.
func (h Hasher) stream(fn func() hash.Hash) ([]byte, error) {
	hasher := fn()
	defer hasher.Reset()

	buffer := make([]byte, BufferSize)

	var hasData bool

	// Stream process data in chunks
	for {
		// Read a chunk of data
		n, err := h.reader.Read(buffer)

		// Handle read errors
		if err != nil && err != io.EOF {
			return []byte{}, fmt.Errorf("stream read error: %w", err)
		}

		// If we read some data, process it immediately
		if n > 0 {
			hasData = true
			// Write the chunk to the hasher for immediate processing
			_, writeErr := hasher.Write(buffer[:n])
			if writeErr != nil {
				return []byte{}, fmt.Errorf("hasher write error: %w", writeErr)
			}
		}

		// If we've reached EOF, break the loop
		if err == io.EOF {
			break
		}
	}

	// If no data was read, return empty result
	if !hasData {
		return []byte{}, nil
	}

	// Return the hash result
	return hasher.Sum(nil), nil
}

// hmac calculates HMAC using the given hash function and key
func (h Hasher) hmac(fn func() hash.Hash) Hasher {
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
		// Try to reset the reader position if it's a seeker
		if seeker, ok := h.reader.(io.Seeker); ok {
			seeker.Seek(0, io.SeekStart)
		}

		buffer := make([]byte, BufferSize)

		var totalBytes int64
		var hasData bool

		// Stream process data in chunks
		for {
			// Read a chunk of data
			n, err := h.reader.Read(buffer)

			// Handle read errors
			if err != nil && err != io.EOF {
				h.Error = fmt.Errorf("hmac stream read error: %w", err)
				return h
			}

			// If we read some data, process it immediately
			if n > 0 {
				hasData = true
				totalBytes += int64(n)

				// Write the chunk to the hasher for immediate processing
				_, writeErr := hasher.Write(buffer[:n])
				if writeErr != nil {
					h.Error = fmt.Errorf("hmac hasher write error: %w", writeErr)
					return h
				}
			}

			// If we've reached EOF, break the loop
			if err == io.EOF {
				break
			}
		}

		// If no data was read, return empty result
		if !hasData {
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
