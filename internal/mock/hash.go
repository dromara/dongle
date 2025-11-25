package mock

// ErrorHasher is a mock implementation of hash.Hash that can return errors on Write operations.
// This is useful for testing error handling in code that uses hash.Hash interfaces.
type ErrorHasher struct {
	writeErr error // Error to return from Write method
}

// NewErrorHasher creates a new ErrorHasher that will return the specified error
// when Write() is called. This is useful for testing hash write error scenarios.
func NewErrorHasher(writeErr error) *ErrorHasher {
	return &ErrorHasher{writeErr: writeErr}
}

// Write implements the hash.Hash interface and returns the configured error.
// This simulates a hash write failure for testing purposes.
func (h *ErrorHasher) Write(p []byte) (n int, err error) {
	if h.writeErr != nil {
		return 0, h.writeErr
	}
	return len(p), nil
}

// Sum implements the hash.Hash interface and returns a mock hash value.
// This always succeeds and returns a unique mock hash for testing.
func (h *ErrorHasher) Sum(b []byte) []byte {
	// Return unique hash based on writeErr to satisfy HMAC requirements
	hash := make([]byte, 32)
	if h.writeErr != nil {
		// Use error message hash to make it unique
		errStr := h.writeErr.Error()
		for i := range hash {
			if i < len(errStr) {
				hash[i] = errStr[i]
			} else {
				hash[i] = byte(i)
			}
		}
	} else {
		for i := range hash {
			hash[i] = byte(i + 1)
		}
	}
	return append(b, hash...)
}

// Reset implements the hash.Hash interface but does nothing in this mock.
func (h *ErrorHasher) Reset() {
	// This is a no-op method, but we add a simple operation
	// to ensure proper coverage tracking
	_ = h.writeErr
}

// Size implements the hash.Hash interface and returns a mock hash size.
func (h *ErrorHasher) Size() int {
	return 32
}

// BlockSize implements the hash.Hash interface and returns a mock block size.
func (h *ErrorHasher) BlockSize() int {
	return 64
}
