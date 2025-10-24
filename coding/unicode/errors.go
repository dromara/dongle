package unicode

import "errors"

// Common unicode encoding/decoding errors
var (
	// ErrInvalidUnicode is returned when invalid unicode data is encountered
	ErrInvalidUnicode = errors.New("invalid unicode data")

	// ErrDecodeFailed is returned when unicode decoding fails
	ErrDecodeFailed = errors.New("unicode decode failed")

	// ErrEncodeFailed is returned when unicode encoding fails
	ErrEncodeFailed = errors.New("unicode encode failed")
)
