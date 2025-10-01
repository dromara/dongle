package coding

import (
	"io"

	"github.com/dromara/dongle/coding/hex"
)

// ByHex encodes by hex.
func (e Encoder) ByHex() Encoder {
	if e.Error != nil {
		return e
	}

	// Streaming encoding mode
	if e.reader != nil {
		e.dst, e.Error = e.stream(func(w io.Writer) io.WriteCloser {
			return hex.NewStreamEncoder(w)
		})
		return e
	}

	// Standard encoding mode
	if len(e.src) > 0 {
		e.dst = hex.NewStdEncoder().Encode(e.src)
	}

	return e
}

// ByHex decodes by hex.
func (d Decoder) ByHex() Decoder {
	if d.Error != nil {
		return d
	}

	// Streaming decoding mode
	if d.reader != nil {
		d.dst, d.Error = d.stream(func(r io.Reader) io.Reader {
			return hex.NewStreamDecoder(r)
		})
		return d
	}

	// Standard decoding mode
	if len(d.src) > 0 {
		d.dst, d.Error = hex.NewStdDecoder().Decode(d.src)
	}

	return d
}
