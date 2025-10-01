package coding

import (
	"io"

	"github.com/dromara/dongle/coding/base45"
)

// ByBase45 encodes by base45.
func (e Encoder) ByBase45() Encoder {
	if e.Error != nil {
		return e
	}

	// Streaming encoding mode
	if e.reader != nil {
		e.dst, e.Error = e.stream(func(w io.Writer) io.WriteCloser {
			return base45.NewStreamEncoder(w)
		})
		return e
	}

	// Standard encoding mode
	if len(e.src) > 0 {
		e.dst = base45.NewStdEncoder().Encode(e.src)
	}

	return e
}

// ByBase45 decodes by base45.
func (d Decoder) ByBase45() Decoder {
	if d.Error != nil {
		return d
	}

	// Streaming decoding mode
	if d.reader != nil {
		d.dst, d.Error = d.stream(func(r io.Reader) io.Reader {
			return base45.NewStreamDecoder(r)
		})
		return d
	}

	// Standard decoding mode
	if len(d.src) > 0 {
		d.dst, d.Error = base45.NewStdDecoder().Decode(d.src)
	}

	return d
}
