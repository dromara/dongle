package coding

import (
	"io"

	"github.com/dromara/dongle/coding/unicode"
)

// ByUnicode encodes by unicode.
func (e Encoder) ByUnicode() Encoder {
	if e.Error != nil {
		return e
	}

	// Streaming encoding mode
	if e.reader != nil {
		e.dst, e.Error = e.stream(func(w io.Writer) io.WriteCloser {
			return unicode.NewStreamEncoder(w)
		})
		return e
	}

	// Standard encoding mode
	if len(e.src) > 0 {
		e.dst = unicode.NewStdEncoder().Encode(e.src)
	}

	return e
}

// ByUnicode decodes by unicode.
func (d Decoder) ByUnicode() Decoder {
	if d.Error != nil {
		return d
	}

	// Streaming decoding mode
	if d.reader != nil {
		d.dst, d.Error = d.stream(func(r io.Reader) io.Reader {
			return unicode.NewStreamDecoder(r)
		})
		return d
	}

	// Standard decoding mode
	if len(d.src) > 0 {
		d.dst, d.Error = unicode.NewStdDecoder().Decode(d.src)
	}

	return d
}
