package coding

import (
	"io"

	"github.com/dromara/dongle/coding/base62"
)

// ByBase62 Encoders by base62.
func (e Encoder) ByBase62() Encoder {
	if e.Error != nil {
		return e
	}
	if e.reader != nil {
		e.dst, e.Error = e.stream(func(w io.Writer) io.WriteCloser {
			return base62.NewStreamEncoder(w)
		})
		return e
	}
	if len(e.src) > 0 {
		e.dst = base62.NewStdEncoder().Encode(e.src)
	}
	return e
}

// ByBase62 decodes by base62.
func (d Decoder) ByBase62() Decoder {
	if d.Error != nil {
		return d
	}
	if d.reader != nil {
		d.dst, d.Error = d.stream(func(r io.Reader) io.Reader {
			return base62.NewStreamDecoder(r)
		})
		return d
	}
	if len(d.src) > 0 {
		d.dst, d.Error = base62.NewStdDecoder().Decode(d.src)
	}
	return d
}
