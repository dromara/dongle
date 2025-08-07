package coding

import (
	"io"

	"github.com/dromara/dongle/coding/base100"
)

// ByBase100 Encoders by base100.
func (e *Encoder) ByBase100() *Encoder {
	if e.Error != nil {
		return e
	}
	if e.reader != nil {
		e.dst, e.Error = e.stream(func(w io.Writer) io.WriteCloser {
			return base100.NewStreamEncoder(w)
		})
		return e
	}
	if len(e.src) > 0 {
		e.dst = base100.NewStdEncoder().Encode(e.src)
	}
	return e
}

// ByBase100 decodes by base100.
func (d *Decoder) ByBase100() *Decoder {
	if d.Error != nil {
		return d
	}
	if d.reader != nil {
		d.dst, d.Error = d.stream(func(r io.Reader) io.Reader {
			return base100.NewStreamDecoder(r)
		})
		return d
	}
	if len(d.src) > 0 {
		d.dst, d.Error = base100.NewStdDecoder().Decode(d.src)
	}
	return d
}
