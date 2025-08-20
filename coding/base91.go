package coding

import (
	"io"

	"gitee.com/golang-package/dongle/coding/base91"
)

// ByBase91 Encoders by base91.
func (e *Encoder) ByBase91() *Encoder {
	if e.Error != nil {
		return e
	}
	if e.reader != nil {
		e.dst, e.Error = e.stream(func(w io.Writer) io.WriteCloser {
			return base91.NewStreamEncoder(w)
		})
		return e
	}
	if len(e.src) > 0 {
		e.dst = base91.NewStdEncoder().Encode(e.src)
	}
	return e
}

// ByBase91 decodes by base91.
func (d *Decoder) ByBase91() *Decoder {
	if d.Error != nil {
		return d
	}
	if d.reader != nil {
		d.dst, d.Error = d.stream(func(r io.Reader) io.Reader {
			return base91.NewStreamDecoder(r)
		})
		return d
	}
	if len(d.src) > 0 {
		d.dst, d.Error = base91.NewStdDecoder().Decode(d.src)
	}
	return d
}
