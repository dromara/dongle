package coding

import (
	"io"

	"gitee.com/golang-package/dongle/coding/base85"
)

// ByBase85 encodes by base85.
func (e *Encoder) ByBase85() *Encoder {
	if e.Error != nil {
		return e
	}
	if e.reader != nil {
		e.dst, e.Error = e.stream(func(w io.Writer) io.WriteCloser {
			return base85.NewStreamEncoder(w)
		})
		return e
	}
	if len(e.src) > 0 {
		e.dst = base85.NewStdEncoder().Encode(e.src)
	}
	return e
}

// ByBase85 decodes by base85.
func (d *Decoder) ByBase85() *Decoder {
	if d.Error != nil {
		return d
	}
	if d.reader != nil {
		d.dst, d.Error = d.stream(func(r io.Reader) io.Reader {
			return base85.NewStreamDecoder(r)
		})
		return d
	}
	if len(d.src) > 0 {
		d.dst, d.Error = base85.NewStdDecoder().Decode(d.src)
	}
	return d
}
