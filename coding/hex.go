package coding

import (
	"io"

	"gitee.com/golang-package/dongle/coding/hex"
)

// ByHex encodes by hex.
func (e *Encoder) ByHex() *Encoder {
	if e.Error != nil {
		return e
	}
	if e.reader != nil {
		e.dst, e.Error = e.stream(func(w io.Writer) io.WriteCloser {
			return hex.NewStreamEncoder(w)
		})
		return e
	}
	if len(e.src) > 0 {
		e.dst = hex.NewStdEncoder().Encode(e.src)
	}
	return e
}

// ByHex decodes by hex.
func (d *Decoder) ByHex() *Decoder {
	if d.Error != nil {
		return d
	}
	if d.reader != nil {
		d.dst, d.Error = d.stream(func(r io.Reader) io.Reader {
			return hex.NewStreamDecoder(r)
		})
		return d
	}
	if len(d.src) > 0 {
		d.dst, d.Error = hex.NewStdDecoder().Decode(d.src)
	}
	return d
}
