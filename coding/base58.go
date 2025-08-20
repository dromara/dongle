package coding

import (
	"io"

	"gitee.com/golang-package/dongle/coding/base58"
)

// ByBase58 Encoders by base58.
func (e *Encoder) ByBase58() *Encoder {
	if e.Error != nil {
		return e
	}
	if e.reader != nil {
		e.dst, e.Error = e.stream(func(w io.Writer) io.WriteCloser {
			return base58.NewStreamEncoder(w)
		})
		return e
	}
	if len(e.src) > 0 {
		e.dst = base58.NewStdEncoder().Encode(e.src)
	}
	return e
}

// ByBase58 decodes by base58.
func (d *Decoder) ByBase58() *Decoder {
	if d.Error != nil {
		return d
	}
	if d.reader != nil {
		d.dst, d.Error = d.stream(func(r io.Reader) io.Reader {
			return base58.NewStreamDecoder(r)
		})
		return d
	}
	if len(d.src) > 0 {
		d.dst, d.Error = base58.NewStdDecoder().Decode(d.src)
	}
	return d
}
