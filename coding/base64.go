package coding

import (
	"io"

	"github.com/dromara/dongle/coding/base64"
)

// ByBase64 Encoders by base64.
func (e *Encoder) ByBase64() *Encoder {
	if e.Error != nil {
		return e
	}
	if e.reader != nil {
		e.dst, e.Error = e.stream(func(w io.Writer) io.WriteCloser {
			return base64.NewStreamEncoder(w, base64.StdAlphabet)
		})
		return e
	}
	if len(e.src) > 0 {
		e.dst = base64.NewStdEncoder(base64.StdAlphabet).Encode(e.src)
	}
	return e
}

// ByBase64 decodes by base64.
func (d *Decoder) ByBase64() *Decoder {
	if d.Error != nil {
		return d
	}
	if d.reader != nil {
		d.dst, d.Error = d.stream(func(r io.Reader) io.Reader {
			return base64.NewStreamDecoder(r, base64.StdAlphabet)
		})
		return d
	}
	if len(d.src) > 0 {
		d.dst, d.Error = base64.NewStdDecoder(base64.StdAlphabet).Decode(d.src)
	}
	return d
}

// ByBase64Url Encoders by base64 url-safe.
func (e *Encoder) ByBase64Url() *Encoder {
	if e.Error != nil {
		return e
	}
	if e.reader != nil {
		e.dst, e.Error = e.stream(func(w io.Writer) io.WriteCloser {
			return base64.NewStreamEncoder(w, base64.URLAlphabet)
		})
		return e
	}
	if len(e.src) > 0 {
		e.dst = base64.NewStdEncoder(base64.URLAlphabet).Encode(e.src)
	}
	return e
}

// ByBase64Url decodes by base64 url-safe.
func (d *Decoder) ByBase64Url() *Decoder {
	if d.Error != nil {
		return d
	}
	if d.reader != nil {
		d.dst, d.Error = d.stream(func(r io.Reader) io.Reader {
			return base64.NewStreamDecoder(r, base64.URLAlphabet)
		})
		return d
	}
	if len(d.src) > 0 {
		d.dst, d.Error = base64.NewStdDecoder(base64.URLAlphabet).Decode(d.src)
	}
	return d
}
