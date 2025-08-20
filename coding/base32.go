package coding

import (
	"io"

	"github.com/dromara/dongle/coding/base32"
)

// ByBase32 Encoders by base32.
func (e *Encoder) ByBase32() *Encoder {
	if e.Error != nil {
		return e
	}
	if e.reader != nil {
		e.dst, e.Error = e.stream(func(w io.Writer) io.WriteCloser {
			return base32.NewStreamEncoder(w, base32.StdAlphabet)
		})
		return e
	}
	if len(e.src) > 0 {
		e.dst = base32.NewStdEncoder(base32.StdAlphabet).Encode(e.src)
	}
	return e
}

// ByBase32 decodes by base32.
func (d *Decoder) ByBase32() *Decoder {
	if d.Error != nil {
		return d
	}
	if d.reader != nil {
		d.dst, d.Error = d.stream(func(r io.Reader) io.Reader {
			return base32.NewStreamDecoder(r, base32.StdAlphabet)
		})
		return d
	}
	if len(d.src) > 0 {
		d.dst, d.Error = base32.NewStdDecoder(base32.StdAlphabet).Decode(d.src)
	}
	return d
}

// ByBase32Hex Encoders by base32hex.
func (e *Encoder) ByBase32Hex() *Encoder {
	if e.Error != nil {
		return e
	}
	if e.reader != nil {
		e.dst, e.Error = e.stream(func(w io.Writer) io.WriteCloser {
			return base32.NewStreamEncoder(w, base32.HexAlphabet)
		})
		return e
	}
	if len(e.src) > 0 {
		e.dst = base32.NewStdEncoder(base32.HexAlphabet).Encode(e.src)
	}
	return e
}

// ByBase32Hex decodes by base32hex.
func (d *Decoder) ByBase32Hex() *Decoder {
	if d.Error != nil {
		return d
	}
	if d.reader != nil {
		d.dst, d.Error = d.stream(func(r io.Reader) io.Reader {
			return base32.NewStreamDecoder(r, base32.HexAlphabet)
		})
		return d
	}
	if len(d.src) > 0 {
		d.dst, d.Error = base32.NewStdDecoder(base32.HexAlphabet).Decode(d.src)
	}
	return d
}
