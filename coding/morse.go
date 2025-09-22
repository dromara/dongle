package coding

import (
	"io"

	"github.com/dromara/dongle/coding/morse"
)

// ByMorse encodes by morse code.
func (e Encoder) ByMorse() Encoder {
	if e.Error != nil {
		return e
	}

	if e.reader != nil {
		e.dst, e.Error = e.stream(func(w io.Writer) io.WriteCloser {
			return morse.NewStreamEncoder(w)
		})
		return e
	}

	if len(e.src) == 0 {
		return e
	}
	encoder := morse.NewStdEncoder()
	e.dst = encoder.Encode(e.src)
	if encoder.Error != nil {
		e.Error = encoder.Error
	}
	return e
}

// ByMorse decodes by morse code.
func (d Decoder) ByMorse() Decoder {
	if d.Error != nil {
		return d
	}

	if d.reader != nil {
		d.dst, d.Error = d.stream(func(r io.Reader) io.Reader {
			return morse.NewStreamDecoder(r)
		})
		return d
	}

	if len(d.src) == 0 {
		return d
	}
	d.dst, d.Error = morse.NewStdDecoder().Decode(d.src)
	return d
}
