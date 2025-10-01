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

	// Streaming encoding mode
	if e.reader != nil {
		e.dst, e.Error = e.stream(func(w io.Writer) io.WriteCloser {
			return morse.NewStreamEncoder(w)
		})
		return e
	}

	// Standard encoding mode
	if len(e.src) > 0 {
		encoder := morse.NewStdEncoder()
		e.Error = encoder.Error
		e.dst = encoder.Encode(e.src)
	}

	return e
}

// ByMorse decodes by morse code.
func (d Decoder) ByMorse() Decoder {
	if d.Error != nil {
		return d
	}

	// Streaming decoding mode
	if d.reader != nil {
		d.dst, d.Error = d.stream(func(r io.Reader) io.Reader {
			return morse.NewStreamDecoder(r)
		})
		return d
	}

	// Standard decoding mode
	if len(d.src) > 0 {
		d.dst, d.Error = morse.NewStdDecoder().Decode(d.src)
	}

	return d
}
