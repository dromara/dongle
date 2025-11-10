// Package sm2 implements SM2 public key encryption and decryption
// with optional streaming helpers.
package sm2

import (
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/binary"
	"io"
	"math/big"

	"github.com/dromara/dongle/crypto/internal/sm2curve"
	"github.com/dromara/dongle/crypto/keypair"
	"github.com/dromara/dongle/hash/sm3"
)

// This package implements only encryption/decryption. Signing code is removed.

// StdEncrypter encrypts data using an SM2 public key.
// The ciphertext component order is derived from Sm2KeyPair.Order.
type StdEncrypter struct {
	keypair *keypair.Sm2KeyPair
	order   keypair.CipherOrder
	Error   error
}

// NewStdEncrypter creates a new SM2 encrypter bound to the given key pair.
func NewStdEncrypter(kp *keypair.Sm2KeyPair) *StdEncrypter {
	e := &StdEncrypter{keypair: kp, order: keypair.C1C3C2}
	if kp == nil {
		e.Error = NilKeyPairError{}
		return e
	}
	if len(kp.PublicKey) == 0 {
		e.Error = KeyPairError{Err: nil}
	}
	// pick order from keypair setting
	if kp.Order == keypair.C1C2C3 {
		e.order = keypair.C1C2C3
	} else {
		e.order = keypair.C1C3C2
	}
	return e
}

// Encrypt encrypts data with SM2 public key.
func (e *StdEncrypter) Encrypt(src []byte) (dst []byte, err error) {
	if e.Error != nil {
		return nil, e.Error
	}
	if len(src) == 0 {
		return nil, nil
	}
	pub, err := e.keypair.ParsePublicKey()
	if err != nil {
		e.Error = KeyPairError{Err: err}
		return nil, e.Error
	}
	out := encrypt(pub, src, e.order, e.keypair.Window)
	return out, nil
}

// StreamEncrypter buffers plaintext and writes SM2 ciphertext on Close.
type StreamEncrypter struct {
	writer  io.Writer
	keypair *keypair.Sm2KeyPair
	order   keypair.CipherOrder
	buffer  []byte
	Error   error
}

// NewStreamEncrypter returns a WriteCloser that encrypts all written data
// with the provided key pair and writes the ciphertext on Close.
func NewStreamEncrypter(w io.Writer, kp *keypair.Sm2KeyPair) io.WriteCloser {
	e := &StreamEncrypter{
		writer:  w,
		keypair: kp,
		order:   keypair.C1C3C2,
		buffer:  make([]byte, 0),
	}
	if kp == nil {
		e.Error = NilKeyPairError{}
		return e
	}
	if len(kp.PublicKey) == 0 {
		e.Error = KeyPairError{Err: nil}
	}
	// pick order from keypair setting
	if kp.Order == keypair.C1C2C3 {
		e.order = keypair.C1C2C3
	} else {
		e.order = keypair.C1C3C2
	}
	return e
}

// Write buffers plaintext to be encrypted.
func (e *StreamEncrypter) Write(p []byte) (n int, err error) {
	if e.Error != nil {
		return 0, e.Error
	}
	if len(p) == 0 {
		return 0, nil
	}
	e.buffer = append(e.buffer, p...)
	return len(p), nil
}

// Close encrypts the buffered plaintext and writes the ciphertext to the
// underlying writer. If the writer implements io.Closer, it is closed.
func (e *StreamEncrypter) Close() error {
	if e.Error != nil {
		return e.Error
	}
	if len(e.buffer) == 0 {
		if closer, ok := e.writer.(io.Closer); ok {
			return closer.Close()
		}
		return nil
	}
	// Encrypt and write
	out, err := NewStdEncrypter(e.keypair).Encrypt(e.buffer)
	if err != nil {
		return err
	}
	if _, err = e.writer.Write(out); err != nil {
		return err
	}
	if closer, ok := e.writer.(io.Closer); ok {
		return closer.Close()
	}
	return nil
}

// StdDecrypter decrypts data using an SM2 private key.
type StdDecrypter struct {
	keypair *keypair.Sm2KeyPair
	order   keypair.CipherOrder
	Error   error
}

// NewStdDecrypter creates a new SM2 decrypter bound to the given key pair.
func NewStdDecrypter(kp *keypair.Sm2KeyPair) *StdDecrypter {
	d := &StdDecrypter{keypair: kp, order: keypair.C1C3C2}
	if kp == nil {
		d.Error = NilKeyPairError{}
		return d
	}
	if len(kp.PrivateKey) == 0 {
		d.Error = KeyPairError{Err: nil}
	}
	// pick order from keypair setting
	if kp.Order == keypair.C1C2C3 {
		d.order = keypair.C1C2C3
	} else {
		d.order = keypair.C1C3C2
	}
	return d
}

// Decrypt decrypts data with SM2 private key.
func (d *StdDecrypter) Decrypt(src []byte) (dst []byte, err error) {
	if d.Error != nil {
		return nil, d.Error
	}
	if len(src) == 0 {
		return nil, nil
	}
	pri, err := d.keypair.ParsePrivateKey()
	if err != nil {
		d.Error = KeyPairError{Err: err}
		return nil, d.Error
	}
	out, err := decrypt(pri, src, d.order, d.keypair.Window)
	if err != nil {
		d.Error = DecryptError{Err: err}
		return nil, d.Error
	}
	return out, nil
}

// StreamDecrypter reads all ciphertext from an io.Reader and exposes the
// decrypted plaintext via Read.
type StreamDecrypter struct {
	reader    io.Reader
	keypair   *keypair.Sm2KeyPair
	order     keypair.CipherOrder
	decrypted []byte
	pos       int
	Error     error
}

// NewStreamDecrypter creates a Reader that decrypts the entire input from r
// using the provided key pair, serving plaintext on subsequent Read calls.
func NewStreamDecrypter(r io.Reader, kp *keypair.Sm2KeyPair) io.Reader {
	d := &StreamDecrypter{
		reader:  r,
		keypair: kp,
		order:   keypair.C1C3C2,
		pos:     0,
	}
	if kp == nil {
		d.Error = NilKeyPairError{}
		return d
	}
	if len(kp.PrivateKey) == 0 {
		d.Error = KeyPairError{Err: nil}
	}
	// pick order from keypair setting
	if kp.Order == keypair.C1C2C3 {
		d.order = keypair.C1C2C3
	} else {
		d.order = keypair.C1C3C2
	}
	return d
}

// Read serves decrypted plaintext from the internal buffer.
func (d *StreamDecrypter) Read(p []byte) (n int, err error) {
	if d.Error != nil {
		return 0, d.Error
	}
	// Serve from decrypted buffer if available
	if d.pos < len(d.decrypted) {
		n = copy(p, d.decrypted[d.pos:])
		d.pos += n
		if d.pos >= len(d.decrypted) {
			return n, io.EOF
		}
		return n, nil
	}
	// Otherwise, read all ciphertext and decrypt once
	enc, err := io.ReadAll(d.reader)
	if err != nil {
		d.Error = ReadError{Err: err}
		return 0, d.Error
	}
	if len(enc) == 0 {
		return 0, io.EOF
	}
	out, err := NewStdDecrypter(d.keypair).Decrypt(enc)
	if err != nil {
		d.Error = err
		return 0, d.Error
	}
	d.decrypted = out
	d.pos = 0
	// Return plaintext
	n = copy(p, d.decrypted)
	d.pos += n
	if d.pos >= len(d.decrypted) {
		return n, io.EOF
	}
	return n, nil
}

// intToBytes returns x encoded as a 4‑byte big‑endian slice.
func intToBytes(x int) []byte {
	var buf [4]byte
	binary.BigEndian.PutUint32(buf[:], uint32(x))
	return buf[:]
}

// padLeft left‑pads b with zeros to reach size bytes.
func padLeft(b []byte, size int) []byte {
	if len(b) >= size {
		return b
	}
	out := make([]byte, size)
	copy(out[size-len(b):], b)
	return out
}

// sm3KDF derives length bytes using SM3 over the provided parts.
func sm3KDF(length int, parts ...[]byte) (out []byte, ok bool) {
	out = make([]byte, length) // Pre-allocate output buffer
	ct := 1
	h := sm3.New()
	blocks := (length + 31) / 32
	for i := 0; i < blocks; i++ {
		h.Reset()
		for _, p := range parts {
			h.Write(p)
		}
		h.Write(intToBytes(ct))
		sum := h.Sum(nil)
		start := i * 32
		end := start + 32
		if end > length {
			end = length
		}
		copy(out[start:end], sum[:end-start])
		ct++
	}
	return out, true
}

// bytesEqual compares two byte slices in constant time.
func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var v byte
	for i := range a {
		v |= a[i] ^ b[i]
	}
	return v == 0
}

// encrypt applies SM2 public‑key encryption with the requested order and window.
func encrypt(pub *ecdsa.PublicKey, src []byte, order keypair.CipherOrder, window int) []byte {
	n := len(src)
	curve := sm2curve.New()
	if window >= 2 && window <= 6 {
		sm2curve.SetWindow(curve, window)
	}
	coordLen := (curve.Params().BitSize + 7) / 8
	k, _ := sm2curve.RandScalar(curve, rand.Reader)
	x1, y1 := curve.ScalarBaseMult(k.Bytes())
	x2, y2 := curve.ScalarMult(pub.X, pub.Y, k.Bytes())
	x1b := padLeft(x1.Bytes(), coordLen)
	y1b := padLeft(y1.Bytes(), coordLen)
	x2b := padLeft(x2.Bytes(), coordLen)
	y2b := padLeft(y2.Bytes(), coordLen)

	// C1: uncompressed point (x1||y1)
	c1 := make([]byte, 0, 2*coordLen)
	c1 = append(c1, x1b...)
	c1 = append(c1, y1b...)

	// C3 = SM3(x2 || M || y2)
	macInput := make([]byte, 0, len(x2b)+n+len(y2b))
	macInput = append(macInput, x2b...)
	macInput = append(macInput, src...)
	macInput = append(macInput, y2b...)
	hh := sm3.New()
	hh.Write(macInput)
	c3 := hh.Sum(nil)

	// C2 = M XOR KDF(x2||y2)
	mask, _ := sm3KDF(n, x2b, y2b)
	c2 := make([]byte, n)
	for i := 0; i < n; i++ {
		c2[i] = src[i] ^ mask[i]
	}

	var payload []byte
	if order == keypair.C1C2C3 {
		payload = append(append(c1, c2...), c3...)
	} else {
		payload = append(append(c1, c3...), c2...)
	}
	return append([]byte{0x04}, payload...)
}

// decrypt applies SM2 private‑key decryption with the requested order and window.
func decrypt(pri *ecdsa.PrivateKey, src []byte, order keypair.CipherOrder, window int) ([]byte, error) {
	if len(src) < 1 {
		return nil, io.ErrUnexpectedEOF
	}
	if src[0] == 0x04 {
		src = src[1:]
	}
	curve := sm2curve.New()
	if window >= 2 && window <= 6 {
		sm2curve.SetWindow(curve, window)
	}
	coordLen := (curve.Params().BitSize + 7) / 8
	if len(src) < 2*coordLen+32 {
		return nil, io.ErrUnexpectedEOF
	}
	x := new(big.Int).SetBytes(src[:coordLen])
	y := new(big.Int).SetBytes(src[coordLen : 2*coordLen])
	x2, y2 := curve.ScalarMult(x, y, pri.D.Bytes())
	x2b := padLeft(x2.Bytes(), coordLen)
	y2b := padLeft(y2.Bytes(), coordLen)
	if order == keypair.C1C2C3 {
		n := len(src) - (2*coordLen + 32)
		mask, _ := sm3KDF(n, x2b, y2b)
		m := make([]byte, n)
		for i := 0; i < n; i++ {
			m[i] = src[2*coordLen+i] ^ mask[i]
		}
		macInput := make([]byte, 0, len(x2b)+n+len(y2b))
		macInput = append(macInput, x2b...)
		macInput = append(macInput, m...)
		macInput = append(macInput, y2b...)
		hh := sm3.New()
		hh.Write(macInput)
		if !bytesEqual(hh.Sum(nil), src[2*coordLen+n:]) {
			return nil, io.ErrUnexpectedEOF
		}
		return m, nil
	}
	n := len(src) - (2*coordLen + 32)
	mask, _ := sm3KDF(n, x2b, y2b)
	m := make([]byte, n)
	for i := 0; i < n; i++ {
		m[i] = src[2*coordLen+32+i] ^ mask[i]
	}
	macInput := make([]byte, 0, len(x2b)+n+len(y2b))
	macInput = append(macInput, x2b...)
	macInput = append(macInput, m...)
	macInput = append(macInput, y2b...)
	hh := sm3.New()
	hh.Write(macInput)
	if !bytesEqual(hh.Sum(nil), src[2*coordLen:2*coordLen+32]) {
		return nil, io.ErrUnexpectedEOF
	}
	return m, nil
}
