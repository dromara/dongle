package sm2

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/asn1"
	"errors"
	"io"
	"math/big"
	"testing"
)

func deterministicKeyPair(t *testing.T) (*ecdsa.PrivateKey, *ecdsa.PublicKey) {
	t.Helper()
	curve := NewCurve()
	d := big.NewInt(1)
	x, y := curve.ScalarBaseMult(d.Bytes())
	pri := &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{Curve: curve, X: x, Y: y},
		D:         d,
	}
	return pri, &pri.PublicKey
}

type errReader struct{}

func (errReader) Read(_ []byte) (int, error) { return 0, io.ErrUnexpectedEOF }

func TestEncryptWithPublicKey(t *testing.T) {
	_, pub := deterministicKeyPair(t)
	plaintext := []byte("hello")

	t.Run("nil public key", func(t *testing.T) {
		_, err := EncryptWithPublicKey(nil, plaintext, 4, c1c2c3)
		if !errors.Is(err, io.ErrUnexpectedEOF) {
			t.Fatalf("expected %v, got %v", io.ErrUnexpectedEOF, err)
		}
	})

	t.Run("empty plaintext", func(t *testing.T) {
		ciphertext, err := EncryptWithPublicKey(pub, nil, 4, c1c2c3)
		if err != nil {
			t.Fatalf("encrypt failed: %v", err)
		}
		if !bytes.Equal(ciphertext, []byte{0x04}) {
			t.Fatalf("unexpected ciphertext: %x", ciphertext)
		}
	})

	t.Run("c1c2c3 order", func(t *testing.T) {
		ciphertext, err := EncryptWithPublicKey(pub, plaintext, 4, c1c2c3)
		if err != nil {
			t.Fatalf("encrypt failed: %v", err)
		}
		if len(ciphertext) < 2 || ciphertext[0] != 0x04 {
			t.Fatalf("unexpected ciphertext: %x", ciphertext)
		}
	})

	t.Run("c1c3c2 order", func(t *testing.T) {
		ciphertext, err := EncryptWithPublicKey(pub, plaintext, 4, c1c3c2)
		if err != nil {
			t.Fatalf("encrypt failed: %v", err)
		}
		if len(ciphertext) < 2 || ciphertext[0] != 0x04 {
			t.Fatalf("unexpected ciphertext: %x", ciphertext)
		}
	})

	t.Run("RandScalar error", func(t *testing.T) {
		orig := rand.Reader
		rand.Reader = errReader{}
		t.Cleanup(func() { rand.Reader = orig })

		_, err := EncryptWithPublicKey(pub, plaintext, 4, c1c2c3)
		if err == nil {
			t.Fatal("expected error")
		}
	})
}

func TestDecryptWithPrivateKey(t *testing.T) {
	pri, pub := deterministicKeyPair(t)
	plaintext := []byte("hello world")

	t.Run("nil private key", func(t *testing.T) {
		_, err := DecryptWithPrivateKey(nil, []byte{0x04}, 4, c1c2c3)
		if !errors.Is(err, io.ErrUnexpectedEOF) {
			t.Fatalf("expected %v, got %v", io.ErrUnexpectedEOF, err)
		}
	})

	t.Run("empty ciphertext", func(t *testing.T) {
		_, err := DecryptWithPrivateKey(pri, nil, 4, c1c2c3)
		if !errors.Is(err, io.ErrUnexpectedEOF) {
			t.Fatalf("expected %v, got %v", io.ErrUnexpectedEOF, err)
		}
	})

	t.Run("ciphertext too short", func(t *testing.T) {
		_, err := DecryptWithPrivateKey(pri, []byte{0x04, 0x01}, 4, c1c2c3)
		if !errors.Is(err, io.ErrUnexpectedEOF) {
			t.Fatalf("expected %v, got %v", io.ErrUnexpectedEOF, err)
		}
	})

	t.Run("decrypt c1c2c3", func(t *testing.T) {
		ciphertext, err := EncryptWithPublicKey(pub, plaintext, 4, c1c2c3)
		if err != nil {
			t.Fatalf("encrypt failed: %v", err)
		}
		got, err := DecryptWithPrivateKey(pri, ciphertext, 4, c1c2c3)
		if err != nil {
			t.Fatalf("decrypt failed: %v", err)
		}
		if !bytes.Equal(got, plaintext) {
			t.Fatalf("plaintext mismatch: got %q want %q", got, plaintext)
		}
	})

	t.Run("decrypt c1c3c2", func(t *testing.T) {
		ciphertext, err := EncryptWithPublicKey(pub, plaintext, 4, c1c3c2)
		if err != nil {
			t.Fatalf("encrypt failed: %v", err)
		}
		got, err := DecryptWithPrivateKey(pri, ciphertext, 4, c1c3c2)
		if err != nil {
			t.Fatalf("decrypt failed: %v", err)
		}
		if !bytes.Equal(got, plaintext) {
			t.Fatalf("plaintext mismatch: got %q want %q", got, plaintext)
		}
	})

	t.Run("decrypt without 0x04 prefix", func(t *testing.T) {
		var ciphertext []byte
		for i := 0; i < 10; i++ {
			c, err := EncryptWithPublicKey(pub, plaintext, 4, c1c2c3)
			if err != nil {
				t.Fatalf("encrypt failed: %v", err)
			}
			if len(c) > 1 && c[1] != 0x04 {
				ciphertext = c
				break
			}
		}
		if ciphertext == nil {
			t.Fatal("failed to create ciphertext whose first coordinate byte is not 0x04")
		}

		got, err := DecryptWithPrivateKey(pri, ciphertext[1:], 4, c1c2c3)
		if err != nil {
			t.Fatalf("decrypt failed: %v", err)
		}
		if !bytes.Equal(got, plaintext) {
			t.Fatalf("plaintext mismatch: got %q want %q", got, plaintext)
		}
	})

	t.Run("C3 mismatch", func(t *testing.T) {
		ciphertext, err := EncryptWithPublicKey(pub, plaintext, 4, c1c2c3)
		if err != nil {
			t.Fatalf("encrypt failed: %v", err)
		}
		if len(ciphertext) < 2 {
			t.Fatalf("unexpected ciphertext: %x", ciphertext)
		}
		ciphertext[len(ciphertext)-1] ^= 0x01
		_, err = DecryptWithPrivateKey(pri, ciphertext, 4, c1c2c3)
		if !errors.Is(err, io.ErrUnexpectedEOF) {
			t.Fatalf("expected %v, got %v", io.ErrUnexpectedEOF, err)
		}
	})
}

func TestSignVerifyWithPublicKey(t *testing.T) {
	pri, pub := deterministicKeyPair(t)
	msg := []byte("message")

	t.Run("invalid private key: d=0", func(t *testing.T) {
		curve := NewCurve()
		badPri := &ecdsa.PrivateKey{PublicKey: ecdsa.PublicKey{Curve: curve}, D: big.NewInt(0)}
		_, err := SignWithPrivateKey(badPri, msg, nil)
		if err == nil {
			t.Fatal("expected error")
		}
	})

	t.Run("invalid private key: d>=n", func(t *testing.T) {
		curve := NewCurve()
		params := curve.Params()
		badPri := &ecdsa.PrivateKey{PublicKey: ecdsa.PublicKey{Curve: curve}, D: new(big.Int).Set(params.N)}
		_, err := SignWithPrivateKey(badPri, msg, nil)
		if err == nil {
			t.Fatal("expected error")
		}
	})

	t.Run("RandScalar error", func(t *testing.T) {
		orig := rand.Reader
		rand.Reader = errReader{}
		t.Cleanup(func() { rand.Reader = orig })

		_, err := SignWithPrivateKey(pri, msg, nil)
		if err == nil {
			t.Fatal("expected error")
		}
	})

	t.Run("sign/verify with default uid", func(t *testing.T) {
		sig, err := SignWithPrivateKey(pri, msg, nil)
		if err != nil {
			t.Fatalf("sign failed: %v", err)
		}
		if !VerifyWithPublicKey(pub, msg, nil, sig) {
			t.Fatal("verify failed")
		}
	})

	t.Run("sign/verify with custom uid", func(t *testing.T) {
		uid := []byte("uid")
		sig, err := SignWithPrivateKey(pri, msg, uid)
		if err != nil {
			t.Fatalf("sign failed: %v", err)
		}
		if !VerifyWithPublicKey(pub, msg, uid, sig) {
			t.Fatal("verify failed")
		}
	})

	t.Run("verify invalid asn1", func(t *testing.T) {
		if VerifyWithPublicKey(pub, msg, nil, []byte{0xff, 0x00}) {
			t.Fatal("expected verify to fail")
		}
	})

	t.Run("verify r out of range", func(t *testing.T) {
		curve := NewCurve()
		params := curve.Params()
		bad := sm2Sign{R: new(big.Int).Set(params.N), S: big.NewInt(1)}
		sig, err := asn1.Marshal(bad)
		if err != nil {
			t.Fatalf("marshal failed: %v", err)
		}
		if VerifyWithPublicKey(pub, msg, nil, sig) {
			t.Fatal("expected verify to fail")
		}
	})

	t.Run("verify s out of range", func(t *testing.T) {
		bad := sm2Sign{R: big.NewInt(1), S: big.NewInt(0)}
		sig, err := asn1.Marshal(bad)
		if err != nil {
			t.Fatalf("marshal failed: %v", err)
		}
		if VerifyWithPublicKey(pub, msg, nil, sig) {
			t.Fatal("expected verify to fail")
		}
	})

	t.Run("verify t == 0", func(t *testing.T) {
		curve := NewCurve()
		params := curve.Params()
		r := new(big.Int).Sub(params.N, big.NewInt(1))
		s := big.NewInt(1)
		bad := sm2Sign{R: r, S: s}
		sig, err := asn1.Marshal(bad)
		if err != nil {
			t.Fatalf("marshal failed: %v", err)
		}
		if VerifyWithPublicKey(pub, msg, nil, sig) {
			t.Fatal("expected verify to fail")
		}
	})

	t.Run("verify v != r", func(t *testing.T) {
		sig, err := SignWithPrivateKey(pri, msg, nil)
		if err != nil {
			t.Fatalf("sign failed: %v", err)
		}
		if VerifyWithPublicKey(pub, []byte("different"), nil, sig) {
			t.Fatal("expected verify to fail")
		}
	})
}

func TestHelpers(t *testing.T) {
	t.Run("padLeft", func(t *testing.T) {
		in := []byte{0x01, 0x02}
		out := padLeft(in, 4)
		if !bytes.Equal(out, []byte{0x00, 0x00, 0x01, 0x02}) {
			t.Fatalf("unexpected padLeft: %x", out)
		}

		noPad := []byte{0x01, 0x02, 0x03, 0x04}
		out2 := padLeft(noPad, 4)
		if &out2[0] != &noPad[0] {
			t.Fatal("expected padLeft to return original slice when no padding needed")
		}
	})

	t.Run("sm3KDF", func(t *testing.T) {
		out, ok := sm3KDF(0)
		if !ok || len(out) != 0 {
			t.Fatalf("unexpected KDF result: ok=%v len=%d", ok, len(out))
		}

		out, ok = sm3KDF(1, []byte("a"))
		if !ok || len(out) != 1 {
			t.Fatalf("unexpected KDF result: ok=%v len=%d", ok, len(out))
		}

		out, ok = sm3KDF(64, []byte("a"), []byte("b"))
		if !ok || len(out) != 64 {
			t.Fatalf("unexpected KDF result: ok=%v len=%d", ok, len(out))
		}
	})

	t.Run("bytesEqual", func(t *testing.T) {
		if bytesEqual([]byte{1}, []byte{1, 2}) {
			t.Fatal("expected false")
		}
		if bytesEqual([]byte{1, 2}, []byte{1, 3}) {
			t.Fatal("expected false")
		}
		if !bytesEqual([]byte{1, 2}, []byte{1, 2}) {
			t.Fatal("expected true")
		}
	})

	t.Run("getZA", func(t *testing.T) {
		_, pub := deterministicKeyPair(t)
		gotDefault := getZA(pub, nil)
		if len(gotDefault) == 0 {
			t.Fatal("expected non-empty ZA input")
		}

		uid := []byte("id")
		gotCustom := getZA(pub, uid)
		if len(gotCustom) != len(gotDefault)-(len(defaultUID)-len(uid)) {
			t.Fatal("unexpected ZA length for custom uid")
		}
	})
}
