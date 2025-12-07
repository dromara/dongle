package sm2

import (
	"bytes"
	"crypto/rand"
	"errors"
	"io"
	"testing"

	"github.com/dromara/dongle/crypto/internal/sm2"
	"github.com/dromara/dongle/crypto/keypair"
	"github.com/dromara/dongle/internal/mock"
	"github.com/stretchr/testify/assert"
)

// TestStdEncryptDecrypt_SM2 tests standard SM2 encryption and decryption.
func TestStdEncryptDecrypt_SM2(t *testing.T) {
	kp := keypair.NewSm2KeyPair()
	assert.Nil(t, kp.GenKeyPair())

	enc := NewStdEncrypter(kp)
	ciphertext, err := enc.Encrypt([]byte("hello sm2"))
	assert.Nil(t, err)
	assert.NotEmpty(t, ciphertext)

	dec := NewStdDecrypter(kp)
	plaintext, err := dec.Decrypt(ciphertext)
	assert.Nil(t, err)
	assert.Equal(t, []byte("hello sm2"), plaintext)
}

// TestStdEncrypter_EmptyInput tests encryption with empty input.
func TestStdEncrypter_EmptyInput(t *testing.T) {
	kp := keypair.NewSm2KeyPair()
	kp.GenKeyPair()
	enc := NewStdEncrypter(kp)
	out, err := enc.Encrypt([]byte{})
	assert.Nil(t, err)
	assert.Nil(t, out)
}

// TestStdDecrypter_EmptyInput tests decryption with empty input.
func TestStdDecrypter_EmptyInput(t *testing.T) {
	kp := keypair.NewSm2KeyPair()
	kp.GenKeyPair()
	dec := NewStdDecrypter(kp)
	out, err := dec.Decrypt([]byte{})
	assert.Nil(t, err)
	assert.Nil(t, out)
}

// TestStdEncryptDecrypt_InvalidKeys tests encryption/decryption with invalid keys.
func TestStdEncryptDecrypt_InvalidKeys(t *testing.T) {
	t.Run("encrypt with invalid public key", func(t *testing.T) {
		kp := keypair.NewSm2KeyPair()
		_ = kp.SetPublicKey([]byte("invalid"))
		enc := NewStdEncrypter(kp)
		out, err := enc.Encrypt([]byte("data"))
		assert.NotNil(t, err)
		assert.Nil(t, out)
	})

	t.Run("decrypt with invalid private key", func(t *testing.T) {
		kp := keypair.NewSm2KeyPair()
		_ = kp.SetPrivateKey([]byte("invalid"))
		dec := NewStdDecrypter(kp)
		out, err := dec.Decrypt([]byte("data"))
		assert.NotNil(t, err)
		assert.Nil(t, out)
	})
}

// TestStreamEncryptDecrypt_SM2 tests streaming SM2 encryption and decryption.
func TestStreamEncryptDecrypt_SM2(t *testing.T) {
	kp := keypair.NewSm2KeyPair()
	assert.Nil(t, kp.GenKeyPair())

	var buf bytes.Buffer
	enc := NewStreamEncrypter(&buf, kp)
	n, err := enc.Write([]byte("streaming sm2"))
	assert.Nil(t, err)
	assert.Equal(t, len("streaming sm2"), n)
	assert.Nil(t, enc.Close())
	assert.NotEmpty(t, buf.Bytes())

	dec := NewStreamDecrypter(bytes.NewReader(buf.Bytes()), kp)
	out := make([]byte, 1024)
	m, err := dec.Read(out)
	if err != nil && err != io.EOF {
		t.Fatalf("unexpected error: %v", err)
	}
	out = out[:m]
	assert.Equal(t, []byte("streaming sm2"), out)
}

// TestStreamEncrypter_CloseErrors tests stream encrypter close errors.
func TestStreamEncrypter_CloseErrors(t *testing.T) {
	kp := keypair.NewSm2KeyPair()
	kp.GenKeyPair()

	mw := mock.NewErrorWriteCloser(assert.AnError)
	enc := NewStreamEncrypter(mw, kp)
	_, _ = enc.Write([]byte("abc"))
	err := enc.Close()
	assert.Equal(t, assert.AnError, err)

	mw2 := mock.NewErrorWriteCloser(assert.AnError)
	enc2 := NewStreamEncrypter(mw2, kp)
	err = enc2.Close()
	assert.Equal(t, assert.AnError, err)
}

// TestStreamEncrypter_WriteAfterError tests writing after an error occurs.
func TestStreamEncrypter_WriteAfterError(t *testing.T) {
	kp := keypair.NewSm2KeyPair()
	enc := NewStreamEncrypter(nil, kp) // nil writer will cause error
	_, err := enc.Write([]byte("test"))
	assert.NotNil(t, err)
	assert.IsType(t, EncryptError{}, err)
}

// TestStreamEncrypter_EmptyWriteAndClose tests closing without writing data.
func TestStreamEncrypter_EmptyWriteAndClose(t *testing.T) {
	kp := keypair.NewSm2KeyPair()
	kp.GenKeyPair()
	var buf bytes.Buffer
	enc := NewStreamEncrypter(&buf, kp)
	err := enc.Close()
	assert.Nil(t, err)
}

// TestStreamEncrypter_CloseWithEmptyBufferAndCloser tests close with empty buffer and no close error.
func TestStreamEncrypter_CloseWithEmptyBufferAndCloser(t *testing.T) {
	kp := keypair.NewSm2KeyPair()
	kp.GenKeyPair()
	mw := mock.NewErrorWriteCloser(nil) // No error on close
	enc := NewStreamEncrypter(mw, kp)
	err := enc.Close()
	assert.Nil(t, err)
}

// TestStreamEncrypter_CloseWithEmptyBufferAndErrorCloser tests close with empty buffer and close error.
func TestStreamEncrypter_CloseWithEmptyBufferAndErrorCloser(t *testing.T) {
	kp := keypair.NewSm2KeyPair()
	kp.GenKeyPair()
	mw := mock.NewErrorWriteCloser(assert.AnError)
	enc := NewStreamEncrypter(mw, kp)
	err := enc.Close()
	assert.Equal(t, assert.AnError, err)
}

// TestStdEncryptDecrypt_SM2_C1C2C3 tests encryption/decryption with C1C2C3 order.
func TestStdEncryptDecrypt_SM2_C1C2C3(t *testing.T) {
	kp := keypair.NewSm2KeyPair()
	assert.Nil(t, kp.GenKeyPair())

	kp.SetOrder(keypair.C1C2C3)
	enc := NewStdEncrypter(kp)
	ct, err := enc.Encrypt([]byte("mode c1c2c3"))
	assert.Nil(t, err)
	assert.NotEmpty(t, ct)

	kp.SetOrder(keypair.C1C2C3)
	dec := NewStdDecrypter(kp)
	pt, err := dec.Decrypt(ct)
	assert.Nil(t, err)
	assert.Equal(t, []byte("mode c1c2c3"), pt)
}

// TestStdEncryptDecrypt_ModeStrictness tests order mismatch between encryption and decryption.
func TestStdEncryptDecrypt_ModeStrictness(t *testing.T) {
	kp := keypair.NewSm2KeyPair()
	assert.Nil(t, kp.GenKeyPair())

	kp.SetOrder(keypair.C1C3C2)
	ct, err := NewStdEncrypter(kp).Encrypt([]byte("strict mode"))
	assert.Nil(t, err)
	assert.NotEmpty(t, ct)

	kp.SetOrder(keypair.C1C2C3)
	pt, err := NewStdDecrypter(kp).Decrypt(ct)
	assert.NotNil(t, err)
	assert.Nil(t, pt)

	kp.SetOrder(keypair.C1C3C2)
	pt, err = NewStdDecrypter(kp).Decrypt(ct)
	assert.Nil(t, err)
	assert.Equal(t, []byte("strict mode"), pt)
}

// TestScalarBaseMult_Equals_ScalarMult verifies ScalarBaseMult equals ScalarMult for base point.
func TestScalarBaseMult_Equals_ScalarMult(t *testing.T) {
	cv := sm2.NewCurve()
	sm2.SetWindow(cv, 6)
	gx, gy := cv.Params().Gx, cv.Params().Gy
	for i := 1; i <= 10; i++ {
		k := make([]byte, 32)
		k[31] = byte(i)
		x1, y1 := cv.ScalarBaseMult(k)
		x2, y2 := cv.ScalarMult(gx, gy, k)
		if i == 1 {
			if x1.Cmp(gx) != 0 || y1.Cmp(gy) != 0 {
				t.Fatalf("ScalarBaseMult(k=1) != G")
			}
		}
		if x1.Cmp(x2) != 0 || y1.Cmp(y2) != 0 {
			t.Fatalf("ScalarBaseMult mismatch small k=%d", i)
		}
	}
	for i := 0; i < 16; i++ {
		k := make([]byte, 32)
		for j := range k {
			k[j] = byte((i + 1) * (j + 3))
		}
		x1, y1 := cv.ScalarBaseMult(k)
		x2, y2 := cv.ScalarMult(gx, gy, k)
		if x1.Cmp(x2) != 0 || y1.Cmp(y2) != 0 {
			t.Fatalf("ScalarBaseMult mismatch at i=%d", i)
		}
	}
}

// TestEncryptWithEmptyMessage tests encryption with empty message.
func TestEncryptWithEmptyMessage(t *testing.T) {
	kp := keypair.NewSm2KeyPair()
	kp.GenKeyPair()
	enc := NewStdEncrypter(kp)
	result, err := enc.Encrypt([]byte{})
	assert.Nil(t, err)
	assert.Nil(t, result)
}

// TestDecryptWithEmptyMessage tests decryption with empty message.
func TestDecryptWithEmptyMessage(t *testing.T) {
	kp := keypair.NewSm2KeyPair()
	kp.GenKeyPair()
	dec := NewStdDecrypter(kp)
	result, err := dec.Decrypt([]byte{})
	assert.Nil(t, err)
	assert.Nil(t, result)
}

// TestStreamEncrypter_WriteEmptyData tests writing empty data.
func TestStreamEncrypter_WriteEmptyData(t *testing.T) {
	kp := keypair.NewSm2KeyPair()
	kp.GenKeyPair()
	var buf bytes.Buffer
	enc := NewStreamEncrypter(&buf, kp)
	n, err := enc.Write([]byte{})
	assert.Nil(t, err)
	assert.Equal(t, 0, n)
}

// TestReadError tests ReadError.
func TestReadError(t *testing.T) {
	err := ReadError{Err: errors.New("read failed")}
	assert.Equal(t, "crypto/sm2: failed to read encrypted data: read failed", err.Error())
}

// TestEncryptError tests EncryptError.
func TestEncryptError(t *testing.T) {
	err := EncryptError{Err: errors.New("encrypt failed")}
	assert.Equal(t, "crypto/sm2: failed to encrypt data: encrypt failed", err.Error())
}

// TestDecryptError tests DecryptError.
func TestDecryptError(t *testing.T) {
	err := DecryptError{Err: errors.New("decrypt failed")}
	assert.Equal(t, "crypto/sm2: failed to decrypt data: decrypt failed", err.Error())
}

// TestNewStdEncrypterWithEmptyPublicKey tests encrypter with empty public key.
func TestNewStdEncrypterWithEmptyPublicKey(t *testing.T) {
	kp := keypair.NewSm2KeyPair()
	enc := NewStdEncrypter(kp)
	assert.NotNil(t, enc.Error)
	assert.IsType(t, EncryptError{}, enc.Error)
}

// TestNewStdEncrypterWithValidKeyPair tests encrypter with valid key pair.
func TestNewStdEncrypterWithValidKeyPair(t *testing.T) {
	kp := keypair.NewSm2KeyPair()
	kp.GenKeyPair()
	enc := NewStdEncrypter(kp)
	assert.Nil(t, enc.Error)
}

// TestNewStdDecrypterWithEmptyPrivateKey tests decrypter with empty private key.
func TestNewStdDecrypterWithEmptyPrivateKey(t *testing.T) {
	kp := keypair.NewSm2KeyPair()
	dec := NewStdDecrypter(kp)
	assert.NotNil(t, dec.Error)
	assert.IsType(t, DecryptError{}, dec.Error)
}

// TestNewStdDecrypterWithValidKeyPair tests decrypter with valid key pair.
func TestNewStdDecrypterWithValidKeyPair(t *testing.T) {
	kp := keypair.NewSm2KeyPair()
	kp.GenKeyPair()
	dec := NewStdDecrypter(kp)
	assert.Nil(t, dec.Error)
}

// TestNewStreamDecrypterWithValidKeyPair tests stream decrypter with valid key pair.
func TestNewStreamDecrypterWithValidKeyPair(t *testing.T) {
	kp := keypair.NewSm2KeyPair()
	kp.GenKeyPair()
	dec := NewStreamDecrypter(bytes.NewReader([]byte{}), kp)
	buf := make([]byte, 1)
	_, err := dec.Read(buf)
	assert.Equal(t, io.EOF, err)
}

// TestStreamDecrypter_ReadAfterError tests reading after an error occurs.
func TestStreamDecrypter_ReadAfterError(t *testing.T) {
	kp := keypair.NewSm2KeyPair()
	dec := NewStreamDecrypter(nil, kp)
	buf := make([]byte, 1)
	_, err := dec.Read(buf)
	assert.NotNil(t, err)
	assert.IsType(t, DecryptError{}, err)

	_, err2 := dec.Read(buf)
	assert.Equal(t, err, err2)
}

// TestStreamDecrypter_ReadEmptyData tests reading empty data.
func TestStreamDecrypter_ReadEmptyData(t *testing.T) {
	kp := keypair.NewSm2KeyPair()
	kp.GenKeyPair()
	dec := NewStreamDecrypter(bytes.NewReader([]byte{}), kp)
	buf := make([]byte, 1)
	_, err := dec.Read(buf)
	assert.Equal(t, io.EOF, err)
}

// TestStreamDecrypter_ReadWithInvalidData tests reading invalid encrypted data.
func TestStreamDecrypter_ReadWithInvalidData(t *testing.T) {
	kp := keypair.NewSm2KeyPair()
	kp.GenKeyPair()
	invalidData := []byte{0x04, 0x01, 0x02}
	dec := NewStreamDecrypter(bytes.NewReader(invalidData), kp)
	buf := make([]byte, 10)
	_, err := dec.Read(buf)
	assert.NotNil(t, err)
}

// TestStreamDecrypter_ReadWithValidData tests reading valid encrypted data.
func TestStreamDecrypter_ReadWithValidData(t *testing.T) {
	kp := keypair.NewSm2KeyPair()
	kp.GenKeyPair()

	enc := NewStdEncrypter(kp)
	ciphertext, err := enc.Encrypt([]byte("test message"))
	assert.Nil(t, err)

	// Then decrypt it with StreamDecrypter
	dec := NewStreamDecrypter(bytes.NewReader(ciphertext), kp)
	buf := make([]byte, 100)
	n, err := dec.Read(buf)
	// For StreamDecrypter, we expect EOF as the read is complete
	assert.Equal(t, io.EOF, err)
	assert.Equal(t, "test message", string(buf[:n]))
}

// TestEncryptWithNilPublicKey tests encryption with nil public key.
func TestEncryptWithNilPublicKey(t *testing.T) {
	kp := keypair.NewSm2KeyPair()
	enc := NewStdEncrypter(kp)
	_, err := enc.Encrypt([]byte("test"))
	assert.NotNil(t, err)
	assert.IsType(t, EncryptError{}, err)
}

// TestDecryptWithNilPrivateKey tests decryption with nil private key.
func TestDecryptWithNilPrivateKey(t *testing.T) {
	kp := keypair.NewSm2KeyPair()
	dec := NewStdDecrypter(kp)
	_, err := dec.Decrypt([]byte("test"))
	assert.NotNil(t, err)
	assert.IsType(t, DecryptError{}, err)
}

// TestStreamDecrypter_ReadWithValidData2 tests reading valid encrypted data (variant 2).
func TestStreamDecrypter_ReadWithValidData2(t *testing.T) {
	kp := keypair.NewSm2KeyPair()
	kp.GenKeyPair()

	enc := NewStdEncrypter(kp)
	ciphertext, err := enc.Encrypt([]byte("test message"))
	assert.Nil(t, err)

	dec := NewStreamDecrypter(bytes.NewReader(ciphertext), kp)
	buf := make([]byte, 100)
	n, err := dec.Read(buf)
	assert.Equal(t, io.EOF, err)
	assert.Equal(t, "test message", string(buf[:n]))
}

// TestEncryptFunctionWithDifferentWindowSizes tests encrypt function with various window sizes.
func TestEncryptFunctionWithDifferentWindowSizes(t *testing.T) {
	kp := keypair.NewSm2KeyPair()
	kp.GenKeyPair()
	pub, _ := kp.ParsePublicKey()

	ciphertext, err := sm2.Encrypt(rand.Reader, pub, []byte("test message"), sm2.C1C3C2, 2)
	assert.Nil(t, err)
	assert.NotNil(t, ciphertext)

	ciphertext, err = sm2.Encrypt(rand.Reader, pub, []byte("test message"), sm2.C1C3C2, 6)
	assert.Nil(t, err)
	assert.NotNil(t, ciphertext)

	ciphertext, err = sm2.Encrypt(rand.Reader, pub, []byte("test message"), sm2.C1C3C2, 1)
	assert.Nil(t, err)
	assert.NotNil(t, ciphertext)
}

// TestDecryptFunctionWithInvalidData tests decrypt function with invalid data.
func TestDecryptFunctionWithInvalidData(t *testing.T) {
	kp := keypair.NewSm2KeyPair()
	kp.GenKeyPair()
	pri, _ := kp.ParsePrivateKey()

	_, err := sm2.Decrypt(pri, []byte{}, sm2.C1C3C2, 0)
	assert.Equal(t, io.ErrUnexpectedEOF, err)

	_, err = sm2.Decrypt(pri, []byte{0x01, 0x02}, sm2.C1C3C2, 0)
	assert.Equal(t, io.ErrUnexpectedEOF, err)

	_, err = sm2.Decrypt(pri, []byte{0x04, 0x01, 0x02}, sm2.C1C3C2, 0)
	assert.Equal(t, io.ErrUnexpectedEOF, err)

	_, err = sm2.Decrypt(pri, []byte{0x04, 0x01, 0x02}, sm2.C1C2C3, 0)
	assert.Equal(t, io.ErrUnexpectedEOF, err)
}

// TestDecryptFunctionWithValidData tests decrypt function with valid data.
func TestDecryptFunctionWithValidData(t *testing.T) {
	kp := keypair.NewSm2KeyPair()
	kp.GenKeyPair()
	pri, _ := kp.ParsePrivateKey()
	pub, _ := kp.ParsePublicKey()

	ciphertext, err := sm2.Encrypt(rand.Reader, pub, []byte("test message"), sm2.C1C3C2, 0)
	assert.Nil(t, err)

	plaintext, err := sm2.Decrypt(pri, ciphertext, sm2.C1C3C2, 0)
	assert.Nil(t, err)
	assert.Equal(t, "test message", string(plaintext))
}

// TestEncryptFunctionWithC1C2C3Order tests encrypt function with C1C2C3 order.
func TestEncryptFunctionWithC1C2C3Order(t *testing.T) {
	kp := keypair.NewSm2KeyPair()
	kp.GenKeyPair()
	pub, _ := kp.ParsePublicKey()

	ciphertext, err := sm2.Encrypt(rand.Reader, pub, []byte("test message"), sm2.C1C2C3, 0)
	assert.Nil(t, err)
	assert.NotNil(t, ciphertext)
}

// TestDecryptFunctionWithC1C2C3Order tests decrypt function with C1C2C3 order.
func TestDecryptFunctionWithC1C2C3Order(t *testing.T) {
	kp := keypair.NewSm2KeyPair()
	kp.GenKeyPair()
	pri, _ := kp.ParsePrivateKey()
	pub, _ := kp.ParsePublicKey()

	ciphertext, err := sm2.Encrypt(rand.Reader, pub, []byte("test message"), sm2.C1C2C3, 0)
	assert.Nil(t, err)

	plaintext, err := sm2.Decrypt(pri, ciphertext, sm2.C1C2C3, 0)
	assert.Nil(t, err)
	assert.Equal(t, "test message", string(plaintext))
}

// TestStreamEncrypter_CloseWithWriteError tests close with write error.
func TestStreamEncrypter_CloseWithWriteError(t *testing.T) {
	kp := keypair.NewSm2KeyPair()
	kp.GenKeyPair()
	mw := mock.NewErrorWriteCloser(assert.AnError)
	enc := NewStreamEncrypter(mw, kp)
	_, _ = enc.Write([]byte("test data"))
	err := enc.Close()
	assert.Equal(t, assert.AnError, err)
}

// TestStdEncrypter_EncryptWithError tests encryption when Error is already set.
func TestStdEncrypter_EncryptWithError(t *testing.T) {
	kp := keypair.NewSm2KeyPair()
	enc := NewStdEncrypter(kp)
	_, err := enc.Encrypt([]byte("test"))
	assert.NotNil(t, err)
	assert.IsType(t, EncryptError{}, err)
}

// TestStdDecrypter_DecryptWithError tests decryption when Error is already set.
func TestStdDecrypter_DecryptWithError(t *testing.T) {
	kp := keypair.NewSm2KeyPair()
	dec := NewStdDecrypter(kp)
	_, err := dec.Decrypt([]byte("test"))
	assert.NotNil(t, err)
	assert.IsType(t, DecryptError{}, err)
}

// TestStreamDecrypter_ReadPartial tests partial reads.
func TestStreamDecrypter_ReadPartial(t *testing.T) {
	kp := keypair.NewSm2KeyPair()
	kp.GenKeyPair()

	// Encrypt some data
	enc := NewStdEncrypter(kp)
	ciphertext, err := enc.Encrypt([]byte("test message for partial read"))
	assert.Nil(t, err)

	dec := NewStreamDecrypter(bytes.NewReader(ciphertext), kp)

	buf1 := make([]byte, 5)
	n1, err1 := dec.Read(buf1)
	assert.Nil(t, err1)
	assert.Equal(t, 5, n1)

	buf2 := make([]byte, 5)
	n2, err2 := dec.Read(buf2)
	assert.Nil(t, err2)
	assert.Equal(t, 5, n2)

	buf3 := make([]byte, 100)
	n3, err3 := dec.Read(buf3)
	assert.Equal(t, io.EOF, err3)
	assert.Greater(t, n3, 0)

	complete := append(append(buf1[:n1], buf2[:n2]...), buf3[:n3]...)
	assert.Equal(t, "test message for partial read", string(complete))
}

// TestStreamDecrypter_ReadWithReadAllError tests read error handling.
func TestStreamDecrypter_ReadWithReadAllError(t *testing.T) {
	kp := keypair.NewSm2KeyPair()
	kp.GenKeyPair()

	errorReader := mock.NewErrorFile(assert.AnError)
	dec := NewStreamDecrypter(errorReader, kp)

	buf := make([]byte, 10)
	_, err := dec.Read(buf)
	assert.NotNil(t, err)
	assert.IsType(t, ReadError{}, err)
}

// TestDecrypt_Without0x04Prefix tests decryption without 0x04 prefix.
func TestDecrypt_Without0x04Prefix(t *testing.T) {
	kp := keypair.NewSm2KeyPair()
	kp.GenKeyPair()
	pri, _ := kp.ParsePrivateKey()
	pub, _ := kp.ParsePublicKey()

	ciphertext, err := sm2.Encrypt(rand.Reader, pub, []byte("test"), sm2.C1C3C2, 0)
	assert.Nil(t, err)

	ciphertextWithoutPrefix := ciphertext[1:]

	plaintext, err := sm2.Decrypt(pri, ciphertextWithoutPrefix, sm2.C1C3C2, 0)
	assert.Nil(t, err)
	assert.Equal(t, "test", string(plaintext))
}

// TestDecrypt_WithVerificationFailure_C1C3C2 tests decryption with corrupted MAC (C1C3C2 order).
func TestDecrypt_WithVerificationFailure_C1C3C2(t *testing.T) {
	kp := keypair.NewSm2KeyPair()
	kp.GenKeyPair()
	pri, _ := kp.ParsePrivateKey()
	pub, _ := kp.ParsePublicKey()

	ciphertext, err := sm2.Encrypt(rand.Reader, pub, []byte("test"), sm2.C1C3C2, 0)
	assert.Nil(t, err)

	ciphertext[len(ciphertext)-1] ^= 0xFF

	_, err = sm2.Decrypt(pri, ciphertext[1:], sm2.C1C3C2, 0)
	assert.NotNil(t, err)
	assert.Equal(t, io.ErrUnexpectedEOF, err)
}

// TestDecrypt_WithVerificationFailure_C1C2C3 tests decryption with corrupted MAC (C1C2C3 order).
func TestDecrypt_WithVerificationFailure_C1C2C3(t *testing.T) {
	kp := keypair.NewSm2KeyPair()
	kp.GenKeyPair()
	pri, _ := kp.ParsePrivateKey()
	pub, _ := kp.ParsePublicKey()

	ciphertext, err := sm2.Encrypt(rand.Reader, pub, []byte("test"), sm2.C1C2C3, 0)
	assert.Nil(t, err)

	ciphertext[len(ciphertext)-1] ^= 0xFF

	_, err = sm2.Decrypt(pri, ciphertext[1:], sm2.C1C2C3, 0)
	assert.NotNil(t, err)
	assert.Equal(t, io.ErrUnexpectedEOF, err)
}

// TestEncrypt_WithWindowSizeOutsideRange tests encryption with invalid window sizes.
func TestEncrypt_WithWindowSizeOutsideRange(t *testing.T) {
	kp := keypair.NewSm2KeyPair()
	kp.GenKeyPair()
	pub, _ := kp.ParsePublicKey()

	// Test with window size 0 (should use default)
	ciphertext, err := sm2.Encrypt(rand.Reader, pub, []byte("test"), sm2.C1C3C2, 0)
	assert.Nil(t, err)
	assert.NotNil(t, ciphertext)

	// Test with window size 7 (should be clamped)
	ciphertext2, err2 := sm2.Encrypt(rand.Reader, pub, []byte("test"), sm2.C1C3C2, 7)
	assert.Nil(t, err2)
	assert.NotNil(t, ciphertext2)

	// Test with window size 1 (should be clamped)
	ciphertext3, err3 := sm2.Encrypt(rand.Reader, pub, []byte("test"), sm2.C1C3C2, 1)
	assert.Nil(t, err3)
	assert.NotNil(t, ciphertext3)
}

// TestDecrypt_WithWindowSizeOutsideRange tests decryption with invalid window sizes.
func TestDecrypt_WithWindowSizeOutsideRange(t *testing.T) {
	kp := keypair.NewSm2KeyPair()
	kp.GenKeyPair()
	pri, _ := kp.ParsePrivateKey()
	pub, _ := kp.ParsePublicKey()

	// Encrypt with default window
	ciphertext, err := sm2.Encrypt(rand.Reader, pub, []byte("test"), sm2.C1C3C2, 0)
	assert.Nil(t, err)

	// Decrypt with window size 0
	plaintext, err := sm2.Decrypt(pri, ciphertext[1:], sm2.C1C3C2, 0)
	assert.Nil(t, err)
	assert.Equal(t, "test", string(plaintext))

	// Decrypt with window size 7 (should be clamped)
	plaintext2, err2 := sm2.Decrypt(pri, ciphertext[1:], sm2.C1C3C2, 7)
	assert.Nil(t, err2)
	assert.Equal(t, "test", string(plaintext2))

	// Decrypt with window size 1 (should be clamped)
	plaintext3, err3 := sm2.Decrypt(pri, ciphertext[1:], sm2.C1C3C2, 1)
	assert.Nil(t, err3)
	assert.Equal(t, "test", string(plaintext3))
}

// TestStreamDecrypter_ReadWithDecryptError tests read with decryption error.
func TestStreamDecrypter_ReadWithDecryptError(t *testing.T) {
	kp := keypair.NewSm2KeyPair()
	kp.GenKeyPair()

	invalidData := []byte{0x04, 0x01, 0x02, 0x03}
	dec := NewStreamDecrypter(bytes.NewReader(invalidData), kp)

	buf := make([]byte, 10)
	_, err := dec.Read(buf)
	assert.NotNil(t, err)
	assert.IsType(t, DecryptError{}, err)
}

// Test StreamEncrypter.Close with buffer and non-Closer writer
func TestStreamEncrypter_CloseWithBufferAndNonCloserWriter(t *testing.T) {
	kp := keypair.NewSm2KeyPair()
	kp.GenKeyPair()
	var buf bytes.Buffer // bytes.Buffer is io.Writer but not io.Closer
	enc := NewStreamEncrypter(&buf, kp)
	_, _ = enc.Write([]byte("test data"))
	err := enc.Close()
	assert.Nil(t, err)
	assert.NotEmpty(t, buf.Bytes())
}

// Test StreamEncrypter.Close when Encrypt fails
func TestStreamEncrypter_CloseWithEncryptError(t *testing.T) {
	kp := keypair.NewSm2KeyPair()
	// Don't generate key pair, so Encrypt will fail
	var buf bytes.Buffer
	enc := NewStreamEncrypter(&buf, kp)
	_, _ = enc.Write([]byte("test data"))
	err := enc.Close()
	assert.NotNil(t, err)
	assert.IsType(t, EncryptError{}, err)
}

// Test NewStreamEncrypter with valid key pair (to cover the path where PublicKey is not empty)
func TestNewStreamEncrypter_WithValidKeyPair(t *testing.T) {
	kp := keypair.NewSm2KeyPair()
	kp.GenKeyPair()
	var buf bytes.Buffer
	enc := NewStreamEncrypter(&buf, kp)
	streamEnc, ok := enc.(*StreamEncrypter)
	assert.True(t, ok)
	assert.Nil(t, streamEnc.Error)
	assert.NotNil(t, enc)
}

// Test encrypt with sm3KDF returning false (retry loop)
// This is also difficult to test deterministically, but the code handles it
func TestEncrypt_WithSm3KDFRetry(t *testing.T) {
	kp := keypair.NewSm2KeyPair()
	kp.GenKeyPair()
	pub, _ := kp.ParsePublicKey()

	// The encrypt function will retry if sm3KDF returns false
	// In practice, this is extremely rare, so we just verify normal operation
	ciphertext, err := sm2.Encrypt(rand.Reader, pub, []byte("test"), sm2.C1C3C2, 0)
	assert.Nil(t, err)
	assert.NotNil(t, ciphertext)
}

// Test StdEncrypter.Encrypt when encrypt function returns error
// This is difficult because encrypt function retries on sm3KDF failure
// But we can test with invalid public key that causes ParsePublicKey to fail
func TestStdEncrypter_EncryptWithParsePublicKeyError(t *testing.T) {
	kp := keypair.NewSm2KeyPair()
	_ = kp.SetPublicKey([]byte("invalid public key"))
	enc := NewStdEncrypter(kp)
	_, err := enc.Encrypt([]byte("test"))
	assert.NotNil(t, err)
	assert.IsType(t, EncryptError{}, err)
}

// Test StdDecrypter.Decrypt when decrypt function returns error
func TestStdDecrypter_DecryptWithParsePrivateKeyError(t *testing.T) {
	kp := keypair.NewSm2KeyPair()
	_ = kp.SetPrivateKey([]byte("invalid private key"))
	dec := NewStdDecrypter(kp)
	_, err := dec.Decrypt([]byte("test"))
	assert.NotNil(t, err)
	assert.IsType(t, DecryptError{}, err)
}

// Test StreamDecrypter.Read returning nil (more data available)
func TestStreamDecrypter_ReadReturningNil(t *testing.T) {
	kp := keypair.NewSm2KeyPair()
	kp.GenKeyPair()

	// Encrypt a longer message
	enc := NewStdEncrypter(kp)
	ciphertext, err := enc.Encrypt([]byte("this is a longer test message for partial reading"))
	assert.Nil(t, err)

	// Decrypt with StreamDecrypter
	dec := NewStreamDecrypter(bytes.NewReader(ciphertext), kp)

	// First read - small buffer, should return nil (not EOF) because there's more data
	buf1 := make([]byte, 10)
	n1, err1 := dec.Read(buf1)
	assert.Nil(t, err1) // Should return nil, not EOF
	assert.Equal(t, 10, n1)

	// Second read - should also return nil if there's more data
	buf2 := make([]byte, 10)
	n2, err2 := dec.Read(buf2)
	// If there's still more data, err2 should be nil
	if err2 == nil {
		assert.Equal(t, 10, n2)
	}
}

// Test NewStreamEncrypter order setting
func TestNewStreamEncrypter_OrderPath(t *testing.T) {
	kp := keypair.NewSm2KeyPair()
	kp.GenKeyPair()
	kp.SetOrder(keypair.C1C2C3)
	var buf bytes.Buffer
	enc := NewStreamEncrypter(&buf, kp)
	streamEnc, ok := enc.(*StreamEncrypter)
	assert.True(t, ok)
	assert.Nil(t, streamEnc.Error)
	assert.Equal(t, keypair.C1C2C3, streamEnc.keypair.Order)

	// Test with C1C3C2 order
	kp.SetOrder(keypair.C1C3C2)
	enc2 := NewStreamEncrypter(&buf, kp)
	streamEnc2, ok := enc2.(*StreamEncrypter)
	assert.True(t, ok)
	assert.Equal(t, keypair.C1C3C2, streamEnc2.keypair.Order)
}

// Test NewStreamDecrypter order setting
func TestNewStreamDecrypter_OrderPath(t *testing.T) {
	kp := keypair.NewSm2KeyPair()
	kp.GenKeyPair()
	kp.SetOrder(keypair.C1C2C3)
	dec := NewStreamDecrypter(bytes.NewReader([]byte{}), kp)
	streamDec, ok := dec.(*StreamDecrypter)
	assert.True(t, ok)
	assert.Nil(t, streamDec.Error)
	assert.Equal(t, keypair.C1C2C3, streamDec.keypair.Order)

	// Test with C1C3C2 order
	kp.SetOrder(keypair.C1C3C2)
	dec2 := NewStreamDecrypter(bytes.NewReader([]byte{}), kp)
	streamDec2, ok := dec2.(*StreamDecrypter)
	assert.True(t, ok)
	assert.Equal(t, keypair.C1C3C2, streamDec2.keypair.Order)
}

// Test encrypt with sm3KDF retry (attempting to trigger the continue branch)
// This is extremely unlikely but we try multiple times
func TestEncrypt_AttemptSm3KDFRetry(t *testing.T) {
	kp := keypair.NewSm2KeyPair()
	kp.GenKeyPair()
	pub, _ := kp.ParsePublicKey()

	// Try encrypting multiple times to see if we can trigger sm3KDF returning false
	// This is extremely unlikely (probability ~ 2^-256 for each attempt)
	// but we try a reasonable number of times
	successCount := 0
	for i := 0; i < 100; i++ {
		ciphertext, err := sm2.Encrypt(rand.Reader, pub, []byte("test"), sm2.C1C3C2, 0)
		assert.Nil(t, err)
		if ciphertext != nil {
			successCount++
		}
	}
	// All attempts should succeed (sm3KDF returning false is extremely rare)
	assert.Equal(t, 100, successCount)
}

// Test that encrypt handles the continue loop correctly
// Even though we can't deterministically trigger sm3KDF returning false,
// we verify that the encrypt function works correctly in normal operation
func TestEncrypt_NormalOperation(t *testing.T) {
	kp := keypair.NewSm2KeyPair()
	kp.GenKeyPair()
	pub, _ := kp.ParsePublicKey()

	// Test with different message lengths
	messages := []string{
		"a",
		"test",
		"this is a longer test message",
		"this is an even longer test message that should work correctly",
	}

	for _, msg := range messages {
		ciphertext, err := sm2.Encrypt(rand.Reader, pub, []byte(msg), sm2.C1C3C2, 0)
		assert.Nil(t, err)
		assert.NotNil(t, ciphertext)
		assert.Greater(t, len(ciphertext), 0)
	}
}

// Note: TestEncrypt_WithRandScalarError has been removed because
// encrypt() now uses rand.Reader internally and cannot inject custom readers

// Test StdEncrypter.Encrypt with encrypt function returning error
func TestStdEncrypter_EncryptWithEncryptError2(t *testing.T) {
	// Test with invalid public key
	kp := keypair.NewSm2KeyPair()
	_ = kp.SetPublicKey([]byte("invalid"))
	enc := NewStdEncrypter(kp)
	_, err := enc.Encrypt([]byte("test"))
	assert.NotNil(t, err)

	// Test with valid key but simulate encrypt error by using a very large window
	kp2 := keypair.NewSm2KeyPair()
	kp2.GenKeyPair()
	kp2.SetWindow(10) // Invalid window, but encrypt will clamp it
	enc2 := NewStdEncrypter(kp2)
	_, err = enc2.Encrypt([]byte("test"))
	// This should succeed as window is clamped
	assert.Nil(t, err)
}

// Test StdDecrypter.Decrypt with decrypt function returning error
func TestStdDecrypter_DecryptWithDecryptError2(t *testing.T) {
	kp := keypair.NewSm2KeyPair()
	kp.GenKeyPair()
	dec := NewStdDecrypter(kp)

	// Test with invalid ciphertext
	_, err := dec.Decrypt([]byte("invalid ciphertext"))
	assert.NotNil(t, err)
	assert.IsType(t, DecryptError{}, err)
}

// Test NewStreamEncrypter with nil keypair - should return early
// Test StreamEncrypter.Close with buffer and closer writer that succeeds
func TestStreamEncrypter_CloseWithBufferAndSuccessfulCloser(t *testing.T) {
	kp := keypair.NewSm2KeyPair()
	kp.GenKeyPair()
	mw := mock.NewErrorWriteCloser(nil) // No error on close
	enc := NewStreamEncrypter(mw, kp)
	_, _ = enc.Write([]byte("test data"))
	err := enc.Close()
	assert.Nil(t, err)
}

// Test StdDecrypter.Decrypt where ParsePrivateKey succeeds but decrypt fails
func TestStdDecrypter_DecryptWithInvalidCiphertext(t *testing.T) {
	kp := keypair.NewSm2KeyPair()
	kp.GenKeyPair()
	dec := NewStdDecrypter(kp)

	// Use a ciphertext that will pass ParsePrivateKey but fail in decrypt
	// A short invalid ciphertext will trigger DecryptError
	invalidCiphertext := []byte{0x04, 0x01, 0x02, 0x03, 0x04}
	_, err := dec.Decrypt(invalidCiphertext)
	assert.NotNil(t, err)
	assert.IsType(t, DecryptError{}, err)

	// Verify the error was stored in the decrypter
	assert.NotNil(t, dec.Error)
	assert.IsType(t, DecryptError{}, dec.Error)
}

// Test StdEncrypter.Encrypt with ParsePublicKey error - line 57-60
func TestStdEncrypter_EncryptWithParsePublicKeyError2(t *testing.T) {
	kp := keypair.NewSm2KeyPair()
	// Directly set PublicKey field with invalid data (bypass SetPublicKey)
	// This ensures len(kp.PublicKey) > 0 but ParsePublicKey will fail
	kp.PublicKey = []byte("invalid public key data")
	enc := NewStdEncrypter(kp)

	// NewStdEncrypter should not have set Error (PublicKey is not empty)
	assert.Nil(t, enc.Error)

	// This should trigger the ParsePublicKey error path (line 57-60)
	result, err := enc.Encrypt([]byte("test data"))
	assert.Nil(t, result)
	assert.NotNil(t, err)
	assert.IsType(t, EncryptError{}, err)

	// Verify the error was stored in the encrypter
	assert.NotNil(t, enc.Error)
	assert.IsType(t, EncryptError{}, enc.Error)
}

// Test StdDecrypter.Decrypt with ParsePrivateKey error - line 176-179
func TestStdDecrypter_DecryptWithParsePrivateKeyError2(t *testing.T) {
	kp := keypair.NewSm2KeyPair()
	// Directly set PrivateKey field with invalid data (bypass SetPrivateKey)
	// This ensures len(kp.PrivateKey) > 0 but ParsePrivateKey will fail
	kp.PrivateKey = []byte("invalid private key data")
	dec := NewStdDecrypter(kp)

	// NewStdDecrypter should not have set Error (PrivateKey is not empty)
	assert.Nil(t, dec.Error)

	// This should trigger the ParsePrivateKey error path (line 176-179)
	result, err := dec.Decrypt([]byte("test data"))
	assert.Nil(t, result)
	assert.NotNil(t, err)
	assert.IsType(t, DecryptError{}, err)

	// Verify the error was stored in the decrypter
	assert.NotNil(t, dec.Error)
	assert.IsType(t, DecryptError{}, dec.Error)
}

// Test StreamEncrypter.Close with Encrypt error - line 129-131
func TestStreamEncrypter_CloseWithNewStdEncrypterError(t *testing.T) {
	kp := keypair.NewSm2KeyPair()
	// Directly set PublicKey field with invalid data (bypass SetPublicKey)
	kp.PublicKey = []byte("invalid public key data")
	var buf bytes.Buffer
	enc := NewStreamEncrypter(&buf, kp)

	// StreamEncrypter should have Error set because public key parsing fails in NewStreamEncrypter
	streamEnc, ok := enc.(*StreamEncrypter)
	assert.True(t, ok)
	assert.NotNil(t, streamEnc.Error)
	assert.IsType(t, EncryptError{}, streamEnc.Error)

	// Write should return error due to preset Error
	_, err := enc.Write([]byte("test data"))
	assert.NotNil(t, err)

	// Close should also return error
	err = enc.Close()
	assert.NotNil(t, err)
	assert.IsType(t, EncryptError{}, err)
}

func TestDecryptWithDerPrivateKey(t *testing.T) {
	kp := &keypair.Sm2KeyPair{
		PrivateKey: []byte{
			0x5e, 0xe5, 0xc6, 0x87,
			0x8a, 0x00, 0xbb, 0xe7,
			0x4b, 0x8e, 0xa8, 0x93,
			0xfc, 0x76, 0xe3, 0x61,
			0xb6, 0x69, 0x4e, 0x1b,
			0xb3, 0x15, 0xb4, 0xeb,
			0x5a, 0x58, 0xa7, 0xdc,
			0x9d, 0x1f, 0x1a, 0x71,
		},
		Order: keypair.C1C3C2,
	}
	plaintext, err := NewStdDecrypter(kp).Decrypt([]byte{
		0xf9, 0x72, 0x8a, 0xc8, 0x32, 0xca, 0x24, 0xd4,
		0xc3, 0x83, 0xc1, 0x29, 0x89, 0x8f, 0xd9, 0x0b,
		0xd5, 0x9a, 0x03, 0xdc, 0xec, 0x23, 0x02, 0x7c,
		0x44, 0x08, 0x27, 0x76, 0x9f, 0x2d, 0x2c, 0xd0,
		0x02, 0x8c, 0x97, 0xfd, 0x5b, 0xfa, 0x45, 0x18,
		0x2c, 0xb2, 0x91, 0xd1, 0x5d, 0xae, 0x5c, 0x0b,
		0xd6, 0x3a, 0xf5, 0xde, 0x68, 0x09, 0x87, 0x4d,
		0x7d, 0xc4, 0x5b, 0x42, 0xc8, 0x4d, 0x1c, 0xc0,
		0x68, 0x00, 0x21, 0x59, 0x35, 0x9b, 0x0c, 0x81,
		0xac, 0x1a, 0x19, 0x30, 0x0d, 0x16, 0x4e, 0x62,
		0x5c, 0x5e, 0xb2, 0x37, 0x32, 0xb6, 0x02, 0x95,
		0x83, 0x30, 0x8c, 0x3b, 0x01, 0x0d, 0x66, 0xec,
		0xf9, 0xd2, 0xc8, 0xb2, 0x06, 0xe3, 0x5b, 0xe9,
		0xb9, 0xd5, 0xe4, 0x19, 0xb1, 0xb5, 0x83, 0x8c,
	})
	assert.Nil(t, err)
	assert.Equal(t, []byte{
		0xc6, 0xf2, 0xcc, 0x55,
		0xb8, 0xcb, 0x73, 0xf3,
		0xa7, 0x5b, 0xf8, 0x8b,
		0x54, 0x16, 0xe6, 0xa0,
	}, plaintext)
}

// TestStreamEncrypter_EncryptEmptyData tests encrypt method with empty data
func TestStreamEncrypter_EncryptEmptyData(t *testing.T) {
	kp := keypair.NewSm2KeyPair()
	err := kp.GenKeyPair()
	assert.NoError(t, err)

	enc := NewStreamEncrypter(&bytes.Buffer{}, kp).(*StreamEncrypter)
	encrypted, err := enc.encrypt(nil)
	assert.Nil(t, encrypted)
	assert.NoError(t, err)
}

// TestStreamEncrypter_EncryptWithOrder tests encrypt method with different orders
func TestStreamEncrypter_EncryptWithOrder(t *testing.T) {
	kp := keypair.NewSm2KeyPair()
	err := kp.GenKeyPair()
	assert.NoError(t, err)

	t.Run("encrypt with C1C2C3 order", func(t *testing.T) {
		kp.SetOrder(keypair.C1C2C3)
		enc := NewStreamEncrypter(&bytes.Buffer{}, kp).(*StreamEncrypter)
		encrypted, err := enc.encrypt([]byte("test data"))
		assert.NoError(t, err)
		assert.NotNil(t, encrypted)
	})

	t.Run("encrypt with C1C3C2 order", func(t *testing.T) {
		kp.SetOrder(keypair.C1C3C2)
		enc := NewStreamEncrypter(&bytes.Buffer{}, kp).(*StreamEncrypter)
		encrypted, err := enc.encrypt([]byte("test data"))
		assert.NoError(t, err)
		assert.NotNil(t, encrypted)
	})
}

// TestStreamEncrypter_CloseWithEmptyBufferNoCloser tests Close with empty buffer
func TestStreamEncrypter_CloseWithEmptyBufferNoCloser(t *testing.T) {
	kp := keypair.NewSm2KeyPair()
	err := kp.GenKeyPair()
	assert.NoError(t, err)

	buf := &bytes.Buffer{}
	enc := NewStreamEncrypter(buf, kp)
	// Don't write anything, buffer is empty
	err = enc.Close()
	assert.NoError(t, err)
}

// TestStreamDecrypter_DecryptEmptyData tests decrypt method with empty data
func TestStreamDecrypter_DecryptEmptyData(t *testing.T) {
	kp := keypair.NewSm2KeyPair()
	err := kp.GenKeyPair()
	assert.NoError(t, err)

	dec := NewStreamDecrypter(&bytes.Buffer{}, kp).(*StreamDecrypter)
	decrypted, err := dec.decrypt(nil)
	assert.Nil(t, decrypted)
	assert.NoError(t, err)
}

// TestStreamDecrypter_DecryptWithOrder tests decrypt method with different orders
func TestStreamDecrypter_DecryptWithOrder(t *testing.T) {
	kp := keypair.NewSm2KeyPair()
	err := kp.GenKeyPair()
	assert.NoError(t, err)

	t.Run("decrypt with C1C2C3 order", func(t *testing.T) {
		kp.SetOrder(keypair.C1C2C3)
		enc := NewStdEncrypter(kp)
		encrypted, err := enc.Encrypt([]byte("test data"))
		assert.NoError(t, err)

		dec := NewStreamDecrypter(&bytes.Buffer{}, kp).(*StreamDecrypter)
		decrypted, err := dec.decrypt(encrypted)
		assert.NoError(t, err)
		assert.Equal(t, []byte("test data"), decrypted)
	})

	t.Run("decrypt with C1C3C2 order", func(t *testing.T) {
		kp.SetOrder(keypair.C1C3C2)
		enc := NewStdEncrypter(kp)
		encrypted, err := enc.Encrypt([]byte("test data"))
		assert.NoError(t, err)

		dec := NewStreamDecrypter(&bytes.Buffer{}, kp).(*StreamDecrypter)
		decrypted, err := dec.decrypt(encrypted)
		assert.NoError(t, err)
		assert.Equal(t, []byte("test data"), decrypted)
	})
}

// TestStreamDecrypter_DecryptError tests decrypt method error handling
func TestStreamDecrypter_DecryptError(t *testing.T) {
	kp := keypair.NewSm2KeyPair()
	err := kp.GenKeyPair()
	assert.NoError(t, err)

	dec := NewStreamDecrypter(&bytes.Buffer{}, kp).(*StreamDecrypter)
	decrypted, err := dec.decrypt([]byte("invalid ciphertext"))
	assert.Nil(t, decrypted)
	assert.Error(t, err)
	assert.IsType(t, DecryptError{}, dec.Error)
}

// TestNewStreamDecrypter_WithInvalidPrivateKey tests NewStreamDecrypter with invalid private key
func TestNewStreamDecrypter_WithInvalidPrivateKey(t *testing.T) {
	kp := keypair.NewSm2KeyPair()
	kp.PrivateKey = []byte("invalid private key")

	dec := NewStreamDecrypter(&bytes.Buffer{}, kp).(*StreamDecrypter)
	assert.NotNil(t, dec.Error)
	assert.IsType(t, DecryptError{}, dec.Error)
}

// TestStreamEncrypter_CloseWithNonCloserWriter tests Close with writer that doesn't implement io.Closer
func TestStreamEncrypter_CloseWithNonCloserWriter(t *testing.T) {
	kp := keypair.NewSm2KeyPair()
	err := kp.GenKeyPair()
	assert.NoError(t, err)

	buf := &bytes.Buffer{}
	enc := NewStreamEncrypter(buf, kp)
	_, err = enc.Write([]byte("test data"))
	assert.NoError(t, err)

	err = enc.Close()
	assert.NoError(t, err)
}

// TestStreamEncrypter_EncryptErrorPath tests encrypt method error path
func TestStreamEncrypter_EncryptErrorPath(t *testing.T) {
	kp := keypair.NewSm2KeyPair()
	kp.GenKeyPair()

	// Create an encrypter with invalid public key to trigger error in encrypt
	kp.PublicKey = []byte("invalid")
	enc := NewStreamEncrypter(&bytes.Buffer{}, kp)
	streamEnc, ok := enc.(*StreamEncrypter)
	assert.True(t, ok)
	assert.NotNil(t, streamEnc.Error)

	// Try to encrypt, should return error
	_, err := streamEnc.encrypt([]byte("test"))
	assert.NotNil(t, err)
}

// TestNewStdSigner tests NewStdSigner
func TestNewStdSigner(t *testing.T) {
	t.Run("with empty private key", func(t *testing.T) {
		kp := keypair.NewSm2KeyPair()
		signer := NewStdSigner(kp)
		assert.NotNil(t, signer.Error)
		assert.IsType(t, SignError{}, signer.Error)
	})

	t.Run("with valid key pair", func(t *testing.T) {
		kp := keypair.NewSm2KeyPair()
		kp.GenKeyPair()
		signer := NewStdSigner(kp)
		assert.Nil(t, signer.Error)
	})
}

// TestStdSigner_Sign tests Sign method
func TestStdSigner_Sign(t *testing.T) {
	t.Run("sign with valid key pair", func(t *testing.T) {
		kp := keypair.NewSm2KeyPair()
		kp.GenKeyPair()
		signer := NewStdSigner(kp)

		signature, err := signer.Sign([]byte("test message"))
		assert.Nil(t, err)
		assert.NotNil(t, signature)
	})

	t.Run("sign with empty message", func(t *testing.T) {
		kp := keypair.NewSm2KeyPair()
		kp.GenKeyPair()
		signer := NewStdSigner(kp)

		signature, err := signer.Sign([]byte{})
		assert.Nil(t, err)
		assert.Nil(t, signature)
	})

	t.Run("sign with error", func(t *testing.T) {
		kp := keypair.NewSm2KeyPair()
		signer := NewStdSigner(kp)

		_, err := signer.Sign([]byte("test"))
		assert.NotNil(t, err)
		assert.IsType(t, SignError{}, err)
	})

	t.Run("sign with invalid private key", func(t *testing.T) {
		kp := keypair.NewSm2KeyPair()
		kp.PrivateKey = []byte("invalid private key")
		signer := NewStdSigner(kp)

		_, err := signer.Sign([]byte("test"))
		assert.NotNil(t, err)
		assert.IsType(t, SignError{}, err)
	})
}

// TestNewStdVerifier tests NewStdVerifier
func TestNewStdVerifier(t *testing.T) {
	t.Run("with empty public key", func(t *testing.T) {
		kp := keypair.NewSm2KeyPair()
		verifier := NewStdVerifier(kp)
		assert.NotNil(t, verifier.Error)
		assert.IsType(t, VerifyError{}, verifier.Error)
	})

	t.Run("with valid key pair", func(t *testing.T) {
		kp := keypair.NewSm2KeyPair()
		kp.GenKeyPair()
		verifier := NewStdVerifier(kp)
		assert.Nil(t, verifier.Error)
	})
}

// TestStdVerifier_Verify tests Verify method
func TestStdVerifier_Verify(t *testing.T) {
	t.Run("verify with valid signature", func(t *testing.T) {
		kp := keypair.NewSm2KeyPair()
		kp.GenKeyPair()

		signer := NewStdSigner(kp)
		message := []byte("test message")
		signature, err := signer.Sign(message)
		assert.Nil(t, err)

		verifier := NewStdVerifier(kp)
		valid, err := verifier.Verify(message, signature)
		assert.Nil(t, err)
		assert.True(t, valid)
	})

	t.Run("verify with invalid signature", func(t *testing.T) {
		kp := keypair.NewSm2KeyPair()
		kp.GenKeyPair()

		verifier := NewStdVerifier(kp)
		valid, err := verifier.Verify([]byte("test message"), []byte("invalid signature"))
		assert.NotNil(t, err)
		assert.False(t, valid)
		assert.IsType(t, VerifyError{}, err)
	})

	t.Run("verify with empty message", func(t *testing.T) {
		kp := keypair.NewSm2KeyPair()
		kp.GenKeyPair()

		verifier := NewStdVerifier(kp)
		valid, err := verifier.Verify([]byte{}, []byte("signature"))
		assert.Nil(t, err)
		assert.False(t, valid)
	})

	t.Run("verify with empty signature", func(t *testing.T) {
		kp := keypair.NewSm2KeyPair()
		kp.GenKeyPair()

		verifier := NewStdVerifier(kp)
		valid, err := verifier.Verify([]byte("test message"), []byte{})
		assert.NotNil(t, err)
		assert.False(t, valid)
		assert.IsType(t, VerifyError{}, err)
	})

	t.Run("verify with error", func(t *testing.T) {
		kp := keypair.NewSm2KeyPair()
		verifier := NewStdVerifier(kp)

		_, err := verifier.Verify([]byte("test"), []byte("signature"))
		assert.NotNil(t, err)
		assert.IsType(t, VerifyError{}, err)
	})

	t.Run("verify with invalid public key", func(t *testing.T) {
		kp := keypair.NewSm2KeyPair()
		kp.PublicKey = []byte("invalid public key")
		verifier := NewStdVerifier(kp)

		_, err := verifier.Verify([]byte("test"), []byte("signature"))
		assert.NotNil(t, err)
		assert.IsType(t, VerifyError{}, err)
	})
}

// TestNewStreamSigner tests NewStreamSigner
func TestNewStreamSigner(t *testing.T) {
	t.Run("with empty private key", func(t *testing.T) {
		kp := keypair.NewSm2KeyPair()
		signer := NewStreamSigner(&bytes.Buffer{}, kp)
		streamSigner, ok := signer.(*StreamSigner)
		assert.True(t, ok)
		assert.NotNil(t, streamSigner.Error)
		assert.IsType(t, SignError{}, streamSigner.Error)
	})

	t.Run("with valid key pair", func(t *testing.T) {
		kp := keypair.NewSm2KeyPair()
		kp.GenKeyPair()
		signer := NewStreamSigner(&bytes.Buffer{}, kp)
		streamSigner, ok := signer.(*StreamSigner)
		assert.True(t, ok)
		assert.Nil(t, streamSigner.Error)
	})

	t.Run("with invalid private key", func(t *testing.T) {
		kp := keypair.NewSm2KeyPair()
		kp.PrivateKey = []byte("invalid private key")
		signer := NewStreamSigner(&bytes.Buffer{}, kp)
		streamSigner, ok := signer.(*StreamSigner)
		assert.True(t, ok)
		assert.NotNil(t, streamSigner.Error)
		assert.IsType(t, SignError{}, streamSigner.Error)
	})
}

// TestStreamSigner_Sign tests sign method
func TestStreamSigner_Sign(t *testing.T) {
	t.Run("sign with valid data", func(t *testing.T) {
		kp := keypair.NewSm2KeyPair()
		kp.GenKeyPair()
		signer := NewStreamSigner(&bytes.Buffer{}, kp)
		streamSigner, _ := signer.(*StreamSigner)

		signature, err := streamSigner.sign([]byte("test message"))
		assert.Nil(t, err)
		assert.NotNil(t, signature)
	})

	t.Run("sign with empty data", func(t *testing.T) {
		kp := keypair.NewSm2KeyPair()
		kp.GenKeyPair()
		signer := NewStreamSigner(&bytes.Buffer{}, kp)
		streamSigner, _ := signer.(*StreamSigner)

		signature, err := streamSigner.sign([]byte{})
		assert.Nil(t, err)
		assert.Nil(t, signature)
	})
}

// TestStreamSigner_Write tests Write method
func TestStreamSigner_Write(t *testing.T) {
	t.Run("write with valid data", func(t *testing.T) {
		kp := keypair.NewSm2KeyPair()
		kp.GenKeyPair()
		signer := NewStreamSigner(&bytes.Buffer{}, kp)

		n, err := signer.Write([]byte("test data"))
		assert.Nil(t, err)
		assert.Equal(t, len("test data"), n)
	})

	t.Run("write with empty data", func(t *testing.T) {
		kp := keypair.NewSm2KeyPair()
		kp.GenKeyPair()
		signer := NewStreamSigner(&bytes.Buffer{}, kp)

		n, err := signer.Write([]byte{})
		assert.Nil(t, err)
		assert.Equal(t, 0, n)
	})

	t.Run("write with error", func(t *testing.T) {
		kp := keypair.NewSm2KeyPair()
		signer := NewStreamSigner(&bytes.Buffer{}, kp)

		_, err := signer.Write([]byte("test"))
		assert.NotNil(t, err)
		assert.IsType(t, SignError{}, err)
	})
}

// TestStreamSigner_Close tests Close method
func TestStreamSigner_Close(t *testing.T) {
	t.Run("close with buffered data", func(t *testing.T) {
		kp := keypair.NewSm2KeyPair()
		kp.GenKeyPair()
		var buf bytes.Buffer
		signer := NewStreamSigner(&buf, kp)
		_, _ = signer.Write([]byte("test message"))

		err := signer.Close()
		assert.Nil(t, err)
		assert.NotEmpty(t, buf.Bytes())
	})

	t.Run("close with empty buffer", func(t *testing.T) {
		kp := keypair.NewSm2KeyPair()
		kp.GenKeyPair()
		signer := NewStreamSigner(&bytes.Buffer{}, kp)

		err := signer.Close()
		assert.Nil(t, err)
	})

	t.Run("close with empty buffer and closer", func(t *testing.T) {
		kp := keypair.NewSm2KeyPair()
		kp.GenKeyPair()
		mw := mock.NewErrorWriteCloser(nil)
		signer := NewStreamSigner(mw, kp)

		err := signer.Close()
		assert.Nil(t, err)
	})

	t.Run("close with empty buffer and error closer", func(t *testing.T) {
		kp := keypair.NewSm2KeyPair()
		kp.GenKeyPair()
		mw := mock.NewErrorWriteCloser(assert.AnError)
		signer := NewStreamSigner(mw, kp)

		err := signer.Close()
		assert.Equal(t, assert.AnError, err)
	})

	t.Run("close with error", func(t *testing.T) {
		kp := keypair.NewSm2KeyPair()
		signer := NewStreamSigner(&bytes.Buffer{}, kp)

		err := signer.Close()
		assert.NotNil(t, err)
		assert.IsType(t, SignError{}, err)
	})

	t.Run("close with write error", func(t *testing.T) {
		kp := keypair.NewSm2KeyPair()
		kp.GenKeyPair()
		mw := mock.NewErrorWriteCloser(assert.AnError)
		signer := NewStreamSigner(mw, kp)
		_, _ = signer.Write([]byte("test"))

		err := signer.Close()
		assert.Equal(t, assert.AnError, err)
	})
}

// TestNewStreamVerifier tests NewStreamVerifier
func TestNewStreamVerifier(t *testing.T) {
	t.Run("with empty public key", func(t *testing.T) {
		kp := keypair.NewSm2KeyPair()
		verifier := NewStreamVerifier(&bytes.Buffer{}, kp)
		streamVerifier, ok := verifier.(*StreamVerifier)
		assert.True(t, ok)
		assert.NotNil(t, streamVerifier.Error)
		assert.IsType(t, VerifyError{}, streamVerifier.Error)
	})

	t.Run("with valid key pair", func(t *testing.T) {
		kp := keypair.NewSm2KeyPair()
		kp.GenKeyPair()
		verifier := NewStreamVerifier(&bytes.Buffer{}, kp)
		streamVerifier, ok := verifier.(*StreamVerifier)
		assert.True(t, ok)
		assert.Nil(t, streamVerifier.Error)
	})

	t.Run("with invalid public key", func(t *testing.T) {
		kp := keypair.NewSm2KeyPair()
		kp.PublicKey = []byte("invalid public key")
		verifier := NewStreamVerifier(&bytes.Buffer{}, kp)
		streamVerifier, ok := verifier.(*StreamVerifier)
		assert.True(t, ok)
		assert.NotNil(t, streamVerifier.Error)
		assert.IsType(t, VerifyError{}, streamVerifier.Error)
	})
}

// TestStreamVerifier_Verify tests verify method
func TestStreamVerifier_Verify(t *testing.T) {
	t.Run("verify with valid signature", func(t *testing.T) {
		kp := keypair.NewSm2KeyPair()
		kp.GenKeyPair()

		signer := NewStdSigner(kp)
		message := []byte("test message")
		signature, err := signer.Sign(message)
		assert.Nil(t, err)

		verifier := NewStreamVerifier(&bytes.Buffer{}, kp)
		streamVerifier, _ := verifier.(*StreamVerifier)

		valid, err := streamVerifier.verify(message, signature)
		assert.Nil(t, err)
		assert.True(t, valid)
	})

	t.Run("verify with invalid signature", func(t *testing.T) {
		kp := keypair.NewSm2KeyPair()
		kp.GenKeyPair()

		verifier := NewStreamVerifier(&bytes.Buffer{}, kp)
		streamVerifier, _ := verifier.(*StreamVerifier)

		valid, err := streamVerifier.verify([]byte("test message"), []byte("invalid signature"))
		assert.NotNil(t, err)
		assert.False(t, valid)
		assert.IsType(t, VerifyError{}, err)
	})

	t.Run("verify with empty data", func(t *testing.T) {
		kp := keypair.NewSm2KeyPair()
		kp.GenKeyPair()

		verifier := NewStreamVerifier(&bytes.Buffer{}, kp)
		streamVerifier, _ := verifier.(*StreamVerifier)

		valid, err := streamVerifier.verify([]byte{}, []byte("signature"))
		assert.Nil(t, err)
		assert.False(t, valid)
	})

	t.Run("verify with empty signature", func(t *testing.T) {
		kp := keypair.NewSm2KeyPair()
		kp.GenKeyPair()

		verifier := NewStreamVerifier(&bytes.Buffer{}, kp)
		streamVerifier, _ := verifier.(*StreamVerifier)

		valid, err := streamVerifier.verify([]byte("test"), []byte{})
		assert.Nil(t, err)
		assert.False(t, valid)
	})
}

// TestStreamVerifier_Write tests Write method
func TestStreamVerifier_Write(t *testing.T) {
	t.Run("write with valid data", func(t *testing.T) {
		kp := keypair.NewSm2KeyPair()
		kp.GenKeyPair()
		verifier := NewStreamVerifier(&bytes.Buffer{}, kp)

		n, err := verifier.Write([]byte("test data"))
		assert.Nil(t, err)
		assert.Equal(t, len("test data"), n)
	})

	t.Run("write with empty data", func(t *testing.T) {
		kp := keypair.NewSm2KeyPair()
		kp.GenKeyPair()
		verifier := NewStreamVerifier(&bytes.Buffer{}, kp)

		n, err := verifier.Write([]byte{})
		assert.Nil(t, err)
		assert.Equal(t, 0, n)
	})

	t.Run("write with error", func(t *testing.T) {
		kp := keypair.NewSm2KeyPair()
		verifier := NewStreamVerifier(&bytes.Buffer{}, kp)

		_, err := verifier.Write([]byte("test"))
		assert.NotNil(t, err)
		assert.IsType(t, VerifyError{}, err)
	})
}

// TestSignError tests SignError.Error method
func TestSignError(t *testing.T) {
	err := SignError{Err: errors.New("sign failed")}
	assert.Equal(t, "crypto/sm2: failed to sign data: sign failed", err.Error())
}

// Test StdEncrypter Encrypt error wrapping when randomness fails.
func TestStdEncrypter_EncryptWithRandError(t *testing.T) {
	kp := keypair.NewSm2KeyPair()
	assert.Nil(t, kp.GenKeyPair())
	enc := NewStdEncrypter(kp)

	orig := rand.Reader
	rand.Reader = mock.NewErrorFile(assert.AnError)
	t.Cleanup(func() { rand.Reader = orig })

	out, err := enc.Encrypt([]byte("data"))
	assert.Nil(t, out)
	assert.Error(t, err)
	assert.IsType(t, EncryptError{}, err)
}

// Test StreamEncrypter.Close when encryption fails after buffering data.
func TestStreamEncrypter_CloseEncryptError(t *testing.T) {
	kp := keypair.NewSm2KeyPair()
	assert.Nil(t, kp.GenKeyPair())
	enc := NewStreamEncrypter(&bytes.Buffer{}, kp).(*StreamEncrypter)

	_, _ = enc.Write([]byte("data"))
	enc.pubKey = nil // force sm2curve.Encrypt to fail

	err := enc.Close()
	assert.Error(t, err)
	assert.True(t, errors.Is(err, io.ErrUnexpectedEOF))
	assert.IsType(t, EncryptError{}, enc.Error)
}

// Test StdSigner.Sign error path when private scalar is invalid after parsing.
func TestStdSigner_SignWithInvalidPrivateScalar(t *testing.T) {
	kp := keypair.NewSm2KeyPair()
	kp.PrivateKey = make([]byte, 32) // parses successfully but yields D=0

	signer := NewStdSigner(kp)
	signature, err := signer.Sign([]byte("msg"))
	assert.Nil(t, signature)
	assert.Error(t, err)
	assert.IsType(t, SignError{}, err)
}

// Test StreamSigner.sign error propagation.
func TestStreamSigner_SignErrorPath(t *testing.T) {
	kp := keypair.NewSm2KeyPair()
	kp.PrivateKey = make([]byte, 32) // produces invalid scalar

	signer := NewStreamSigner(&bytes.Buffer{}, kp).(*StreamSigner)
	signature, err := signer.sign([]byte("msg"))
	assert.Nil(t, signature)
	assert.Error(t, err)
	assert.IsType(t, SignError{}, err)
}

// Test StreamSigner.Close when sign fails and when writer implements io.Closer.
func TestStreamSigner_CloseAdditionalPaths(t *testing.T) {
	t.Run("sign failure in close", func(t *testing.T) {
		kp := keypair.NewSm2KeyPair()
		kp.PrivateKey = make([]byte, 32)

		signer := NewStreamSigner(&bytes.Buffer{}, kp)
		streamSigner, _ := signer.(*StreamSigner)
		_, _ = streamSigner.Write([]byte("data"))

		err := streamSigner.Close()
		assert.Error(t, err)
		assert.IsType(t, SignError{}, err)
	})

	t.Run("writer with closer", func(t *testing.T) {
		kp := keypair.NewSm2KeyPair()
		assert.Nil(t, kp.GenKeyPair())
		var buf bytes.Buffer
		wc := mock.NewCloseErrorWriteCloser(&buf, nil)
		signer := NewStreamSigner(wc, kp)

		_, _ = signer.Write([]byte("data"))
		err := signer.Close()
		assert.NoError(t, err)
		assert.NotZero(t, buf.Len())
	})
}

// Test StreamVerifier.Close across success, empty, read error, and verify error paths.
func TestStreamVerifier_Close(t *testing.T) {
	message := []byte("test message")

	t.Run("successful close with closer reader", func(t *testing.T) {
		kp := keypair.NewSm2KeyPair()
		assert.Nil(t, kp.GenKeyPair())
		sig, err := NewStdSigner(kp).Sign(message)
		assert.NoError(t, err)

		reader := io.NopCloser(bytes.NewReader(sig))
		verifier := NewStreamVerifier(reader, kp)
		_, _ = verifier.Write(message)

		err = verifier.Close()
		assert.NoError(t, err)
		streamVerifier, _ := verifier.(*StreamVerifier)
		assert.True(t, streamVerifier.verified)
	})

	t.Run("empty signature", func(t *testing.T) {
		kp := keypair.NewSm2KeyPair()
		assert.Nil(t, kp.GenKeyPair())
		verifier := NewStreamVerifier(bytes.NewReader(nil), kp)
		_, _ = verifier.Write(message)

		err := verifier.Close()
		assert.NoError(t, err)
	})

	t.Run("read error", func(t *testing.T) {
		kp := keypair.NewSm2KeyPair()
		assert.Nil(t, kp.GenKeyPair())
		verifier := NewStreamVerifier(mock.NewErrorFile(assert.AnError), kp)

		err := verifier.Close()
		assert.Error(t, err)
		assert.IsType(t, ReadError{}, err)
	})

	t.Run("verify error", func(t *testing.T) {
		kp := keypair.NewSm2KeyPair()
		assert.Nil(t, kp.GenKeyPair())
		verifier := NewStreamVerifier(bytes.NewReader([]byte("invalid signature")), kp)
		_, _ = verifier.Write(message)

		err := verifier.Close()
		assert.Error(t, err)
		assert.IsType(t, VerifyError{}, err)
	})

	t.Run("preset error", func(t *testing.T) {
		kp := keypair.NewSm2KeyPair() // no public key -> NewStreamVerifier sets Error
		verifier := NewStreamVerifier(&bytes.Buffer{}, kp)
		err := verifier.Close()
		assert.Error(t, err)
		assert.IsType(t, VerifyError{}, err)
	})

	t.Run("success without closer", func(t *testing.T) {
		kp := keypair.NewSm2KeyPair()
		assert.Nil(t, kp.GenKeyPair())
		sig, err := NewStdSigner(kp).Sign(message)
		assert.NoError(t, err)

		verifier := NewStreamVerifier(bytes.NewReader(sig), kp)
		_, _ = verifier.Write(message)
		err = verifier.Close()
		assert.NoError(t, err)
	})
}
