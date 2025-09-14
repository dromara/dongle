package salsa20

import (
	"bytes"
	"crypto/rand"
	"io"
	"testing"

	"github.com/dromara/dongle/crypto/cipher"
)

// Benchmark data
var (
	benchKey32  = make([]byte, 32)
	benchNonce8 = make([]byte, 8)
	benchData1K = make([]byte, 1024)
	benchData1M = make([]byte, 1024*1024)
)

func init() {
	// Initialize benchmark data
	rand.Read(benchKey32)
	rand.Read(benchNonce8)
	rand.Read(benchData1K)
	rand.Read(benchData1M)
}

func BenchmarkStdEncrypter_Encrypt_1K(b *testing.B) {
	c := cipher.NewSalsa20Cipher()
	c.SetKey(benchKey32)
	c.SetNonce(benchNonce8)

	encrypter := NewStdEncrypter(c)
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := encrypter.Encrypt(benchData1K)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkStdEncrypter_Encrypt_1M(b *testing.B) {
	c := cipher.NewSalsa20Cipher()
	c.SetKey(benchKey32)
	c.SetNonce(benchNonce8)

	encrypter := NewStdEncrypter(c)
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := encrypter.Encrypt(benchData1M)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkStdDecrypter_Decrypt_1K(b *testing.B) {
	c := cipher.NewSalsa20Cipher()
	c.SetKey(benchKey32)
	c.SetNonce(benchNonce8)

	// Pre-encrypt data for decryption benchmark
	encrypter := NewStdEncrypter(c)
	encrypted, err := encrypter.Encrypt(benchData1K)
	if err != nil {
		b.Fatal(err)
	}

	decrypter := NewStdDecrypter(c)
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := decrypter.Decrypt(encrypted)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkStdDecrypter_Decrypt_1M(b *testing.B) {
	c := cipher.NewSalsa20Cipher()
	c.SetKey(benchKey32)
	c.SetNonce(benchNonce8)

	// Pre-encrypt data for decryption benchmark
	encrypter := NewStdEncrypter(c)
	encrypted, err := encrypter.Encrypt(benchData1M)
	if err != nil {
		b.Fatal(err)
	}

	decrypter := NewStdDecrypter(c)
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := decrypter.Decrypt(encrypted)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkStreamEncrypter_Write_1K(b *testing.B) {
	c := cipher.NewSalsa20Cipher()
	c.SetKey(benchKey32)
	c.SetNonce(benchNonce8)

	var buf bytes.Buffer
	encrypter := NewStreamEncrypter(&buf, c)
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		buf.Reset()
		_, err := encrypter.Write(benchData1K)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkStreamEncrypter_Write_1M(b *testing.B) {
	c := cipher.NewSalsa20Cipher()
	c.SetKey(benchKey32)
	c.SetNonce(benchNonce8)

	var buf bytes.Buffer
	encrypter := NewStreamEncrypter(&buf, c)
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		buf.Reset()
		_, err := encrypter.Write(benchData1M)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkStreamDecrypter_Read_1K(b *testing.B) {
	c := cipher.NewSalsa20Cipher()
	c.SetKey(benchKey32)
	c.SetNonce(benchNonce8)

	// Pre-encrypt data for decryption benchmark
	encrypter := NewStdEncrypter(c)
	encrypted, err := encrypter.Encrypt(benchData1K)
	if err != nil {
		b.Fatal(err)
	}

	buf := make([]byte, len(benchData1K))
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		reader := bytes.NewReader(encrypted)
		decrypter := NewStreamDecrypter(reader, c)
		_, err := decrypter.Read(buf)
		if err != nil && err != io.EOF {
			b.Fatal(err)
		}
	}
}

func BenchmarkStreamDecrypter_Read_1M(b *testing.B) {
	c := cipher.NewSalsa20Cipher()
	c.SetKey(benchKey32)
	c.SetNonce(benchNonce8)

	// Pre-encrypt data for decryption benchmark
	encrypter := NewStdEncrypter(c)
	encrypted, err := encrypter.Encrypt(benchData1M)
	if err != nil {
		b.Fatal(err)
	}

	buf := make([]byte, len(benchData1M))
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		reader := bytes.NewReader(encrypted)
		decrypter := NewStreamDecrypter(reader, c)
		_, err := decrypter.Read(buf)
		if err != nil && err != io.EOF {
			b.Fatal(err)
		}
	}
}

func BenchmarkSalsa20_EncryptDecrypt_1K(b *testing.B) {
	c := cipher.NewSalsa20Cipher()
	c.SetKey(benchKey32)
	c.SetNonce(benchNonce8)

	encrypter := NewStdEncrypter(c)
	decrypter := NewStdDecrypter(c)
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		// Encrypt
		encrypted, err := encrypter.Encrypt(benchData1K)
		if err != nil {
			b.Fatal(err)
		}

		// Decrypt
		_, err = decrypter.Decrypt(encrypted)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkSalsa20_EncryptDecrypt_1M(b *testing.B) {
	c := cipher.NewSalsa20Cipher()
	c.SetKey(benchKey32)
	c.SetNonce(benchNonce8)

	encrypter := NewStdEncrypter(c)
	decrypter := NewStdDecrypter(c)
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		// Encrypt
		encrypted, err := encrypter.Encrypt(benchData1M)
		if err != nil {
			b.Fatal(err)
		}

		// Decrypt
		_, err = decrypter.Decrypt(encrypted)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkSalsa20_Stream_1K(b *testing.B) {
	c := cipher.NewSalsa20Cipher()
	c.SetKey(benchKey32)
	c.SetNonce(benchNonce8)

	decrypted := make([]byte, len(benchData1K))
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		// Encrypt
		var buf bytes.Buffer
		encrypter := NewStreamEncrypter(&buf, c)
		_, err := encrypter.Write(benchData1K)
		if err != nil {
			b.Fatal(err)
		}

		// Decrypt
		reader := bytes.NewReader(buf.Bytes())
		decrypter := NewStreamDecrypter(reader, c)
		_, err = decrypter.Read(decrypted)
		if err != nil && err != io.EOF {
			b.Fatal(err)
		}
	}
}

func BenchmarkSalsa20_Stream_1M(b *testing.B) {
	c := cipher.NewSalsa20Cipher()
	c.SetKey(benchKey32)
	c.SetNonce(benchNonce8)

	decrypted := make([]byte, len(benchData1M))
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		// Encrypt
		var buf bytes.Buffer
		encrypter := NewStreamEncrypter(&buf, c)
		_, err := encrypter.Write(benchData1M)
		if err != nil {
			b.Fatal(err)
		}

		// Decrypt
		reader := bytes.NewReader(buf.Bytes())
		decrypter := NewStreamDecrypter(reader, c)
		_, err = decrypter.Read(decrypted)
		if err != nil && err != io.EOF {
			b.Fatal(err)
		}
	}
}
