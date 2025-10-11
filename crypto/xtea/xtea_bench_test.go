package xtea

import (
	"bytes"
	"fmt"
	"io"
	"testing"

	"github.com/dromara/dongle/crypto/cipher"
)

var (
	benchKey16 = []byte("1234567890123456") // XTEA-128 key
	benchIV8   = []byte("12345678")         // 8-byte IV
	benchData  = []byte("hello world test data for benchmarking")
)

func BenchmarkStdEncrypter_CBC(b *testing.B) {
	c := cipher.NewXteaCipher(cipher.CBC)
	c.SetKey(benchKey16)
	c.SetIV(benchIV8)
	c.SetPadding(cipher.PKCS7)

	encrypter := NewStdEncrypter(c)
	if encrypter.Error != nil {
		b.Fatal(encrypter.Error)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := encrypter.Encrypt(benchData)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkStdDecrypter_CBC(b *testing.B) {
	c := cipher.NewXteaCipher(cipher.CBC)
	c.SetKey(benchKey16)
	c.SetIV(benchIV8)
	c.SetPadding(cipher.PKCS7)

	encrypter := NewStdEncrypter(c)
	if encrypter.Error != nil {
		b.Fatal(encrypter.Error)
	}

	ciphertext, err := encrypter.Encrypt(benchData)
	if err != nil {
		b.Fatal(err)
	}

	decrypter := NewStdDecrypter(c)
	if decrypter.Error != nil {
		b.Fatal(decrypter.Error)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := decrypter.Decrypt(ciphertext)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkStdEncrypter_ECB(b *testing.B) {
	c := cipher.NewXteaCipher(cipher.ECB)
	c.SetKey(benchKey16)
	c.SetPadding(cipher.PKCS7)

	encrypter := NewStdEncrypter(c)
	if encrypter.Error != nil {
		b.Fatal(encrypter.Error)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := encrypter.Encrypt(benchData)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkStdDecrypter_ECB(b *testing.B) {
	c := cipher.NewXteaCipher(cipher.ECB)
	c.SetKey(benchKey16)
	c.SetPadding(cipher.PKCS7)

	encrypter := NewStdEncrypter(c)
	if encrypter.Error != nil {
		b.Fatal(encrypter.Error)
	}

	ciphertext, err := encrypter.Encrypt(benchData)
	if err != nil {
		b.Fatal(err)
	}

	decrypter := NewStdDecrypter(c)
	if decrypter.Error != nil {
		b.Fatal(decrypter.Error)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := decrypter.Decrypt(ciphertext)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkStdEncrypter_CTR(b *testing.B) {
	c := cipher.NewXteaCipher(cipher.CTR)
	c.SetKey(benchKey16)
	c.SetIV(benchIV8)

	encrypter := NewStdEncrypter(c)
	if encrypter.Error != nil {
		b.Fatal(encrypter.Error)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := encrypter.Encrypt(benchData)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkStdDecrypter_CTR(b *testing.B) {
	c := cipher.NewXteaCipher(cipher.CTR)
	c.SetKey(benchKey16)
	c.SetIV(benchIV8)

	encrypter := NewStdEncrypter(c)
	if encrypter.Error != nil {
		b.Fatal(encrypter.Error)
	}

	ciphertext, err := encrypter.Encrypt(benchData)
	if err != nil {
		b.Fatal(err)
	}

	decrypter := NewStdDecrypter(c)
	if decrypter.Error != nil {
		b.Fatal(decrypter.Error)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := decrypter.Decrypt(ciphertext)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkStreamEncrypter_CBC(b *testing.B) {
	c := cipher.NewXteaCipher(cipher.CBC)
	c.SetKey(benchKey16)
	c.SetIV(benchIV8)
	c.SetPadding(cipher.PKCS7)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var buf bytes.Buffer
		encrypter := NewStreamEncrypter(&buf, c)
		if encrypter == nil {
			b.Fatal("encrypter is nil")
		}

		_, err := encrypter.Write(benchData)
		if err != nil {
			b.Fatal(err)
		}

		err = encrypter.Close()
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkStreamDecrypter_CBC(b *testing.B) {
	c := cipher.NewXteaCipher(cipher.CBC)
	c.SetKey(benchKey16)
	c.SetIV(benchIV8)
	c.SetPadding(cipher.PKCS7)

	// Pre-encrypt data
	var encBuf bytes.Buffer
	encrypter := NewStreamEncrypter(&encBuf, c)
	if encrypter == nil {
		b.Fatal("encrypter is nil")
	}

	_, err := encrypter.Write(benchData)
	if err != nil {
		b.Fatal(err)
	}

	err = encrypter.Close()
	if err != nil {
		b.Fatal(err)
	}

	ciphertext := encBuf.Bytes()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		decrypter := NewStreamDecrypter(bytes.NewReader(ciphertext), c)
		if decrypter == nil {
			b.Fatal("decrypter is nil")
		}

		_, err := io.ReadAll(decrypter)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkXTEA_DifferentDataSizes(b *testing.B) {
	sizes := []int{8, 64, 512, 4096, 32768}

	for _, size := range sizes {
		data := make([]byte, size)
		for i := range data {
			data[i] = byte(i % 256)
		}

		b.Run(fmt.Sprintf("Size_%d", size), func(b *testing.B) {
			c := cipher.NewXteaCipher(cipher.CBC)
			c.SetKey(benchKey16)
			c.SetIV(benchIV8)
			c.SetPadding(cipher.PKCS7)

			encrypter := NewStdEncrypter(c)
			if encrypter.Error != nil {
				b.Fatal(encrypter.Error)
			}

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_, err := encrypter.Encrypt(data)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
