package tea

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"testing"

	"github.com/dromara/dongle/crypto/cipher"
)

func BenchmarkTEA_StdEncryption(b *testing.B) {
	key := make([]byte, 16)
	rand.Read(key)

	c := cipher.NewTeaCipher(cipher.ECB)
	c.SetKey(key)

	plaintext := make([]byte, 1024)
	rand.Read(plaintext)

	encrypter := NewStdEncrypter(c)
	decrypter := NewStdDecrypter(c)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		encrypted, _ := encrypter.Encrypt(plaintext)
		decrypter.Decrypt(encrypted)
	}
}

func BenchmarkTEA_StreamEncryption(b *testing.B) {
	key := make([]byte, 16)
	rand.Read(key)

	c := cipher.NewTeaCipher(cipher.ECB)
	c.SetKey(key)

	plaintext := make([]byte, 1024)
	rand.Read(plaintext)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Encrypt
		var buf bytes.Buffer
		encrypter := NewStreamEncrypter(&buf, c)
		encrypter.Write(plaintext)
		encrypter.Close()

		// Decrypt
		reader := bytes.NewReader(buf.Bytes())
		decrypter := NewStreamDecrypter(reader, c)
		decrypted := make([]byte, len(plaintext))
		decrypter.Read(decrypted)
	}
}

func BenchmarkTEA_CBC_StdEncryption(b *testing.B) {
	key := make([]byte, 16)
	iv := make([]byte, 8)
	rand.Read(key)
	rand.Read(iv)

	c := cipher.NewTeaCipher(cipher.CBC)
	c.SetKey(key)
	c.SetIV(iv)
	c.SetPadding(cipher.PKCS7)

	plaintext := make([]byte, 1024)
	rand.Read(plaintext)

	encrypter := NewStdEncrypter(c)
	decrypter := NewStdDecrypter(c)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		encrypted, _ := encrypter.Encrypt(plaintext)
		decrypter.Decrypt(encrypted)
	}
}

func BenchmarkTEA_CBC_StreamEncryption(b *testing.B) {
	key := make([]byte, 16)
	iv := make([]byte, 8)
	rand.Read(key)
	rand.Read(iv)

	c := cipher.NewTeaCipher(cipher.CBC)
	c.SetKey(key)
	c.SetIV(iv)
	c.SetPadding(cipher.PKCS7)

	plaintext := make([]byte, 1024)
	rand.Read(plaintext)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Encrypt
		var buf bytes.Buffer
		encrypter := NewStreamEncrypter(&buf, c)
		encrypter.Write(plaintext)
		encrypter.Close()

		// Decrypt
		reader := bytes.NewReader(buf.Bytes())
		decrypter := NewStreamDecrypter(reader, c)
		decrypted := make([]byte, len(plaintext))
		decrypter.Read(decrypted)
	}
}

func BenchmarkTEA_CTR_StdEncryption(b *testing.B) {
	key := make([]byte, 16)
	iv := make([]byte, 8)
	rand.Read(key)
	rand.Read(iv)

	c := cipher.NewTeaCipher(cipher.CTR)
	c.SetKey(key)
	c.SetIV(iv)

	plaintext := make([]byte, 1024)
	rand.Read(plaintext)

	encrypter := NewStdEncrypter(c)
	decrypter := NewStdDecrypter(c)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		encrypted, _ := encrypter.Encrypt(plaintext)
		decrypter.Decrypt(encrypted)
	}
}

func BenchmarkTEA_CTR_StreamEncryption(b *testing.B) {
	key := make([]byte, 16)
	iv := make([]byte, 8)
	rand.Read(key)
	rand.Read(iv)

	c := cipher.NewTeaCipher(cipher.CTR)
	c.SetKey(key)
	c.SetIV(iv)

	plaintext := make([]byte, 1024)
	rand.Read(plaintext)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Encrypt
		var buf bytes.Buffer
		encrypter := NewStreamEncrypter(&buf, c)
		encrypter.Write(plaintext)
		encrypter.Close()

		// Decrypt
		reader := bytes.NewReader(buf.Bytes())
		decrypter := NewStreamDecrypter(reader, c)
		decrypted := make([]byte, len(plaintext))
		decrypter.Read(decrypted)
	}
}

func BenchmarkTEA_CFB_StdEncryption(b *testing.B) {
	key := make([]byte, 16)
	iv := make([]byte, 8)
	rand.Read(key)
	rand.Read(iv)

	c := cipher.NewTeaCipher(cipher.CFB)
	c.SetKey(key)
	c.SetIV(iv)

	plaintext := make([]byte, 1024)
	rand.Read(plaintext)

	encrypter := NewStdEncrypter(c)
	decrypter := NewStdDecrypter(c)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		encrypted, _ := encrypter.Encrypt(plaintext)
		decrypter.Decrypt(encrypted)
	}
}

func BenchmarkTEA_OFB_StdEncryption(b *testing.B) {
	key := make([]byte, 16)
	iv := make([]byte, 8)
	rand.Read(key)
	rand.Read(iv)

	c := cipher.NewTeaCipher(cipher.OFB)
	c.SetKey(key)
	c.SetIV(iv)

	plaintext := make([]byte, 1024)
	rand.Read(plaintext)

	encrypter := NewStdEncrypter(c)
	decrypter := NewStdDecrypter(c)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		encrypted, _ := encrypter.Encrypt(plaintext)
		decrypter.Decrypt(encrypted)
	}
}

func BenchmarkTEA_DifferentSizes(b *testing.B) {
	key := make([]byte, 16)
	rand.Read(key)

	c := cipher.NewTeaCipher(cipher.ECB)
	c.SetKey(key)

	sizes := []int{8, 64, 256, 1024, 4096}
	for _, size := range sizes {
		b.Run(fmt.Sprintf("size_%d", size), func(b *testing.B) {
			plaintext := make([]byte, size)
			rand.Read(plaintext)

			encrypter := NewStdEncrypter(c)
			decrypter := NewStdDecrypter(c)

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				encrypted, _ := encrypter.Encrypt(plaintext)
				decrypter.Decrypt(encrypted)
			}
		})
	}
}

func BenchmarkTEA_DifferentRounds(b *testing.B) {
	key := make([]byte, 16)
	rand.Read(key)

	rounds := []int{32, 64, 96}
	for _, rounds := range rounds {
		b.Run(fmt.Sprintf("rounds_%d", rounds), func(b *testing.B) {
			c := cipher.NewTeaCipher(cipher.ECB)
			c.SetKey(key)
			c.SetRounds(rounds)

			plaintext := make([]byte, 1024)
			rand.Read(plaintext)

			encrypter := NewStdEncrypter(c)
			decrypter := NewStdDecrypter(c)

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				encrypted, _ := encrypter.Encrypt(plaintext)
				decrypter.Decrypt(encrypted)
			}
		})
	}
}
