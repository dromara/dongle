package twofish

import (
	"testing"

	"github.com/dromara/dongle/crypto/cipher"
)

// Benchmark data
var (
	benchKey128 = []byte("1234567890123456")                 // 16-byte key
	benchKey192 = []byte("123456789012345678901234")         // 24-byte key
	benchKey256 = []byte("12345678901234567890123456789012") // 32-byte key
	benchIV     = []byte("1234567890123456")                 // 16-byte IV
	benchData   = []byte("This is a test message for Twofish encryption and decryption benchmarking.")
)

func BenchmarkTwofish_Encrypt_128bit(b *testing.B) {
	c := cipher.NewTwofishCipher(cipher.CBC)
	c.SetKey(benchKey128)
	c.SetIV(benchIV)

	encrypter := NewStdEncrypter(c)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = encrypter.Encrypt(benchData)
	}
}

func BenchmarkTwofish_Encrypt_192bit(b *testing.B) {
	c := cipher.NewTwofishCipher(cipher.CBC)
	c.SetKey(benchKey192)
	c.SetIV(benchIV)

	encrypter := NewStdEncrypter(c)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = encrypter.Encrypt(benchData)
	}
}

func BenchmarkTwofish_Encrypt_256bit(b *testing.B) {
	c := cipher.NewTwofishCipher(cipher.CBC)
	c.SetKey(benchKey256)
	c.SetIV(benchIV)

	encrypter := NewStdEncrypter(c)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = encrypter.Encrypt(benchData)
	}
}

func BenchmarkTwofish_Decrypt_128bit(b *testing.B) {
	c := cipher.NewTwofishCipher(cipher.CBC)
	c.SetKey(benchKey128)
	c.SetIV(benchIV)

	// Pre-encrypt data
	encrypter := NewStdEncrypter(c)
	encrypted, _ := encrypter.Encrypt(benchData)

	decrypter := NewStdDecrypter(c)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = decrypter.Decrypt(encrypted)
	}
}

func BenchmarkTwofish_Decrypt_192bit(b *testing.B) {
	c := cipher.NewTwofishCipher(cipher.CBC)
	c.SetKey(benchKey192)
	c.SetIV(benchIV)

	// Pre-encrypt data
	encrypter := NewStdEncrypter(c)
	encrypted, _ := encrypter.Encrypt(benchData)

	decrypter := NewStdDecrypter(c)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = decrypter.Decrypt(encrypted)
	}
}

func BenchmarkTwofish_Decrypt_256bit(b *testing.B) {
	c := cipher.NewTwofishCipher(cipher.CBC)
	c.SetKey(benchKey256)
	c.SetIV(benchIV)

	// Pre-encrypt data
	encrypter := NewStdEncrypter(c)
	encrypted, _ := encrypter.Encrypt(benchData)

	decrypter := NewStdDecrypter(c)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = decrypter.Decrypt(encrypted)
	}
}

func BenchmarkTwofish_RoundTrip_128bit(b *testing.B) {
	c := cipher.NewTwofishCipher(cipher.CBC)
	c.SetKey(benchKey128)
	c.SetIV(benchIV)

	encrypter := NewStdEncrypter(c)
	decrypter := NewStdDecrypter(c)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		encrypted, _ := encrypter.Encrypt(benchData)
		_, _ = decrypter.Decrypt(encrypted)
	}
}

func BenchmarkTwofish_RoundTrip_192bit(b *testing.B) {
	c := cipher.NewTwofishCipher(cipher.CBC)
	c.SetKey(benchKey192)
	c.SetIV(benchIV)

	encrypter := NewStdEncrypter(c)
	decrypter := NewStdDecrypter(c)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		encrypted, _ := encrypter.Encrypt(benchData)
		_, _ = decrypter.Decrypt(encrypted)
	}
}

func BenchmarkTwofish_RoundTrip_256bit(b *testing.B) {
	c := cipher.NewTwofishCipher(cipher.CBC)
	c.SetKey(benchKey256)
	c.SetIV(benchIV)

	encrypter := NewStdEncrypter(c)
	decrypter := NewStdDecrypter(c)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		encrypted, _ := encrypter.Encrypt(benchData)
		_, _ = decrypter.Decrypt(encrypted)
	}
}
