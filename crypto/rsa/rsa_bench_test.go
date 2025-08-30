package rsa

import (
	"bytes"
	"crypto"
	"testing"

	"github.com/dromara/dongle/crypto/keypair"
)

// BenchmarkStdEncrypter tests the performance of standard encryption
func BenchmarkStdEncrypter(b *testing.B) {
	// Create key pair
	kp := keypair.NewRsaKeyPair()
	kp.SetFormat(keypair.PKCS1)
	kp.SetHash(crypto.SHA256)
	kp.GenKeyPair(2048)

	// Test data
	testData := []byte("Hello, this is a test message for benchmarking RSA encryption performance!")

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		enc := NewStdEncrypter(kp)
		_, err := enc.Encrypt(testData)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkStdDecrypter tests the performance of standard decryption
func BenchmarkStdDecrypter(b *testing.B) {
	// Create key pair
	kp := keypair.NewRsaKeyPair()
	kp.SetFormat(keypair.PKCS1)
	kp.SetHash(crypto.SHA256)
	kp.GenKeyPair(2048)

	// Encrypt test data first
	enc := NewStdEncrypter(kp)
	encrypted, err := enc.Encrypt([]byte("Hello, this is a test message for benchmarking RSA decryption performance!"))
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		dec := NewStdDecrypter(kp)
		_, err := dec.Decrypt(encrypted)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkStreamEncrypter tests the performance of streaming encryption
func BenchmarkStreamEncrypter(b *testing.B) {
	// Create key pair
	kp := keypair.NewRsaKeyPair()
	kp.SetFormat(keypair.PKCS1)
	kp.SetHash(crypto.SHA256)
	kp.GenKeyPair(2048)

	// Test data
	testData := []byte("Hello, this is a test message for benchmarking RSA streaming encryption performance!")

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		var buf bytes.Buffer
		enc := NewStreamEncrypter(&buf, kp)
		_, err := enc.Write(testData)
		if err != nil {
			b.Fatal(err)
		}
		err = enc.Close()
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkStreamDecrypter tests the performance of streaming decryption
func BenchmarkStreamDecrypter(b *testing.B) {
	// Create key pair
	kp := keypair.NewRsaKeyPair()
	kp.SetFormat(keypair.PKCS1)
	kp.SetHash(crypto.SHA256)
	kp.GenKeyPair(2048)

	// Create encrypted data first
	var buf bytes.Buffer
	enc := NewStreamEncrypter(&buf, kp)
	testData := []byte("Hello, this is a test message for benchmarking RSA streaming decryption performance!")
	_, err := enc.Write(testData)
	if err != nil {
		b.Fatal(err)
	}
	err = enc.Close()
	if err != nil {
		b.Fatal(err)
	}

	encryptedData := buf.Bytes()

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		reader := bytes.NewReader(encryptedData)
		dec := NewStreamDecrypter(reader, kp)
		result := make([]byte, 100)
		_, err := dec.Read(result)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkLargeData tests performance with larger data sets
func BenchmarkLargeData(b *testing.B) {
	// Create key pair
	kp := keypair.NewRsaKeyPair()
	kp.SetFormat(keypair.PKCS1)
	kp.SetHash(crypto.SHA256)
	kp.GenKeyPair(2048)

	// Create larger test data (1KB)
	testData := make([]byte, 1024)
	for i := range testData {
		testData[i] = byte(i % 256)
	}

	b.ResetTimer()
	b.ReportAllocs()

	b.Run("Standard_Encryption", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			enc := NewStdEncrypter(kp)
			_, err := enc.Encrypt(testData)
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("Streaming_Encryption", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			var buf bytes.Buffer
			enc := NewStreamEncrypter(&buf, kp)
			_, err := enc.Write(testData)
			if err != nil {
				b.Fatal(err)
			}
			err = enc.Close()
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}
