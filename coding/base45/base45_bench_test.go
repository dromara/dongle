package base45

import (
	"bytes"
	"testing"
)

func BenchmarkStdEncoder_Encode(b *testing.B) {
	data := []byte("Hello, World! This is a test string for base45 encoding benchmark.")
	encoder := NewStdEncoder()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		encoder.Encode(data)
	}
}

func BenchmarkStdEncoder_EncodeLarge(b *testing.B) {
	// Create a larger data set for testing
	data := bytes.Repeat([]byte("Hello, World! "), 1000) // ~15KB
	encoder := NewStdEncoder()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		encoder.Encode(data)
	}
}

func BenchmarkStdEncoder_EncodeBinary(b *testing.B) {
	// Create binary data for testing
	data := make([]byte, 1024)
	for i := range data {
		data[i] = byte(i % 256)
	}
	encoder := NewStdEncoder()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		encoder.Encode(data)
	}
}

func BenchmarkStdDecoder_Decode(b *testing.B) {
	// Create encoded data for testing
	encoder := NewStdEncoder()
	original := []byte("Hello, World! This is a test string for base45 decoding benchmark.")
	encoded := encoder.Encode(original)
	decoder := NewStdDecoder()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		decoder.Decode(encoded)
	}
}

func BenchmarkStdDecoder_DecodeLarge(b *testing.B) {
	// Create large encoded data for testing
	encoder := NewStdEncoder()
	original := bytes.Repeat([]byte("Hello, World! "), 1000) // ~15KB
	encoded := encoder.Encode(original)
	decoder := NewStdDecoder()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		decoder.Decode(encoded)
	}
}

func BenchmarkStdDecoder_DecodeBinary(b *testing.B) {
	// Create binary encoded data for testing
	encoder := NewStdEncoder()
	original := make([]byte, 1024)
	for i := range original {
		original[i] = byte(i % 256)
	}
	encoded := encoder.Encode(original)
	decoder := NewStdDecoder()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		decoder.Decode(encoded)
	}
}

func BenchmarkStreamEncoder_Write(b *testing.B) {
	data := []byte("Hello, World! This is a test string for streaming base45 encoding benchmark.")
	var buf bytes.Buffer
	encoder := NewStreamEncoder(&buf)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		buf.Reset()
		encoder.Write(data)
		encoder.Close()
	}
}

func BenchmarkStreamDecoder_Read(b *testing.B) {
	// Create encoded data for testing
	encoder := NewStdEncoder()
	original := []byte("Hello, World! This is a test string for streaming base45 decoding benchmark.")
	encoded := encoder.Encode(original)
	reader := bytes.NewReader(encoded)
	decoder := NewStreamDecoder(reader)

	buffer := make([]byte, 1024)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		reader.Reset(encoded)
		decoder.Read(buffer)
	}
}

func BenchmarkNewStdEncoder(b *testing.B) {
	for i := 0; i < b.N; i++ {
		NewStdEncoder()
	}
}

func BenchmarkNewStdDecoder(b *testing.B) {
	for i := 0; i < b.N; i++ {
		NewStdDecoder()
	}
}
