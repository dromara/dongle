package sm3

import (
	"testing"
)

func BenchmarkSM3(b *testing.B) {
	data := []byte("benchmark data for SM3 hash algorithm")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		h := New()
		h.Write(data)
		h.Sum(nil)
	}
}

func BenchmarkSM3Large(b *testing.B) {
	// Create a larger data set for testing
	data := make([]byte, 1024*1024) // 1MB
	for i := range data {
		data[i] = byte(i % 256)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		h := New()
		h.Write(data)
		h.Sum(nil)
	}
}

func BenchmarkSM3MultipleWrites(b *testing.B) {
	chunks := [][]byte{
		[]byte("first chunk"),
		[]byte("second chunk"),
		[]byte("third chunk"),
		[]byte("fourth chunk"),
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		h := New()
		for _, chunk := range chunks {
			h.Write(chunk)
		}
		h.Sum(nil)
	}
}

func BenchmarkSM3Reset(b *testing.B) {
	data := []byte("data to hash")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		h := New()
		h.Write(data)
		h.Sum(nil)
		h.Reset()
		h.Write(data)
		h.Sum(nil)
	}
}
