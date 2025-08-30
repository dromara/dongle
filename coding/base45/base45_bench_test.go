package base45

import (
	"bytes"
	"fmt"
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

// BenchmarkStreamingVsStandard compares streaming vs standard operations
func BenchmarkStreamingVsStandard(b *testing.B) {
	data := make([]byte, 10240) // 10KB for better streaming comparison
	for i := range data {
		data[i] = byte(i % 256)
	}

	b.Run("standard_encode", func(b *testing.B) {
		encoder := NewStdEncoder()
		b.ResetTimer()
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			encoder.Encode(data)
		}
	})

	b.Run("streaming_encode", func(b *testing.B) {
		var buf bytes.Buffer
		b.ResetTimer()
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			buf.Reset()
			encoder := NewStreamEncoder(&buf)
			encoder.Write(data)
			encoder.Close()
		}
	})

	// For decoding, we need encoded data first
	encoder := NewStdEncoder()
	encoded := encoder.Encode(data)

	b.Run("standard_decode", func(b *testing.B) {
		decoder := NewStdDecoder()
		b.ResetTimer()
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			decoder.Decode(encoded)
		}
	})

	b.Run("streaming_decode", func(b *testing.B) {
		buf := make([]byte, 1024)
		b.ResetTimer()
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			reader := bytes.NewReader(encoded)
			decoder := NewStreamDecoder(reader)
			decoder.Read(buf)
		}
	})
}

// BenchmarkLargeFileStreaming tests streaming performance with various file sizes
func BenchmarkLargeFileStreaming(b *testing.B) {
	sizes := []struct {
		name string
		size int
	}{
		{"1KB", 1024},
		{"10KB", 10 * 1024},
		{"100KB", 100 * 1024},
		{"1MB", 1024 * 1024},
	}

	for _, size := range sizes {
		data := make([]byte, size.size)
		for i := range data {
			data[i] = byte(i % 256)
		}

		b.Run("std_encode_"+size.name, func(b *testing.B) {
			encoder := NewStdEncoder()
			b.ResetTimer()
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				encoder.Encode(data)
			}
		})

		b.Run("streaming_encode_"+size.name, func(b *testing.B) {
			var buf bytes.Buffer
			b.ResetTimer()
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				buf.Reset()
				encoder := NewStreamEncoder(&buf)
				encoder.Write(data)
				encoder.Close()
			}
		})

		// For decoding benchmarks
		encoder := NewStdEncoder()
		encoded := encoder.Encode(data)

		b.Run("std_decode_"+size.name, func(b *testing.B) {
			decoder := NewStdDecoder()
			b.ResetTimer()
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				decoder.Decode(encoded)
			}
		})

		b.Run("streaming_decode_"+size.name, func(b *testing.B) {
			buf := make([]byte, 1024)
			b.ResetTimer()
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				reader := bytes.NewReader(encoded)
				decoder := NewStreamDecoder(reader)
				decoder.Read(buf)
			}
		})
	}
}

// BenchmarkStreamingBufferSizes tests streaming with different buffer sizes
func BenchmarkStreamingBufferSizes(b *testing.B) {
	data := make([]byte, 10240) // 10KB
	for i := range data {
		data[i] = byte(i % 256)
	}

	encoder := NewStdEncoder()
	encoded := encoder.Encode(data)

	bufferSizes := []int{256, 512, 1024, 2048, 4096}

	for _, bufSize := range bufferSizes {
		b.Run(fmt.Sprintf("buffer_%d", bufSize), func(b *testing.B) {
			buf := make([]byte, bufSize)
			b.ResetTimer()
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				reader := bytes.NewReader(encoded)
				decoder := NewStreamDecoder(reader)
				decoder.Read(buf)
			}
		})
	}
}
