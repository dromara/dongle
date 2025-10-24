package unicode

import (
	"strings"
	"testing"
)

var (
	// Test data for benchmarking
	smallData   = []byte("hello")
	mediumData  = []byte("hello world this is a medium sized string for testing")
	largeData   = make([]byte, 1024*1024) // 1MB
	unicodeData = []byte("你好世界这是一个测试字符串")
)

func init() {
	// Fill large data with test content
	for i := range largeData {
		largeData[i] = byte(i % 256)
	}
}

func BenchmarkStdEncoder_Encode(b *testing.B) {
	b.Run("small", func(b *testing.B) {
		encoder := NewStdEncoder()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			encoder.Encode(smallData)
		}
	})

	b.Run("medium", func(b *testing.B) {
		encoder := NewStdEncoder()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			encoder.Encode(mediumData)
		}
	})

	b.Run("large", func(b *testing.B) {
		encoder := NewStdEncoder()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			encoder.Encode(largeData)
		}
	})

	b.Run("unicode", func(b *testing.B) {
		encoder := NewStdEncoder()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			encoder.Encode(unicodeData)
		}
	})
}

func BenchmarkStdDecoder_Decode(b *testing.B) {
	// Pre-encode data for decoding benchmarks
	encoder := NewStdEncoder()
	smallEncoded := encoder.Encode(smallData)
	mediumEncoded := encoder.Encode(mediumData)
	largeEncoded := encoder.Encode(largeData)
	unicodeEncoded := encoder.Encode(unicodeData)

	b.Run("small", func(b *testing.B) {
		decoder := NewStdDecoder()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			decoder.Decode(smallEncoded)
		}
	})

	b.Run("medium", func(b *testing.B) {
		decoder := NewStdDecoder()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			decoder.Decode(mediumEncoded)
		}
	})

	b.Run("large", func(b *testing.B) {
		decoder := NewStdDecoder()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			decoder.Decode(largeEncoded)
		}
	})

	b.Run("unicode", func(b *testing.B) {
		decoder := NewStdDecoder()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			decoder.Decode(unicodeEncoded)
		}
	})
}

func BenchmarkStreamEncoder_Write(b *testing.B) {
	b.Run("small", func(b *testing.B) {
		var buf strings.Builder
		encoder := NewStreamEncoder(&buf)
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			encoder.Write(smallData)
		}
		encoder.Close()
	})

	b.Run("medium", func(b *testing.B) {
		var buf strings.Builder
		encoder := NewStreamEncoder(&buf)
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			encoder.Write(mediumData)
		}
		encoder.Close()
	})

	b.Run("large", func(b *testing.B) {
		var buf strings.Builder
		encoder := NewStreamEncoder(&buf)
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			encoder.Write(largeData)
		}
		encoder.Close()
	})

	b.Run("unicode", func(b *testing.B) {
		var buf strings.Builder
		encoder := NewStreamEncoder(&buf)
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			encoder.Write(unicodeData)
		}
		encoder.Close()
	})
}

func BenchmarkStreamDecoder_Read(b *testing.B) {
	// Pre-encode data for reading benchmarks
	encoder := NewStdEncoder()
	smallEncoded := encoder.Encode(smallData)
	mediumEncoded := encoder.Encode(mediumData)
	largeEncoded := encoder.Encode(largeData)
	unicodeEncoded := encoder.Encode(unicodeData)

	b.Run("small", func(b *testing.B) {
		reader := strings.NewReader(string(smallEncoded))
		decoder := NewStreamDecoder(reader)
		buf := make([]byte, 1024)
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			reader.Seek(0, 0)
			decoder.Read(buf)
		}
	})

	b.Run("medium", func(b *testing.B) {
		reader := strings.NewReader(string(mediumEncoded))
		decoder := NewStreamDecoder(reader)
		buf := make([]byte, 1024)
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			reader.Seek(0, 0)
			decoder.Read(buf)
		}
	})

	b.Run("large", func(b *testing.B) {
		reader := strings.NewReader(string(largeEncoded))
		decoder := NewStreamDecoder(reader)
		buf := make([]byte, 1024)
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			reader.Seek(0, 0)
			decoder.Read(buf)
		}
	})

	b.Run("unicode", func(b *testing.B) {
		reader := strings.NewReader(string(unicodeEncoded))
		decoder := NewStreamDecoder(reader)
		buf := make([]byte, 1024)
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			reader.Seek(0, 0)
			decoder.Read(buf)
		}
	})
}

func BenchmarkEncodeDecodeRoundTrip(b *testing.B) {
	b.Run("small", func(b *testing.B) {
		encoder := NewStdEncoder()
		decoder := NewStdDecoder()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			encoded := encoder.Encode(smallData)
			decoder.Decode(encoded)
		}
	})

	b.Run("medium", func(b *testing.B) {
		encoder := NewStdEncoder()
		decoder := NewStdDecoder()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			encoded := encoder.Encode(mediumData)
			decoder.Decode(encoded)
		}
	})

	b.Run("unicode", func(b *testing.B) {
		encoder := NewStdEncoder()
		decoder := NewStdDecoder()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			encoded := encoder.Encode(unicodeData)
			decoder.Decode(encoded)
		}
	})
}
