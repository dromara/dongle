package base64

import (
	"bytes"
	"fmt"
	"io"
	"testing"

	"github.com/dromara/dongle/internal/mock"
)

// BenchmarkStdEncoder_Encode benchmarks the standard base64 encoder with small data
func BenchmarkStdEncoder_Encode(b *testing.B) {
	data := []byte("Hello, World! This is a test string for base64 encoding benchmark.")
	encoder := NewStdEncoder(StdAlphabet)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		encoder.Encode(data)
	}
}

// BenchmarkStdEncoder_EncodeLarge benchmarks the standard base64 encoder with large data
func BenchmarkStdEncoder_EncodeLarge(b *testing.B) {
	// Create a larger data set for testing
	data := bytes.Repeat([]byte("Hello, World! "), 1000) // ~15KB
	encoder := NewStdEncoder(StdAlphabet)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		encoder.Encode(data)
	}
}

// BenchmarkStdEncoder_EncodeBinary benchmarks the standard base64 encoder with binary data
func BenchmarkStdEncoder_EncodeBinary(b *testing.B) {
	// Create binary data for testing
	data := make([]byte, 1024)
	for i := range data {
		data[i] = byte(i % 256)
	}
	encoder := NewStdEncoder(StdAlphabet)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		encoder.Encode(data)
	}
}

// BenchmarkStdEncoder_EncodeEmpty benchmarks the standard base64 encoder with empty data
func BenchmarkStdEncoder_EncodeEmpty(b *testing.B) {
	var data []byte
	encoder := NewStdEncoder(StdAlphabet)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		encoder.Encode(data)
	}
}

// BenchmarkStdEncoder_EncodeSingleByte benchmarks the standard base64 encoder with single byte
func BenchmarkStdEncoder_EncodeSingleByte(b *testing.B) {
	data := []byte{0x41} // 'A'
	encoder := NewStdEncoder(StdAlphabet)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		encoder.Encode(data)
	}
}

// BenchmarkStdEncoder_EncodeBlockSize benchmarks the standard base64 encoder with block size data
func BenchmarkStdEncoder_EncodeBlockSize(b *testing.B) {
	// Base64 processes data in 3-byte blocks
	data := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06}
	encoder := NewStdEncoder(StdAlphabet)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		encoder.Encode(data)
	}
}

// BenchmarkStdEncoder_EncodeURLSafe benchmarks the standard base64 encoder with URL-safe alphabet
func BenchmarkStdEncoder_EncodeURLSafe(b *testing.B) {
	data := []byte("Hello, World! This is a test string for URL-safe base64 encoding benchmark.")
	encoder := NewStdEncoder(URLAlphabet)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		encoder.Encode(data)
	}
}

// BenchmarkStdEncoder_EncodeUnicode benchmarks the standard base64 encoder with Unicode data
func BenchmarkStdEncoder_EncodeUnicode(b *testing.B) {
	data := []byte("你好世界，这是一个包含中文的测试字符串")
	encoder := NewStdEncoder(StdAlphabet)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		encoder.Encode(data)
	}
}

// BenchmarkStdEncoder_EncodeLeadingZeros benchmarks the standard base64 encoder with leading zeros
func BenchmarkStdEncoder_EncodeLeadingZeros(b *testing.B) {
	data := []byte{0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05}
	encoder := NewStdEncoder(StdAlphabet)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		encoder.Encode(data)
	}
}

// BenchmarkStdEncoder_EncodeMixedData benchmarks the standard base64 encoder with mixed data types
func BenchmarkStdEncoder_EncodeMixedData(b *testing.B) {
	data := []byte{
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
	}
	encoder := NewStdEncoder(StdAlphabet)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		encoder.Encode(data)
	}
}

// BenchmarkStdDecoder_Decode benchmarks the standard base64 decoder with small data
func BenchmarkStdDecoder_Decode(b *testing.B) {
	// Create encoded data for testing
	encoder := NewStdEncoder(StdAlphabet)
	original := []byte("Hello, World! This is a test string for base64 decoding benchmark.")
	encoded := encoder.Encode(original)
	decoder := NewStdDecoder(StdAlphabet)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		decoder.Decode(encoded)
	}
}

// BenchmarkStdDecoder_DecodeLarge benchmarks the standard base64 decoder with large data
func BenchmarkStdDecoder_DecodeLarge(b *testing.B) {
	// Create large encoded data for testing
	encoder := NewStdEncoder(StdAlphabet)
	original := bytes.Repeat([]byte("Hello, World! "), 1000) // ~15KB
	encoded := encoder.Encode(original)
	decoder := NewStdDecoder(StdAlphabet)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		decoder.Decode(encoded)
	}
}

// BenchmarkStdDecoder_DecodeBinary benchmarks the standard base64 decoder with binary data
func BenchmarkStdDecoder_DecodeBinary(b *testing.B) {
	// Create binary encoded data for testing
	encoder := NewStdEncoder(StdAlphabet)
	original := make([]byte, 1024)
	for i := range original {
		original[i] = byte(i % 256)
	}
	encoded := encoder.Encode(original)
	decoder := NewStdDecoder(StdAlphabet)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		decoder.Decode(encoded)
	}
}

// BenchmarkStdDecoder_DecodeEmpty benchmarks the standard base64 decoder with empty data
func BenchmarkStdDecoder_DecodeEmpty(b *testing.B) {
	var data []byte
	decoder := NewStdDecoder(StdAlphabet)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		decoder.Decode(data)
	}
}

// BenchmarkStdDecoder_DecodeURLSafe benchmarks the standard base64 decoder with URL-safe alphabet
func BenchmarkStdDecoder_DecodeURLSafe(b *testing.B) {
	// Create URL-safe encoded data for testing
	encoder := NewStdEncoder(URLAlphabet)
	original := []byte("Hello, World! This is a test string for URL-safe base64 decoding benchmark.")
	encoded := encoder.Encode(original)
	decoder := NewStdDecoder(URLAlphabet)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		decoder.Decode(encoded)
	}
}

// BenchmarkStdDecoder_DecodeUnicode benchmarks the standard base64 decoder with unicode data
func BenchmarkStdDecoder_DecodeUnicode(b *testing.B) {
	// Create encoded unicode data for testing
	encoder := NewStdEncoder(StdAlphabet)
	original := []byte("你好世界，这是一个包含中文的测试字符串")
	encoded := encoder.Encode(original)
	decoder := NewStdDecoder(StdAlphabet)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		decoder.Decode(encoded)
	}
}

// BenchmarkStdDecoder_DecodeWithPadding benchmarks the standard base64 decoder with padded data
func BenchmarkStdDecoder_DecodeWithPadding(b *testing.B) {
	// Create encoded data with padding for testing
	encoder := NewStdEncoder(StdAlphabet)
	original := []byte{0x01, 0x02, 0x03} // 3 bytes will produce padding
	encoded := encoder.Encode(original)
	decoder := NewStdDecoder(StdAlphabet)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		decoder.Decode(encoded)
	}
}

// BenchmarkStreamEncoder_Write benchmarks the streaming base64 encoder
func BenchmarkStreamEncoder_Write(b *testing.B) {
	data := []byte("Hello, World! This is a test string for streaming base64 encoding benchmark.")
	var buf bytes.Buffer
	encoder := NewStreamEncoder(&buf, StdAlphabet)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		buf.Reset()
		encoder.Write(data)
		encoder.Close()
	}
}

// BenchmarkStreamEncoder_WriteLarge benchmarks the streaming base64 encoder with large data
func BenchmarkStreamEncoder_WriteLarge(b *testing.B) {
	data := bytes.Repeat([]byte("Hello, World! "), 1000) // ~15KB
	var buf bytes.Buffer
	encoder := NewStreamEncoder(&buf, StdAlphabet)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		buf.Reset()
		encoder.Write(data)
		encoder.Close()
	}
}

// BenchmarkStreamEncoder_WriteChunked benchmarks the streaming base64 encoder with chunked writes
func BenchmarkStreamEncoder_WriteChunked(b *testing.B) {
	chunks := [][]byte{
		[]byte("Hello, "),
		[]byte("World! "),
		[]byte("This is a "),
		[]byte("test string "),
		[]byte("for streaming "),
		[]byte("base64 encoding "),
		[]byte("benchmark."),
	}
	var buf bytes.Buffer
	encoder := NewStreamEncoder(&buf, StdAlphabet)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		buf.Reset()
		for _, chunk := range chunks {
			encoder.Write(chunk)
		}
		encoder.Close()
	}
}

// BenchmarkStreamEncoder_WriteURLSafe benchmarks the streaming base64 encoder with URL-safe alphabet
func BenchmarkStreamEncoder_WriteURLSafe(b *testing.B) {
	data := []byte("Hello, World! This is a test string for URL-safe streaming base64 encoding benchmark.")
	var buf bytes.Buffer
	encoder := NewStreamEncoder(&buf, URLAlphabet)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		buf.Reset()
		encoder.Write(data)
		encoder.Close()
	}
}

// BenchmarkStreamDecoder_Read benchmarks the streaming base64 decoder
func BenchmarkStreamDecoder_Read(b *testing.B) {
	// Create encoded data for testing
	encoder := NewStdEncoder(StdAlphabet)
	original := []byte("Hello, World! This is a test string for streaming base64 decoding benchmark.")
	encoded := encoder.Encode(original)

	// Create a reader from the encoded data
	reader := mock.NewFile(encoded, "test.bin")
	defer reader.Close()
	decoder := NewStreamDecoder(reader, StdAlphabet)

	// Buffer to read into
	buf := make([]byte, 1024)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		reader.Seek(0, 0) // Reset reader position
		decoder.Read(buf)
	}
}

// BenchmarkStreamDecoder_ReadLarge benchmarks the streaming base64 decoder with large data
func BenchmarkStreamDecoder_ReadLarge(b *testing.B) {
	// Create large encoded data for testing
	encoder := NewStdEncoder(StdAlphabet)
	original := bytes.Repeat([]byte("Hello, World! "), 1000) // ~15KB
	encoded := encoder.Encode(original)

	// Create a reader from the encoded data
	reader := mock.NewFile(encoded, "test.bin")
	defer reader.Close()
	decoder := NewStreamDecoder(reader, StdAlphabet)

	// Buffer to read into
	buf := make([]byte, 1024)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		reader.Seek(0, 0) // Reset reader position
		decoder.Read(buf)
	}
}

// BenchmarkStreamDecoder_ReadURLSafe benchmarks the streaming base64 decoder with URL-safe alphabet
func BenchmarkStreamDecoder_ReadURLSafe(b *testing.B) {
	// Create URL-safe encoded data for testing
	encoder := NewStdEncoder(URLAlphabet)
	original := []byte("Hello, World! This is a test string for URL-safe streaming base64 decoding benchmark.")
	encoded := encoder.Encode(original)

	// Create a reader from the encoded data
	reader := mock.NewFile(encoded, "test.bin")
	defer reader.Close()
	decoder := NewStreamDecoder(reader, URLAlphabet)

	// Buffer to read into
	buf := make([]byte, 1024)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		reader.Seek(0, 0) // Reset reader position
		decoder.Read(buf)
	}
}

// BenchmarkConvenience_Encode benchmarks the convenience Encode function
func BenchmarkConvenience_Encode(b *testing.B) {
	data := []byte("Hello, World! This is a test string for base64 convenience encoding benchmark.")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Encode(data)
	}
}

// BenchmarkConvenience_EncodeURLSafe benchmarks the convenience EncodeURLSafe function
func BenchmarkConvenience_EncodeURLSafe(b *testing.B) {
	data := []byte("Hello, World! This is a test string for URL-safe base64 convenience encoding benchmark.")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		EncodeURLSafe(data)
	}
}

// BenchmarkConvenience_Decode benchmarks the convenience Decode function
func BenchmarkConvenience_Decode(b *testing.B) {
	// Create encoded data for testing
	encoder := NewStdEncoder(StdAlphabet)
	original := []byte("Hello, World! This is a test string for base64 convenience decoding benchmark.")
	encoded := encoder.Encode(original)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Decode(encoded)
	}
}

// BenchmarkConvenience_DecodeURLSafe benchmarks the convenience DecodeURLSafe function
func BenchmarkConvenience_DecodeURLSafe(b *testing.B) {
	// Create URL-safe encoded data for testing
	encoder := NewStdEncoder(URLAlphabet)
	original := []byte("Hello, World! This is a test string for URL-safe base64 convenience decoding benchmark.")
	encoded := encoder.Encode(original)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		DecodeURLSafe(encoded)
	}
}

// BenchmarkStdEncoder_EncodeWithError benchmarks the standard base64 encoder with existing error
func BenchmarkStdEncoder_EncodeWithError(b *testing.B) {
	data := []byte("Hello, World!")
	encoder := &StdEncoder{Error: bytes.ErrTooLarge} // This will cause an error

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		encoder.Encode(data)
	}
}

// BenchmarkStdDecoder_DecodeWithError benchmarks the standard base64 decoder with invalid data
func BenchmarkStdDecoder_DecodeWithError(b *testing.B) {
	// Create invalid base64 data (contains characters not in the alphabet)
	invalidData := []byte("INVALID_BASE64_DATA!!!")
	decoder := NewStdDecoder(StdAlphabet)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		decoder.Decode(invalidData)
	}
}

// BenchmarkStdEncoder_EncodeShortStrings benchmarks the standard base64 encoder with short strings
func BenchmarkStdEncoder_EncodeShortStrings(b *testing.B) {
	shortStrings := [][]byte{
		[]byte("A"),
		[]byte("AB"),
		[]byte("ABC"),
		[]byte("ABCD"),
		[]byte("ABCDE"),
	}
	encoder := NewStdEncoder(StdAlphabet)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, str := range shortStrings {
			encoder.Encode(str)
		}
	}
}

// BenchmarkStdDecoder_DecodeShortStrings benchmarks the standard base64 decoder with short strings
func BenchmarkStdDecoder_DecodeShortStrings(b *testing.B) {
	// Create encoded short strings for testing
	encoder := NewStdEncoder(StdAlphabet)
	shortStrings := [][]byte{
		[]byte("A"),
		[]byte("AB"),
		[]byte("ABC"),
		[]byte("ABCD"),
		[]byte("ABCDE"),
	}

	var encodedStrings [][]byte
	for _, str := range shortStrings {
		encodedStrings = append(encodedStrings, encoder.Encode(str))
	}

	decoder := NewStdDecoder(StdAlphabet)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, encoded := range encodedStrings {
			decoder.Decode(encoded)
		}
	}
}

// BenchmarkStdEncoder_EncodeDifferentAlphabets benchmarks encoding with different alphabets
func BenchmarkStdEncoder_EncodeDifferentAlphabets(b *testing.B) {
	data := []byte("Hello, World! This is a test string for different alphabet base64 encoding benchmark.")

	// Test both standard and URL-safe alphabets
	alphabets := []string{StdAlphabet, URLAlphabet}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, alphabet := range alphabets {
			encoder := NewStdEncoder(alphabet)
			encoder.Encode(data)
		}
	}
}

// BenchmarkStdDecoder_DecodeDifferentAlphabets benchmarks decoding with different alphabets
func BenchmarkStdDecoder_DecodeDifferentAlphabets(b *testing.B) {
	// Create encoded data with both alphabets for testing
	data := []byte("Hello, World! This is a test string for different alphabet base64 decoding benchmark.")

	// Test both standard and URL-safe alphabets
	alphabets := []string{StdAlphabet, URLAlphabet}

	var encodedStrings [][]byte
	for _, alphabet := range alphabets {
		encoder := NewStdEncoder(alphabet)
		encodedStrings = append(encodedStrings, encoder.Encode(data))
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for j, alphabet := range alphabets {
			decoder := NewStdDecoder(alphabet)
			decoder.Decode(encodedStrings[j])
		}
	}
}

// BenchmarkStreamingVsStandard benchmarks streaming vs standard performance
func BenchmarkStreamingVsStandard(b *testing.B) {
	data := bytes.Repeat([]byte("Hello, World! "), 100) // ~1.5KB

	b.Run("standard_encoder", func(b *testing.B) {
		encoder := NewStdEncoder(StdAlphabet)
		b.ResetTimer()
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			encoder.Encode(data)
		}
	})

	b.Run("streaming_encoder", func(b *testing.B) {
		var buf bytes.Buffer
		encoder := NewStreamEncoder(&buf, StdAlphabet)
		b.ResetTimer()
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			buf.Reset()
			encoder.Write(data)
			encoder.Close()
		}
	})

	b.Run("standard_decoder", func(b *testing.B) {
		encoder := NewStdEncoder(StdAlphabet)
		decoder := NewStdDecoder(StdAlphabet)
		encoded := encoder.Encode(data)
		b.ResetTimer()
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			decoder.Decode(encoded)
		}
	})

	b.Run("streaming_decoder", func(b *testing.B) {
		encoder := NewStdEncoder(StdAlphabet)
		encoded := encoder.Encode(data)
		reader := mock.NewFile(encoded, "test.bin")
		defer reader.Close()
		decoder := NewStreamDecoder(reader, StdAlphabet)
		b.ResetTimer()
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			reader.Seek(0, 0)
			io.Copy(io.Discard, decoder)
		}
	})
}

// BenchmarkLargeFileStreaming benchmarks streaming performance for various data sizes
func BenchmarkLargeFileStreaming(b *testing.B) {
	sizes := []int{1024, 10 * 1024, 50 * 1024} // 1KB, 10KB, 50KB

	for _, size := range sizes {
		data := make([]byte, size)
		for i := range data {
			data[i] = byte(i % 256)
		}

		b.Run(fmt.Sprintf("encode_%dKB", size/1024), func(b *testing.B) {
			var buf bytes.Buffer
			encoder := NewStreamEncoder(&buf, StdAlphabet)
			b.ResetTimer()
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				buf.Reset()
				encoder.Write(data)
				encoder.Close()
			}
		})

		b.Run(fmt.Sprintf("decode_%dKB", size/1024), func(b *testing.B) {
			encoded := NewStdEncoder(StdAlphabet).Encode(data)
			reader := mock.NewFile(encoded, "test.bin")
			defer reader.Close()
			decoder := NewStreamDecoder(reader, StdAlphabet)
			b.ResetTimer()
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				reader.Seek(0, 0)
				io.Copy(io.Discard, decoder)
			}
		})
	}
}

// BenchmarkStreamingBufferSizes benchmarks streaming performance with different buffer sizes
func BenchmarkStreamingBufferSizes(b *testing.B) {
	data := make([]byte, 20*1024) // 20KB
	for i := range data {
		data[i] = byte(i % 256)
	}

	bufferSizes := []int{256, 512, 1024, 2048} // Reduced from 5 sizes to 4

	for _, bufSize := range bufferSizes {
		b.Run(fmt.Sprintf("buffer_%d", bufSize), func(b *testing.B) {
			var buf bytes.Buffer
			encoder := NewStreamEncoder(&buf, StdAlphabet)
			b.ResetTimer()
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				buf.Reset()
				// Write in chunks of buffer size
				for j := 0; j < len(data); j += bufSize {
					end := j + bufSize
					if end > len(data) {
						end = len(data)
					}
					encoder.Write(data[j:end])
				}
				encoder.Close()
			}
		})
	}
}
