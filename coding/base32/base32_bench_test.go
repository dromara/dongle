package base32

import (
	"bytes"
	"testing"

	"github.com/dromara/dongle/mock"
)

// BenchmarkStdEncoder_Encode benchmarks the standard base32 encoder with small data
func BenchmarkStdEncoder_Encode(b *testing.B) {
	data := []byte("Hello, World! This is a test string for base32 encoding benchmark.")
	encoder := NewStdEncoder(StdAlphabet)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		encoder.Encode(data)
	}
}

// BenchmarkStdEncoder_EncodeLarge benchmarks the standard base32 encoder with large data
func BenchmarkStdEncoder_EncodeLarge(b *testing.B) {
	// Create a larger data set for testing
	data := bytes.Repeat([]byte("Hello, World! "), 1000) // ~15KB
	encoder := NewStdEncoder(StdAlphabet)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		encoder.Encode(data)
	}
}

// BenchmarkStdEncoder_EncodeBinary benchmarks the standard base32 encoder with binary data
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

// BenchmarkStdEncoder_EncodeEmpty benchmarks the standard base32 encoder with empty data
func BenchmarkStdEncoder_EncodeEmpty(b *testing.B) {
	var data []byte
	encoder := NewStdEncoder(StdAlphabet)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		encoder.Encode(data)
	}
}

// BenchmarkStdEncoder_EncodeSingleByte benchmarks the standard base32 encoder with single byte
func BenchmarkStdEncoder_EncodeSingleByte(b *testing.B) {
	data := []byte{0x41} // 'A'
	encoder := NewStdEncoder(StdAlphabet)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		encoder.Encode(data)
	}
}

// BenchmarkStdEncoder_EncodeBlockSize benchmarks the standard base32 encoder with block size data
func BenchmarkStdEncoder_EncodeBlockSize(b *testing.B) {
	// Base32 processes data in 5-byte blocks
	data := make([]byte, 5)
	for i := range data {
		data[i] = byte(i)
	}
	encoder := NewStdEncoder(StdAlphabet)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		encoder.Encode(data)
	}
}

// BenchmarkStdEncoder_EncodeHexAlphabet benchmarks the standard base32 encoder with hex alphabet
func BenchmarkStdEncoder_EncodeHexAlphabet(b *testing.B) {
	data := []byte("Hello, World! This is a test string for base32 hex encoding benchmark.")
	encoder := NewStdEncoder(HexAlphabet)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		encoder.Encode(data)
	}
}

// BenchmarkStdDecoder_Decode benchmarks the standard base32 decoder with small data
func BenchmarkStdDecoder_Decode(b *testing.B) {
	// Create encoded data for testing
	encoder := NewStdEncoder(StdAlphabet)
	original := []byte("Hello, World! This is a test string for base32 decoding benchmark.")
	encoded := encoder.Encode(original)
	decoder := NewStdDecoder(StdAlphabet)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		decoder.Decode(encoded)
	}
}

// BenchmarkStdDecoder_DecodeLarge benchmarks the standard base32 decoder with large data
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

// BenchmarkStdDecoder_DecodeBinary benchmarks the standard base32 decoder with binary data
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

// BenchmarkStdDecoder_DecodeEmpty benchmarks the standard base32 decoder with empty data
func BenchmarkStdDecoder_DecodeEmpty(b *testing.B) {
	var data []byte
	decoder := NewStdDecoder(StdAlphabet)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		decoder.Decode(data)
	}
}

// BenchmarkStdDecoder_DecodeHexAlphabet benchmarks the standard base32 decoder with hex alphabet
func BenchmarkStdDecoder_DecodeHexAlphabet(b *testing.B) {
	// Create encoded data for testing with hex alphabet
	encoder := NewStdEncoder(HexAlphabet)
	original := []byte("Hello, World! This is a test string for base32 hex decoding benchmark.")
	encoded := encoder.Encode(original)
	decoder := NewStdDecoder(HexAlphabet)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		decoder.Decode(encoded)
	}
}

// BenchmarkStreamEncoder_Write benchmarks the streaming base32 encoder
func BenchmarkStreamEncoder_Write(b *testing.B) {
	data := []byte("Hello, World! This is a test string for streaming base32 encoding benchmark.")
	var buf bytes.Buffer
	encoder := NewStreamEncoder(&buf, StdAlphabet)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		buf.Reset()
		encoder.Write(data)
		encoder.Close()
	}
}

// BenchmarkStreamEncoder_WriteLarge benchmarks the streaming base32 encoder with large data
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

// BenchmarkStreamEncoder_WriteChunked benchmarks the streaming base32 encoder with chunked writes
func BenchmarkStreamEncoder_WriteChunked(b *testing.B) {
	chunks := [][]byte{
		[]byte("Hello, "),
		[]byte("World! "),
		[]byte("This is a "),
		[]byte("test string "),
		[]byte("for streaming "),
		[]byte("base32 encoding "),
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

// BenchmarkStreamDecoder_Read benchmarks the streaming base32 decoder
func BenchmarkStreamDecoder_Read(b *testing.B) {
	// Create encoded data for testing
	encoder := NewStdEncoder(StdAlphabet)
	original := []byte("Hello, World! This is a test string for streaming base32 decoding benchmark.")
	encoded := encoder.Encode(original)

	// Create a reader from the encoded data
	reader := mock.NewFile(encoded, "test.bin")
	decoder := NewStreamDecoder(reader, StdAlphabet)

	// Buffer to read into
	buf := make([]byte, 1024)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		reader.Seek(0, 0) // Reset reader position
		decoder.Read(buf)
	}
}

// BenchmarkStreamDecoder_ReadLarge benchmarks the streaming base32 decoder with large data
func BenchmarkStreamDecoder_ReadLarge(b *testing.B) {
	// Create large encoded data for testing
	encoder := NewStdEncoder(StdAlphabet)
	original := bytes.Repeat([]byte("Hello, World! "), 1000) // ~15KB
	encoded := encoder.Encode(original)

	// Create a reader from the encoded data
	reader := mock.NewFile(encoded, "test.bin")
	decoder := NewStreamDecoder(reader, StdAlphabet)

	// Buffer to read into
	buf := make([]byte, 1024)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		reader.Seek(0, 0) // Reset reader position
		decoder.Read(buf)
	}
}

// BenchmarkStdEncoder_EncodeWithError benchmarks the standard base32 encoder with invalid alphabet
func BenchmarkStdEncoder_EncodeWithError(b *testing.B) {
	data := []byte("Hello, World!")
	encoder := NewStdEncoder("invalid") // This will cause an error

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		encoder.Encode(data)
	}
}

// BenchmarkStdDecoder_DecodeWithError benchmarks the standard base32 decoder with invalid data
func BenchmarkStdDecoder_DecodeWithError(b *testing.B) {
	// Create invalid base32 data
	invalidData := []byte("INVALID_BASE32_DATA!!!")
	decoder := NewStdDecoder(StdAlphabet)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		decoder.Decode(invalidData)
	}
}

// BenchmarkStdEncoder_EncodeUnicode benchmarks the standard base32 encoder with Unicode data
func BenchmarkStdEncoder_EncodeUnicode(b *testing.B) {
	data := []byte("你好世界，这是一个包含中文的测试字符串")
	encoder := NewStdEncoder(StdAlphabet)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		encoder.Encode(data)
	}
}

// BenchmarkStdDecoder_DecodeUnicode benchmarks the standard base32 decoder with unicode data
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

// BenchmarkStdEncoder_EncodeLeadingZeros benchmarks the standard base32 encoder with leading zeros
func BenchmarkStdEncoder_EncodeLeadingZeros(b *testing.B) {
	data := []byte{0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05}
	encoder := NewStdEncoder(StdAlphabet)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		encoder.Encode(data)
	}
}

// BenchmarkStdEncoder_EncodeMixedData benchmarks the standard base32 encoder with mixed data types
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
