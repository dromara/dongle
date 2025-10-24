---
title: Unicode Encoding/Decoding
head:
  - - meta
    - name: description
      content: Unicode Encoding/Decoding | A lightweight, semantic and developer-friendly golang encoding & crypto library
  - - meta
    - name: keywords
      content: encoding, decoding, unicode, unicode-encoding, unicode-decoding, escape-sequence
---

# Unicode

Unicode is an encoding method that converts byte data to `Unicode` escape sequences, using `\uXXXX` format to represent non-`ASCII` characters. `dongle` supports standard and streaming `Unicode` encoding, implemented based on `strconv.QuoteToASCII`.

### Encoding Data
Input Data

```go
// Input string
encoder := dongle.Encode.FromString("你好世界").ByUnicode()

// Input byte slice
encoder := dongle.Encode.FromBytes([]byte("你好世界")).ByUnicode()

// Input file stream
file, _ := os.Open("test.txt")
encoder := dongle.Encode.FromFile(file).ByUnicode()

// Check encoding error
if encoder.Error != nil {
	fmt.Printf("Encoding error: %v\n", encoder.Error)
	return
}
```

Output Data

```go
// Output string
encoder.ToString() // \u4f60\u597d\u4e16\u754c
// Output byte slice
encoder.ToBytes()  // []byte("\u4f60\u597d\u4e16\u754c")
```

### Decoding Data
Input Data

```go
// Input string
decoder := dongle.Decode.FromString("\u4f60\u597d\u4e16\u754c").ByUnicode()

// Input byte slice
decoder := dongle.Decode.FromBytes([]byte("\u4f60\u597d\u4e16\u754c")).ByUnicode()

// Input file stream
file, _ := os.Open("test.txt")
decoder := dongle.Decode.FromFile(file).ByUnicode()

// Check decoding error
if decoder.Error != nil {
	fmt.Printf("Decoding error: %v\n", decoder.Error)
	return
}
```

Output Data

```go
// Output string
decoder.ToString() // 你好世界
// Output byte slice
decoder.ToBytes()  // []byte("你好世界")
```