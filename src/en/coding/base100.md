---
title: Base100 Encoding/Decoding
head:
  - - meta
    - name: description
      content: Base100 Encoding/Decoding | A lightweight, semantic and developer-friendly golang encoding & crypto library
  - - meta
    - name: keywords
      content: encoding, decoding, base100, emoji, base100-encoding, base100-decoding, emoji-encoding, emoji-decoding
---

# Base100

Base100 is an encoding method that converts binary data to `Emoji` characters, where each byte is converted to a `4-byte` UTF-8 sequence representing an emoji symbol. `dongle` supports standard and streaming `Base100` encoding.

### Encoding Data
Input Data

```go
// Input string
encoder := dongle.Encode.FromString("hello world").ByBase100()
// Input byte slice
encoder := dongle.Encode.FromBytes([]byte("hello world")).ByBase100()
// Input file stream
file, _ := os.Open("test.txt")
encoder := dongle.Encode.FromFile(file).ByBase100()

// Check encoding error
if encoder.Error != nil {
	fmt.Printf("Encoding error: %v\n", encoder.Error)
	return
}
```

Output Data

```go
// Output string
encoder.ToString() // 👟👜👣👣👦🐗👮👦👩👣👛
// Output byte slice
encoder.ToBytes()  // []byte("👟👜👣👣👦🐗👮👦👩👣👛")
```

### Decoding Data
Input Data

```go
// Input string
decoder := dongle.Decode.FromString("👟👜👣👣👦🐗👮👦👩👣👛").ByBase100()
// Input byte slice
decoder := dongle.Decode.FromBytes([]byte("👟👜👣👣👦🐗👮👦👩👣👛")).ByBase100()
// Input file stream
file, _ := os.Open("test.txt")
decoder := dongle.Decode.FromFile(file).ByBase100()

// Check decoding error
if decoder.Error != nil {
	fmt.Printf("Decoding error: %v\n", decoder.Error)
	return
}
```

Output Data

```go
// Output string
decoder.ToString() // hello world
// Output byte slice
decoder.ToBytes()  // []byte("hello world")
```
 