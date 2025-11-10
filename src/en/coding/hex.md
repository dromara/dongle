---
title: Hex Encoding/Decoding
head:
  - - meta
    - name: description
      content: Hex encoding/decoding, also known as Base16, uses 16 characters (0-9, A-F), supports custom case, supports standard and streaming processing, supports string, byte and file input, provides string and byte output
  - - meta
    - name: keywords
      content: dongle, go-dongle, encoding, decoding, Hex, Base16, case, custom character set, streaming processing, string input, byte input, file input, string output, byte output
---

# Hex

Hex is an encoding method that converts binary data to `ASCII` characters, using `16` characters (0-9, A-F) to represent data. `dongle` supports standard and streaming `Hex` encoding, also known as `Base16` encoding.

### Encoding Data
Input Data

```go
// Input string
encoder := dongle.Encode.FromString("hello world").ByHex()

// Input byte slice
encoder := dongle.Encode.FromBytes([]byte("hello world")).ByHex()

// Input file stream
file, _ := os.Open("test.txt")
encoder := dongle.Encode.FromFile(file).ByHex()

// Check encoding error
if encoder.Error != nil {
	fmt.Printf("Encoding error: %v\n", encoder.Error)
	return
}
```

Output Data

```go
// Output string
encoder.ToString() // 68656c6c6f20776f726c64
// Output byte slice
encoder.ToBytes()  // []byte("68656c6c6f20776f726c64")
```

### Decoding Data
Input Data

```go
// Input string
decoder := dongle.Decode.FromString("68656c6c6f20776f726c64").ByHex()

// Input byte slice
decoder := dongle.Decode.FromBytes([]byte("68656c6c6f20776f726c64")).ByHex()

// Input file stream
file, _ := os.Open("test.txt")
decoder := dongle.Decode.FromFile(file).ByHex()

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