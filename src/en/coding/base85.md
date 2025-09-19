---
title: Base85 Encoding/Decoding
head:
  - - meta
    - name: description
      content: Base85 Encoding/Decoding | A lightweight, semantic and developer-friendly golang encoding & crypto library
  - - meta
    - name: keywords
      content: dongle, base85, ascii85
---

# Base85

Base85 is an encoding method that converts binary data to `ASCII` characters, using `85` characters (ASCII 33-117, i.e., ! to u) to represent data. `dongle` supports standard `Base85` encoding, also known as `ASCII85`, compliant with `Adobe PostScript` and `PDF` specifications.

### Encoding Data

Input Data

```go
// Input string
encoder := dongle.Encode.FromString("hello world").ByBase85()

// Input byte slice
encoder := dongle.Encode.FromBytes([]byte("hello world")).ByBase85()

// Input file stream
file, _ := os.Open("test.txt")
encoder := dongle.Encode.FromFile(file).ByBase85()

// Check encoding error
if encoder.Error != nil {
	fmt.Printf("Encoding error: %v\n", encoder.Error)
	return
}
```

Output Data

```go
// Output string
encoder.ToString() // BOu!rD]j7BEbo7
// Output byte slice
encoder.ToBytes()  // []byte("BOu!rD]j7BEbo7")
```

### Decoding Data

Input Data

```go
// Input string
decoder := dongle.Decode.FromString("BOu!rD]j7BEbo7").ByBase85()

// Input byte slice
decoder := dongle.Decode.FromBytes([]byte("BOu!rD]j7BEbo7")).ByBase85()

// Input file stream
file, _ := os.Open("test.txt")
decoder := dongle.Decode.FromFile(file).ByBase85()

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