---
title: Base91 Encoding/Decoding
head:
  - - meta
    - name: description
      content: Base91 Encoding/Decoding | A lightweight, semantic and developer-friendly golang encoding & crypto library
  - - meta
    - name: keywords
      content: encoding, decoding, base91, base91-encoding, base91-decoding
---

# Base91

Base91 is an encoding method that converts binary data to `ASCII` characters, using `91` characters (A-Z, a-z, 0-9, and special characters, excluding spaces, apostrophes, hyphens, and backslashes) to represent data. `dongle` supports standard and streaming `Base91` encoding.

> The default character set is `ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!#$%&()*+,./:;<=>?@[]^_{|}~"`,
> which can be customized by setting `base91.StdAlphabet`

### Encoding Data
Input Data

```go
// Input string
encoder := dongle.Encode.FromString("hello world").ByBase91()
// Input byte slice
encoder := dongle.Encode.FromBytes([]byte("hello world")).ByBase91()
// Input file stream
file, _ := os.Open("test.txt")
encoder := dongle.Encode.FromFile(file).ByBase91()

// Check encoding error
if encoder.Error != nil {
	fmt.Printf("Encoding error: %v\n", encoder.Error)
	return
}
```

Output Data

```go
// Output string
encoder.ToString() // TPwJh>Io2Tv!lE
// Output byte slice
encoder.ToBytes()  // []byte("TPwJh>Io2Tv!lE")
```

### Decoding Data
Input Data

```go
// Input string
decoder := dongle.Decode.FromString("TPwJh>Io2Tv!lE").ByBase91()
// Input byte slice
decoder := dongle.Decode.FromBytes([]byte("TPwJh>Io2Tv!lE")).ByBase91()
// Input file stream
file, _ := os.Open("test.txt")
decoder := dongle.Decode.FromFile(file).ByBase91()

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
 