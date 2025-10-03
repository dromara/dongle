---
title: Base45 Encoding/Decoding
head:
  - - meta
    - name: description
      content: Base45 Encoding/Decoding | A lightweight, semantic and developer-friendly golang encoding & crypto library
  - - meta
    - name: keywords
      content: dongle, base45
---

# Base45

Base45 is an encoding method that converts binary data to `ASCII` characters, using `45` characters （0-9, A-Z, space, $, %, *, +, -, ., /, :）to represent data. `dongle` supports standard and streaming `Base45` encoding, compliant with `RFC9285` specifications.

> The default alphabet is `0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:`,
> You can customize the alphabet by setting `base45.StdAlphabet`

### Encoding Data

Input Data

```go
// Input string
encoder := dongle.Encode.FromString("hello world").ByBase45()

// Input byte slice
encoder := dongle.Encode.FromBytes([]byte("hello world")).ByBase45()

// Input file stream
file, _ := os.Open("test.txt")
encoder := dongle.Encode.FromFile(file).ByBase45()

// Check encoding error
if encoder.Error != nil {
	fmt.Printf("Encoding error: %v\n", encoder.Error)
	return
}
```

Output Data

```go
// Output string
encoder.ToString() // +8D VD82EK4F.KEA2
// Output byte slice
encoder.ToBytes()  // []byte("+8D VD82EK4F.KEA2")
```

### Decoding Data

Input Data

```go
// Input string
decoder := dongle.Decode.FromString("+8D VD82EK4F.KEA2").ByBase45()

// Input byte slice
decoder := dongle.Decode.FromBytes([]byte("+8D VD82EK4F.KEA2")).ByBase45()

// Input file stream
file, _ := os.Open("test.txt")
decoder := dongle.Decode.FromFile(file).ByBase45()

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
