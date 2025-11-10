---
title: Base62 Encoding/Decoding
head:
  - - meta
    - name: description
      content: Base62 encoding/decoding, uses 62 characters (0-9, A-Z, a-z), supports custom alphabet, supports standard and streaming processing, supports string, byte and file input, provides string and byte output
  - - meta
    - name: keywords
      content: dongle, go-dongle, encoding, decoding, Base62, alphabet, custom character set, streaming processing, string input, byte input, file input, string output, byte output
---

# Base62

Base62 is an encoding method that converts binary data to `ASCII` characters, using `62` characters (0-9, A-Z, a-z) to represent data. `dongle` supports standard and streaming `Base62` encoding.

> The default alphabet is `0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz`,
> You can customize the alphabet by setting `base62.StdAlphabet`

### Encoding Data
Input Data

```go
// Input string
encoder := dongle.Encode.FromString("hello world").ByBase62()
// Input byte slice
encoder := dongle.Encode.FromBytes([]byte("hello world")).ByBase62()
// Input file stream
file, _ := os.Open("test.txt")
encoder := dongle.Encode.FromFile(file).ByBase62()

// Check encoding error
if encoder.Error != nil {
	fmt.Printf("Encoding error: %v\n", encoder.Error)
	return
}
```

Output Data

```go
// Output string
encoder.ToString() // AAwf93rvy4aWQVw
// Output byte slice
encoder.ToBytes()  // []byte("AAwf93rvy4aWQVw")
```

### Decoding Data
Input Data

```go
// Input string
decoder := dongle.Decode.FromString("AAwf93rvy4aWQVw").ByBase62()
// Input byte slice
decoder := dongle.Decode.FromBytes([]byte("AAwf93rvy4aWQVw")).ByBase62()
// Input file stream
file, _ := os.Open("test.txt")
decoder := dongle.Decode.FromFile(file).ByBase62()

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
 