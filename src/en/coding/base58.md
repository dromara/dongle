---
title: Base58 Encoding/Decoding
head:
  - - meta
    - name: description
      content: Base58 encoding/decoding, follows Bitcoin-style character set, excludes confusing characters (0, O, I, l), supports custom alphabet, supports standard and streaming processing, supports string, byte and file input, provides string and byte output
  - - meta
    - name: keywords
      content: dongle, go-dongle, encoding, decoding, Base58, Bitcoin-style, alphabet, custom character set, streaming processing, string input, byte input, file input, string output, byte output
---

# Base58

Base58 is an encoding method that converts binary data to `ASCII` characters, using `58` characters (1-9, A-Z, a-z, excluding easily confused characters 0, O, I, l) to represent data. `dongle` supports standard and streaming `Base58` encoding, following Bitcoin-style specifications.

> The default alphabet is `123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz`,
> You can customize the alphabet by setting `base58.StdAlphabet`

### Encoding Data
Input Data

```go
// Input string
encoder := dongle.Encode.FromString("hello world").ByBase58()
// Input byte slice
encoder := dongle.Encode.FromBytes([]byte("hello world")).ByBase58()
// Input file stream
file, _ := os.Open("test.txt")
encoder := dongle.Encode.FromFile(file).ByBase58()

// Check encoding error
if encoder.Error != nil {
	fmt.Printf("Encoding error: %v\n", encoder.Error)
	return
}
```

Output Data

```go
// Output string
encoder.ToString() // StV1DL6CwTryKyV
// Output byte slice
encoder.ToBytes()  // []byte("StV1DL6CwTryKyV")
```

### Decoding Data
Input Data

```go
// Input string
decoder := dongle.Decode.FromString("StV1DL6CwTryKyV").ByBase58()
// Input byte slice
decoder := dongle.Decode.FromBytes([]byte("StV1DL6CwTryKyV")).ByBase58()
// Input file stream
file, _ := os.Open("test.txt")
decoder := dongle.Decode.FromFile(file).ByBase58()

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
 