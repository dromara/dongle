---
head:
  - - meta
    - name: description
      content: SM3 Hash Algorithm|A lightweight, semantic, developer-friendly golang encoding & cryptography library
  - - meta
    - name: keywords
      content: hash, sm3, cryptography
---

# Hash-Sm3

`Hash-SM3` is a national cryptographic hash algorithm that produces `32`-byte hash values. It is a cryptographic hash algorithm published by the National Cryptography Administration of China, compliant with the `GB/T 32918.1-2016` standard. `dongle` supports standard and streaming `SM3` hash algorithms and provides multiple output formats.

## Input Data

```go
// Input string
hasher := dongle.Hash.FromString("hello world").BySm3()
// Input byte slice
hasher := dongle.Hash.FromBytes([]byte("hello world")).BySm3()
// Input file stream
file, _ := os.Open("test.txt")
hasher := dongle.Hash.FromFile(file).BySm3()

// Check hash error
if hasher.Error != nil {
	fmt.Printf("Hash error: %v\n", hasher.Error)
	return
}
```

## Output Data

```go
// Output hex-encoded string
hasher.ToHexString() // 44f0061e69fa6fdfc290c494654a05dc0c053da7e5c52b84ef93a9d67d3fff88
// Output hex-encoded byte slice
hasher.ToHexBytes()  // []byte("44f0061e69fa6fdfc290c494654a05dc0c053da7e5c52b84ef93a9d67d3fff88")

// Output base64-encoded string
hasher.ToBase64String() // RPAWHmn6b9/CkMSGVUoF3AwFPafly7hO+Trp1tP/+Ig=
// Output base64-encoded byte slice
hasher.ToBase64Bytes()  // []byte("RPAWHmn6b9/CkMSGVUoF3AwFPafly7hO+Trp1tP/+Ig=")

// Output raw string
hasher.ToRawString()
// Output raw byte slice
hasher.ToRawBytes()
```
