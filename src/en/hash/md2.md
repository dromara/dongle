---
title: MD2 Hash Algorithm
head:
  - - meta
    - name: description
      content: MD2 Hash Algorithm, generates 16-byte hash value, supports standard and streaming processing, string, byte and file input, and Hex and Base64 output formats
  - - meta
    - name: keywords
      content: dongle, go-dongle, hashing, hash, md2, streaming processing, string input, byte input, file input, Hex, Base64
---

# Hash-Md2

`Hash-Md2` is a hash algorithm that produces a `16-byte` hash value. `dongle` supports standard and streaming `md2` hash algorithms and provides multiple output formats.

## Input Data

```go
// Input string
hasher := dongle.Hash.FromString("hello world").ByMd2()

// Input byte slice
hasher := dongle.Hash.FromBytes([]byte("hello world")).ByMd2()

// Input file stream
file, _ := os.Open("test.txt")
hasher := dongle.Hash.FromFile(file).ByMd2()

// Check hash error
if hasher.Error != nil {
	fmt.Printf("Hash error: %v\n", hasher.Error)
	return
}
```

## Output Data

```go
// Output Hex encoded string
hasher.ToHexString() // d9cce882ee690a5c1ce70beff3a78c77
// Output Hex encoded byte slice
hasher.ToHexBytes()  // []byte("d9cce882ee690a5c1ce70beff3a78c77")

// Output Base64 encoded string
hasher.ToBase64String() // 2czogu5pClwc5wvv86eMdw==
// Output Base64 encoded byte slice
hasher.ToBase64Bytes()  // []byte("2czogu5pClwc5wvv86eMdw==")

// Output unencoded raw string
hasher.ToRawString()
// Output unencoded raw byte slice
hasher.ToRawBytes()
```
