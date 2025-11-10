---
title: MD5 Hash Algorithm
head:
  - - meta
    - name: description
      content: MD5 Hash Algorithm, generates 16-byte hash value, supports standard and streaming processing, string, byte and file input, and Hex and Base64 output formats
  - - meta
    - name: keywords
      content: dongle, go-dongle, hashing, hash, md5, streaming processing, string input, byte input, file input, Hex, Base64
---

# Hash-Md5

`Hash-Md5` is a hash algorithm that produces a `16-byte` hash value. `dongle` supports standard and streaming `md5` hash algorithms and provides multiple output formats.

## Input Data

```go
// Input string
hasher := dongle.Hash.FromString("hello world").ByMd5()
// Input byte slice
hasher := dongle.Hash.FromBytes([]byte("hello world")).ByMd5()
// Input file stream
file, _ := os.Open("test.txt")
hasher := dongle.Hash.FromFile(file).ByMd5()

// Check hash error
if hasher.Error != nil {
	fmt.Printf("Hash error: %v\n", hasher.Error)
	return
}
```

## Output Data

```go
// Output Hex encoded string
hasher.ToHexString() // 5eb63bbbe01eeed093cb22bb8f5acdc3
// Output Hex encoded byte slice
hasher.ToHexBytes()  // []byte("5eb63bbbe01eeed093cb22bb8f5acdc3")

// Output Base64 encoded string
hasher.ToBase64String() // XrY7u+Ae7tCTyyK7j1rNww==
// Output Base64 encoded byte slice
hasher.ToBase64Bytes()  // []byte("XrY7u+Ae7tCTyyK7j1rNww==")

// Output unencoded raw string
hasher.ToRawString()
// Output unencoded raw byte slice
hasher.ToRawBytes()
``` 