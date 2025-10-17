---
title: Ripemd160 Hash Algorithm
head:
  - - meta
    - name: description
      content: Ripemd160 Hash Algorithm | A lightweight, semantic and developer-friendly golang encoding & crypto library
  - - meta
    - name: keywords
      content: hashing, hash, ripemd160, hash-ripemd160
---

# Hash-Ripemd160

`Hash-Ripemd160` is a hash algorithm that produces a `20-byte` hash value. `dongle` supports standard and streaming `ripemd160` hash algorithms and provides multiple output formats.

## Input Data

```go
// Input string
hasher := dongle.Hash.FromString("hello world").ByRipemd160()
// Input byte slice
hasher := dongle.Hash.FromBytes([]byte("hello world")).ByRipemd160()
// Input file stream
file, _ := os.Open("test.txt")
hasher := dongle.Hash.FromFile(file).ByRipemd160()

// Check hash error
if hasher.Error != nil {
	fmt.Printf("Hash error: %v\n", hasher.Error)
	return
}
```

## Output Data

```go
// Output Hex encoded string
hasher.ToHexString() // 98c615784ccb5fe5936fbc0cbe9dfdb408d92f0f
// Output Hex encoded byte slice
hasher.ToHexBytes()  // []byte("98c615784ccb5fe5936fbc0cbe9dfdb408d92f0f")

// Output Base64 encoded string
hasher.ToBase64String() // mMYVeEzLX+WTb7wMvp39tAjZLw8=
// Output Base64 encoded byte slice
hasher.ToBase64Bytes()  // []byte("mMYVeEzLX+WTb7wMvp39tAjZLw8=")

// Output unencoded raw string
hasher.ToRawString()
// Output unencoded raw byte slice
hasher.ToRawBytes()
```
