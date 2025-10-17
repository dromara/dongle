---
title: MD4 Hash Algorithm
head:
  - - meta
    - name: description
      content: MD4 Hash Algorithm | A lightweight, semantic and developer-friendly golang encoding & crypto library
  - - meta
    - name: keywords
      content: hashing, hash, md4, hash-md4
---

# Hash-Md4

`Hash-Md4` is a hash algorithm that produces a `16-byte` hash value. `dongle` supports standard and streaming `md4` hash algorithms and provides multiple output formats.

## Input Data

```go
// Input string
hasher := dongle.Hash.FromString("hello world").ByMd4()
// Input byte slice
hasher := dongle.Hash.FromBytes([]byte("hello world")).ByMd4()
// Input file stream
file, _ := os.Open("test.txt")
hasher := dongle.Hash.FromFile(file).ByMd4()

// Check hash error
if hasher.Error != nil {
	fmt.Printf("Hash error: %v\n", hasher.Error)
	return
}
```

## Output Data

```go
// Output Hex encoded string
hasher.ToHexString() // aa010fbc1d14c795d86ef98c95479d17
// Output Hex encoded byte slice
hasher.ToHexBytes()  // []byte("aa010fbc1d14c795d86ef98c95479d17")

// Output Base64 encoded string
hasher.ToBase64String() // qgEPvB0Ux5XYbvmMlUedFw==
// Output Base64 encoded byte slice
hasher.ToBase64Bytes()  // []byte("qgEPvB0Ux5XYbvmMlUedFw==")

// Output unencoded raw string
hasher.ToRawString()
// Output unencoded raw byte slice
hasher.ToRawBytes()
```