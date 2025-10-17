---
title: SHA1 Hash Algorithm
head:
  - - meta
    - name: description
      content: SHA1 Hash Algorithm | A lightweight, semantic and developer-friendly golang encoding & crypto library
  - - meta
    - name: keywords
      content: hashing, hash, sha1, hash-sha1
---

# Hash-Sha1

`Hash-Sha1` is a hash algorithm that produces a `20-byte` hash value. `dongle` supports standard and streaming `sha1` hash algorithms and provides multiple output formats.

## Input Data

```go
// Input string
hasher := dongle.Hash.FromString("hello world").BySha1()
// Input byte slice
hasher := dongle.Hash.FromBytes([]byte("hello world")).BySha1()
// Input file stream
file, _ := os.Open("test.txt")
hasher := dongle.Hash.FromFile(file).BySha1()

// Check hash error
if hasher.Error != nil {
	fmt.Printf("Hash error: %v\n", hasher.Error)
	return
}
```

## Output Data

```go
// Output Hex encoded string
hasher.ToHexString() // 2aae6c35c94fcfb415dbe95f408b9ce91ee846ed
// Output Hex encoded byte slice
hasher.ToHexBytes()  // []byte("2aae6c35c94fcfb415dbe95f408b9ce91ee846ed")

// Output Base64 encoded string
hasher.ToBase64String() // Kq5sNclPz7QV2+lfQIuc6R7oRu0=
// Output Base64 encoded byte slice
hasher.ToBase64Bytes()  // []byte("Kq5sNclPz7QV2+lfQIuc6R7oRu0=")

// Output unencoded raw string
hasher.ToRawString()
// Output unencoded raw byte slice
hasher.ToRawBytes()
```
