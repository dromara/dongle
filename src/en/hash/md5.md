---
head:
  - - meta
    - name: description
      content: MD5 Hash Algorithm | A lightweight, semantic and developer-friendly golang encoding & crypto library
  - - meta
    - name: keywords
      content: hash, hash algorithm, md5
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
// Output hex-encoded string
hasher.ToHexString() // 5eb63bbbe01eeed093cb22bb8f5acdc3
// Output hex-encoded byte slice
hasher.ToHexBytes()  // []byte("5eb63bbbe01eeed093cb22bb8f5acdc3")

// Output base64-encoded string
hasher.ToBase64String() // XrY7u+Ae7tCTyyK7j1rNww==
// Output base64-encoded byte slice
hasher.ToBase64Bytes()  // []byte("XrY7u+Ae7tCTyyK7j1rNww==")

// Output raw string
hasher.ToRawString()
// Output raw byte slice
hasher.ToRawBytes()
``` 