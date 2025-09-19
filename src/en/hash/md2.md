---
head:
  - - meta
    - name: description
      content: MD2 Hash Algorithm | A lightweight, semantic and developer-friendly golang encoding & crypto library
  - - meta
    - name: keywords
      content: hash, hash algorithm, md2
---

# Hash-Md2

`Hash-Md2` is a hash algorithm that produces a `16-byte` hash value. `dongle` supports the standard `md2` hash algorithm and provides multiple output formats.

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
// Output hex-encoded string
hasher.ToHexString() // d9cce882ee690a5c1ce70beff3a78c77
// Output hex-encoded byte slice
hasher.ToHexBytes()  // []byte("d9cce882ee690a5c1ce70beff3a78c77")

// Output base64-encoded string
hasher.ToBase64String() // 2czogu5pClwc5wvv86eMdw==
// Output base64-encoded byte slice
hasher.ToBase64Bytes()  // []byte("2czogu5pClwc5wvv86eMdw==")

// Output raw string
hasher.ToRawString()
// Output raw byte slice
hasher.ToRawBytes()
```
