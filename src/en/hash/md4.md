---
head:
  - - meta
    - name: description
      content: MD4 Hash Algorithm | A lightweight, semantic and developer-friendly golang encoding & crypto library
  - - meta
    - name: keywords
      content: hash, hash algorithm, md4
---

# Hash-Md4

`Hash-Md4` is a hash algorithm that produces a `16-byte` hash value. `dongle` supports the standard `md4` hash algorithm and provides multiple output formats.

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
// Output hex-encoded string
hasher.ToHexString() // aa010fbc1d14c795d86ef98c95479d17
// Output hex-encoded byte slice
hasher.ToHexBytes()  // []byte("aa010fbc1d14c795d86ef98c95479d17")

// Output base64-encoded string
hasher.ToBase64String() // qgEPvB0Ux5XYbvmMlUedFw==
// Output base64-encoded byte slice
hasher.ToBase64Bytes()  // []byte("qgEPvB0Ux5XYbvmMlUedFw==")

// Output raw string
hasher.ToRawString()
// Output raw byte slice
hasher.ToRawBytes()
```