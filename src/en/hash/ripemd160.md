---
head:
  - - meta
    - name: description
      content: Ripemd160 Hash Algorithm | A lightweight, semantic and developer-friendly golang encoding & crypto library
  - - meta
    - name: keywords
      content: hash, hash algorithm, ripemd160
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
// Output hex-encoded string
hasher.ToHexString() // 98c615784ccb5fe5936fbc0cbe9dfdb408d92f0f
// Output hex-encoded byte slice
hasher.ToHexBytes()  // []byte("98c615784ccb5fe5936fbc0cbe9dfdb408d92f0f")

// Output base64-encoded string
hasher.ToBase64String() // mMYVeEzLX+WTb7wMvp39tAjZLw8=
// Output base64-encoded byte slice
hasher.ToBase64Bytes()  // []byte("mMYVeEzLX+WTb7wMvp39tAjZLw8=")

// Output raw string
hasher.ToRawString()
// Output raw byte slice
hasher.ToRawBytes()
```
