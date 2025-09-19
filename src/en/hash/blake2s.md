---
head:
  - - meta
    - name: description
      content: BLAKE2s Hash Algorithm|A lightweight, semantic, developer-friendly golang encoding & cryptography library
  - - meta
    - name: keywords
      content: hash, blake2s, blake2s-128, blake2s-256
---

# Hash-Blake2s

`Hash-Blake2s` is a series of hash algorithms that produce hash values of different lengths, including `blake2s-128` and `blake2s-256`. `dongle` supports both `hash-blake2s` variants.

- [Blake2s-128](#blake2s-128)：Generates 16-byte hash value
- [Blake2s-256](#blake2s-256)：Generates 32-byte hash value

## Blake2s-128

### Input Data

```go
// Input string (requires key)
hasher := dongle.Hash.FromString("hello world").WithKey([]byte("secret")).ByBlake2s(128)
// Input byte slice (requires key)
hasher := dongle.Hash.FromBytes([]byte("hello world")).WithKey([]byte("secret")).ByBlake2s(128)
// Input file stream (requires key)
file, _ := os.Open("test.txt")
hasher := dongle.Hash.FromFile(file).WithKey([]byte("secret")).ByBlake2s(128)

// Check hash error
if hasher.Error != nil {
	fmt.Printf("Hash error: %v\n", hasher.Error)
	return
}
```

### Output Data

```go
// Output Hex encoded string
hasher.ToHexString() // 8f9dff49538583cb967e763c54d51280
// Output Hex encoded byte slice
hasher.ToHexBytes()  // []byte("8f9dff49538583cb967e763c54d51280")

// Output Base64 encoded string
hasher.ToBase64String() // j53/SVOFg8uWfnY8VNUSgA==
// Output Base64 encoded byte slice
hasher.ToBase64Bytes()  // []byte("j53/SVOFg8uWfnY8VNUSgA==")

// Output unencoded raw string
hasher.ToRawString()
// Output unencoded raw byte slice
hasher.ToRawBytes()
```

## Blake2s-256

### Input Data

```go
// Input string
hasher := dongle.Hash.FromString("hello world").ByBlake2s(256)
// Input byte slice
hasher := dongle.Hash.FromBytes([]byte("hello world")).ByBlake2s(256)
// Input file stream
file, _ := os.Open("test.txt")
hasher := dongle.Hash.FromFile(file).ByBlake2s(256)

// Check hash error
if hasher.Error != nil {
	fmt.Printf("Hash error: %v\n", hasher.Error)
	return
}
```

### Output Data

```go
// Output Hex encoded string
hasher.ToHexString() // 9aec6806794561107e594b1f6a8a6b0c92a0cba9acf5e5e93cca06f781813b0b
// Output Hex encoded byte slice
hasher.ToHexBytes()  // []byte("9aec6806794561107e594b1f6a8a6b0c92a0cba9acf5e5e93cca06f781813b0b")

// Output Base64 encoded string
hasher.ToBase64String() // muxoBnlFYRB+WUsfaoprDJKgy6ms9eXpPMoG94GBOws=
// Output Base64 encoded byte slice
hasher.ToBase64Bytes()  // []byte("muxoBnlFYRB+WUsfaoprDJKgy6ms9eXpPMoG94GBOws=")

// Output unencoded raw string
hasher.ToRawString()
// Output unencoded raw byte slice
hasher.ToRawBytes()
```