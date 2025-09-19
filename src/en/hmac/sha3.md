---
head:
  - - meta
    - name: description
      content: HMAC-SHA3 Algorithm | A lightweight, semantic and developer-friendly golang encoding & crypto library
  - - meta
    - name: keywords
      content: hmac-sha3, hmac-sha224, hmac-sha256, hmac-sha384, hmac-sha512
---

# Hmac-Sha3

`Hmac-Sha3` is a series of message authentication code algorithms based on `sha3`, including `sha3-224`, `sha3-256`, `sha3-384`, and `sha3-512`. `dongle` supports all four `sha3` message authentication code algorithm variants.

> Note: The `WithKey` method must be called before `BySha3`

- [Sha3-224](#sha3-224)：Generates `28-byte` hash value
- [Sha3-256](#sha3-256)：Generates `32-byte` hash value
- [Sha3-384](#sha3-384)：Generates `48-byte` hash value
- [Sha3-512](#sha3-512)：Generates `64-byte` hash value

## Sha3-224

### Input Data

```go
// Input string
hasher := dongle.Hash.FromString("hello world").WithKey([]byte("dongle")).BySha3(224)

// Input byte slice
hasher := dongle.Hash.FromBytes([]byte("hello world")).WithKey([]byte("dongle")).BySha3(224)

// Input file stream
file, _ := os.Open("test.txt")
hasher := dongle.Hash.FromFile(file).WithKey([]byte("dongle")).BySha3(224)

// Check HMAC error
if hasher.Error != nil {
	fmt.Printf("HMAC error: %v\n", hasher.Error)
	return
}
```

### Output Data

```go
// Output hex-encoded string
hasher.ToHexString() // fb8f061d9d1dddd2f5d3b9064a5e98e3e4b6df27ea93ce67627583ce
// Output hex-encoded byte slice
hasher.ToHexBytes()  // []byte("fb8f061d9d1dddd2f5d3b9064a5e98e3e4b6df27ea93ce67627583ce")

// Output base64-encoded string
hasher.ToBase64String() // +48GHZ0d3dL107kGSl6Y4+S23yfqk85nYnWDzg==
// Output base64-encoded byte slice
hasher.ToBase64Bytes()  // []byte("+48GHZ0d3dL107kGSl6Y4+S23yfqk85nYnWDzg==")

// Output raw string
hasher.ToRawString()
// Output raw byte slice
hasher.ToRawBytes()
```

## Sha3-256

### Input Data

```go
// Input string
hasher := dongle.Hash.FromString("hello world").WithKey([]byte("dongle")).BySha3(256)

// Input byte slice
hasher := dongle.Hash.FromBytes([]byte("hello world")).WithKey([]byte("dongle")).BySha3(256)

// Input file stream
file, _ := os.Open("test.txt")
hasher := dongle.Hash.FromFile(file).WithKey([]byte("dongle")).BySha3(256)

// Check HMAC error
if hasher.Error != nil {
	fmt.Printf("HMAC error: %v\n", hasher.Error)
	return
}
```

### Output Data

```go
// Output hex-encoded string
hasher.ToHexString() // 8193367fde28cf5c460adb449a04b3dd9c184f488bdccbabf0526c54f90c4460
// Output hex-encoded byte slice
hasher.ToHexBytes()  // []byte("8193367fde28cf5c460adb449a04b3dd9c184f488bdccbabf0526c54f90c4460")

// Output base64-encoded string
hasher.ToBase64String() // gZM2f94oz1xGCttEmgSz3ZwYT0iL3Mur8FJsVPkMRGA=
// Output base64-encoded byte slice
hasher.ToBase64Bytes()  // []byte("gZM2f94oz1xGCttEmgSz3ZwYT0iL3Mur8FJsVPkMRGA=")

// Output raw string
hasher.ToRawString()
// Output raw byte slice
hasher.ToRawBytes()
```

## Sha3-384

### Input Data

```go
// Input string
hasher := dongle.Hash.FromString("hello world").WithKey([]byte("dongle")).BySha3(384)

// Input byte slice
hasher := dongle.Hash.FromBytes([]byte("hello world")).WithKey([]byte("dongle")).BySha3(384)

// Input file stream
file, _ := os.Open("test.txt")
hasher := dongle.Hash.FromFile(file).WithKey([]byte("dongle")).BySha3(384)

// Check HMAC error
if hasher.Error != nil {
	fmt.Printf("HMAC error: %v\n", hasher.Error)
	return
}
```

### Output Data

```go
// Output hex-encoded string
hasher.ToHexString() // 3f76f5cda69cada3ee6b33f8458cd498b063075db263dd8b33f2a3992a8804f9569a7c86ffa2b8f0748babeb7a6fc0e7
// Output hex-encoded byte slice
hasher.ToHexBytes()  // []byte("3f76f5cda69cada3ee6b33f8458cd498b063075db263dd8b33f2a3992a8804f9569a7c86ffa2b8f0748babeb7a6fc0e7")

// Output base64-encoded string
hasher.ToBase64String() // P3b1zaacraPuazP4RYzUmLBjB12yY92LM/KjmSqIBPlWmnyG/6K48HSLq+t6b8Dn
// Output base64-encoded byte slice
hasher.ToBase64Bytes()  // []byte("P3b1zaacraPuazP4RYzUmLBjB12yY92LM/KjmSqIBPlWmnyG/6K48HSLq+t6b8Dn")

// Output raw string
hasher.ToRawString()
// Output raw byte slice
hasher.ToRawBytes()
```

## Sha3-512

### Input Data

```go
// Input string
hasher := dongle.Hash.FromString("hello world").WithKey([]byte("dongle")).BySha3(512)

// Input byte slice
hasher := dongle.Hash.FromBytes([]byte("hello world")).WithKey([]byte("dongle")).BySha3(512)

// Input file stream
file, _ := os.Open("test.txt")
hasher := dongle.Hash.FromFile(file).WithKey([]byte("dongle")).BySha3(512)

// Check HMAC error
if hasher.Error != nil {
	fmt.Printf("HMAC error: %v\n", hasher.Error)
	return
}
```

### Output Data

```go
// Output hex-encoded string
hasher.ToHexString() // a99653d0407d659eccdeed43bb7cccd2e2b05a2c34fd3467c4198cf2ad26a466738513e88839fb55e64eb49df65bc52ed0fec2775bd9e086edd4fb4024add4a2
// Output hex-encoded byte slice
hasher.ToHexBytes()  // []byte("a99653d0407d659eccdeed43bb7cccd2e2b05a2c34fd3467c4198cf2ad26a466738513e88839fb55e64eb49df65bc52ed0fec2775bd9e086edd4fb4024add4a2")

// Output base64-encoded string
hasher.ToBase64String() // qZZT0EB9ZZ7M3u1Du3zM0uKwWiw0/TRnxBmM8q0mpGZzhRPoiDn7VeZOtJ32W8Uu0P7Cd1vZ4Ibt1PtAJK3Uog==
// Output base64-encoded byte slice
hasher.ToBase64Bytes()  // []byte("qZZT0EB9ZZ7M3u1Du3zM0uKwWiw0/TRnxBmM8q0mpGZzhRPoiDn7VeZOtJ32W8Uu0P7Cd1vZ4Ibt1PtAJK3Uog==")

// Output raw string
hasher.ToRawString()
// Output raw byte slice
hasher.ToRawBytes()
```
