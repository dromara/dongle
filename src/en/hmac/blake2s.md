---
head:
  - - meta
    - name: description
      content: HMAC-BLAKE2s Algorithm|A lightweight, semantic, developer-friendly golang encoding & cryptography library
  - - meta
    - name: keywords
      content: HMAC-BLAKE2s
---

# Hmac-Blake2s

`Hmac-Blake2s` is a message authentication code algorithm based on `blake2s`. `dongle` supports standard and streaming `blake2s` message authentication code algorithms and provides multiple output formats.

> Note: The `WithKey` method must be called before `ByBlake2s`

## Supported Hash Algorithms

- [Blake2s-128](#blake2s-128)：Generates 16-byte hash value
- [Blake2s-256](#blake2s-256)：Generates 32-byte hash value

## Blake2s-128

### Input Data

```go
// Input string
hasher := dongle.Hash.FromString("hello world").WithKey([]byte("dongle")).ByBlake2s(128)

// Input byte slice
hasher := dongle.Hash.FromBytes([]byte("hello world")).WithKey([]byte("dongle")).ByBlake2s(128)

// Input file stream
file, _ := os.Open("test.txt")
hasher := dongle.Hash.FromFile(file).WithKey([]byte("dongle")).ByBlake2s(128)

// Check HMAC error
if hasher.Error != nil {
	fmt.Printf("HMAC error: %v\n", hasher.Error)
	return
}
```

### Output Data

```go
// Output Hex encoded string
hasher.ToHexString() // 8e9dce350baec849c2bc163d0e73552a
// Output Hex encoded byte slice
hasher.ToHexBytes()  // []byte("8e9dce350baec849c2bc163d0e73552a")

// Output Base64 encoded string
hasher.ToBase64String() // jp3ONQuuyEnCvBY9DnNVKg==
// Output Base64 encoded byte slice
hasher.ToBase64Bytes()  // []byte("jp3ONQuuyEnCvBY9DnNVKg==")

// Output unencoded raw string
hasher.ToRawString()
// Output unencoded raw byte slice
hasher.ToRawBytes()
```

## Blake2s-256

### Input Data

```go
// Input string
hasher := dongle.Hash.FromString("hello world").WithKey([]byte("dongle")).ByBlake2s(256)

// Input byte slice
hasher := dongle.Hash.FromBytes([]byte("hello world")).WithKey([]byte("dongle")).ByBlake2s(256)

// Input file stream
file, _ := os.Open("test.txt")
hasher := dongle.Hash.FromFile(file).WithKey([]byte("dongle")).ByBlake2s(256)

// Check HMAC error
if hasher.Error != nil {
	fmt.Printf("HMAC error: %v\n", hasher.Error)
	return
}
```

### Output Data

```go
// Output Hex encoded string
hasher.ToHexString() // 14953619e2781ed4a20f571d32d494af37b92e9bede33fbe429dff376f233af3
// Output Hex encoded byte slice
hasher.ToHexBytes()  // []byte("14953619e2781ed4a20f571d32d494af37b92e9bede33fbe429dff376f233af3")

// Output Base64 encoded string
hasher.ToBase64String() // FJU2GeJ4HtSiD1cdMtSUrze5Lpvt4z++Qp3/N28jOvM=
// Output Base64 encoded byte slice
hasher.ToBase64Bytes()  // []byte("FJU2GeJ4HtSiD1cdMtSUrze5Lpvt4z++Qp3/N28jOvM=")

// Output unencoded raw string
hasher.ToRawString()
// Output unencoded raw byte slice
hasher.ToRawBytes()
```