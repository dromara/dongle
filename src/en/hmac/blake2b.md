---
head:
  - - meta
    - name: description
      content: HMAC-BLAKE2b Algorithm|A lightweight, semantic, developer-friendly golang encoding & cryptography library
  - - meta
    - name: keywords
      content: HMAC-BLAKE2b
---

# Hmac-Blake2b

`Hmac-Blake2b` is a message authentication code algorithm based on `blake2b`. `dongle` supports standard and streaming `blake2b` message authentication code algorithms and provides multiple output formats.

> Note: The `WithKey` method must be called before `ByBlake2b`

## Supported Hash Algorithms

- [Blake2b-256](#blake2b-256)：Generates 32-byte hash value
- [Blake2b-384](#blake2b-384)：Generates 48-byte hash value
- [Blake2b-512](#blake2b-512)：Generates 64-byte hash value

## Blake2b-256

### Input Data

```go
// Input string
hasher := dongle.Hash.FromString("hello world").WithKey([]byte("dongle")).ByBlake2b(256)

// Input byte slice
hasher := dongle.Hash.FromBytes([]byte("hello world")).WithKey([]byte("dongle")).ByBlake2b(256)

// Input file stream
file, _ := os.Open("test.txt")
hasher := dongle.Hash.FromFile(file).WithKey([]byte("dongle")).ByBlake2b(256)

// Check HMAC error
if hasher.Error != nil {
	fmt.Printf("HMAC error: %v\n", hasher.Error)
	return
}
```

### Output Data

```go
// Output Hex encoded string
hasher.ToHexString() // 11de19238a5d5414bc8f9effb2a5f004a4210804668d25d252d0733c26670a0d
// Output Hex encoded byte slice
hasher.ToHexBytes()  // []byte("11de19238a5d5414bc8f9effb2a5f004a4210804668d25d252d0733c26670a0d")

// Output Base64 encoded string
hasher.ToBase64String() // Ed4ZI4pdVBS8j57/sqXwBKQhCARmjSXSUtBzPCZnCg0=
// Output Base64 encoded byte slice
hasher.ToBase64Bytes()  // []byte("Ed4ZI4pdVBS8j57/sqXwBKQhCARmjSXSUtBzPCZnCg0=")

// Output unencoded raw string
hasher.ToRawString()
// Output unencoded raw byte slice
hasher.ToRawBytes()
```

## Blake2b-384

### Input Data

```go
// Input string
hasher := dongle.Hash.FromString("hello world").WithKey([]byte("dongle")).ByBlake2b(384)

// Input byte slice
hasher := dongle.Hash.FromBytes([]byte("hello world")).WithKey([]byte("dongle")).ByBlake2b(384)

// Input file stream
file, _ := os.Open("test.txt")
hasher := dongle.Hash.FromFile(file).WithKey([]byte("dongle")).ByBlake2b(384)

// Check HMAC error
if hasher.Error != nil {
	fmt.Printf("HMAC error: %v\n", hasher.Error)
	return
}
```

### Output Data

```go
// Output Hex encoded string
hasher.ToHexString() // 506c397b0b5d437342a07748d09612f9905ab21e6674d8409516a53cf341a1bc9052bf47edf85ffe506437acd1f91bc
// Output Hex encoded byte slice
hasher.ToHexBytes()  // []byte("506c397b0b5d437342a07748d09612f9905ab21e6674d8409516a53cf341a1bc9052bf47edf85ffe506437acd1f91bc")

// Output Base64 encoded string
hasher.ToBase64String() // UGw5ewtdQ3NCoHdI0JYS+ZBash5mdNhAlRalPPNBobyQUr9H7fhf/lBkOnrNH5G8
// Output Base64 encoded byte slice
hasher.ToBase64Bytes()  // []byte("UGw5ewtdQ3NCoHdI0JYS+ZBash5mdNhAlRalPPNBobyQUr9H7fhf/lBkOnrNH5G8")

// Output unencoded raw string
hasher.ToRawString()
// Output unencoded raw byte slice
hasher.ToRawBytes()
```

## Blake2b-512

### Input Data

```go
// Input string
hasher := dongle.Hash.FromString("hello world").WithKey([]byte("dongle")).ByBlake2b(512)

// Input byte slice
hasher := dongle.Hash.FromBytes([]byte("hello world")).WithKey([]byte("dongle")).ByBlake2b(512)

// Input file stream
file, _ := os.Open("test.txt")
hasher := dongle.Hash.FromFile(file).WithKey([]byte("dongle")).ByBlake2b(512)

// Check HMAC error
if hasher.Error != nil {
	fmt.Printf("HMAC error: %v\n", hasher.Error)
	return
}
```

### Output Data

```go
// Output Hex encoded string
hasher.ToHexString() // 9ab7280ca18d0fca29034329eddecb36ecdcefe00758bbe966e30cfbf9774e3e21c2ee5be01fdc23c983d8849fcf2f0dcfd3a0e6ba92442cbd64a2342763d2ae
// Output Hex encoded byte slice
hasher.ToHexBytes()  // []byte("9ab7280ca18d0fca29034329eddecb36ecdcefe00758bbe966e30cfbf9774e3e21c2ee5be01fdc23c983d8849fcf2f0dcfd3a0e6ba92442cbd64a2342763d2ae")

// Output Base64 encoded string
hasher.ToBase64String() // mrcoDKGND8opA0Mp7d7LNuzc7+AHWLvpZuMM+/l3Tj4hwu5b4B/cI8mD2ISfzy8Nz9Og5rqSRCy9ZKI0J2PSrg==
// Output Base64 encoded byte slice
hasher.ToBase64Bytes()  // []byte("mrcoDKGND8opA0Mp7d7LNuzc7+AHWLvpZuMM+/l3Tj4hwu5b4B/cI8mD2ISfzy8Nz9Og5rqSRCy9ZKI0J2PSrg==")

// Output unencoded raw string
hasher.ToRawString()
// Output unencoded raw byte slice
hasher.ToRawBytes()
```