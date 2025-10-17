---
title: Ripemd160 Message Authentication Code Algorithm
head:
  - - meta
    - name: description
      content: HMAC-RIPEMD160 Algorithm | A lightweight, semantic and developer-friendly golang encoding & crypto library
  - - meta
    - name: keywords
      content: message authentication code, hmac, ripemd160, hmac-ripemd160
---

# Hmac-Ripemd160

`Hmac-Ripemd160` is a message authentication code algorithm based on `ripemd160`. `dongle` supports standard and streaming `ripemd160` message authentication code algorithms and provides multiple output formats.

> Note: The `WithKey` method must be called before `ByRipemd160`

## Input Data

```go
// Input string
hasher := dongle.Hash.FromString("hello world").WithKey([]byte("dongle")).ByRipemd160()
// Input byte slice
hasher := dongle.Hash.FromBytes([]byte("hello world")).WithKey([]byte("dongle")).ByRipemd160()
// Input file stream
file, _ := os.Open("test.txt")
hasher := dongle.Hash.FromFile(file).WithKey([]byte("dongle")).ByRipemd160()

// Check HMAC error
if hasher.Error != nil {
	fmt.Printf("HMAC error: %v\n", hasher.Error)
	return
}
```

## Output Data

```go
// Output Hex encoded string
hasher.ToHexString() // 3691ad040e80c43dc6e8ffe9bc6ef3d5bd8786b8
// Output Hex encoded byte slice
hasher.ToHexBytes()  // []byte("3691ad040e80c43dc6e8ffe9bc6ef3d5bd8786b8")

// Output Base64 encoded string
hasher.ToBase64String() // NpGtBA6AxD3G6P/pvG7z1b2Hhrg=
// Output Base64 encoded byte slice
hasher.ToBase64Bytes()  // []byte("NpGtBA6AxD3G6P/pvG7z1b2Hhrg=")

// Output unencoded raw string
hasher.ToRawString()
// Output unencoded raw byte slice
hasher.ToRawBytes()
```
