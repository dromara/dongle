---
title: MD4 Message Authentication Code Algorithm
head:
  - - meta
    - name: description
      content: HMAC-MD4 message authentication code algorithm, based on MD4 hash algorithm, using key for message authentication, generates 16-byte authentication code, supports standard and streaming processing, string, byte and file input, and Hex and Base64 output formats
  - - meta
    - name: keywords
      content: dongle, go-dongle, HMAC, message authentication code, MD4, key, streaming processing, string input, byte input, file input, Hex, Base64
---

# Hmac-Md4

`Hmac-Md4` is a message authentication code algorithm based on `md4`. `dongle` supports standard and streaming `md4` message authentication code algorithms and provides multiple output formats.

> Note: The `WithKey` method must be called before `ByMd4`

## Input Data

```go
// Input string
hasher := dongle.Hash.FromString("hello world").WithKey([]byte("dongle")).ByMd4()
// Input byte slice
hasher := dongle.Hash.FromBytes([]byte("hello world")).WithKey([]byte("dongle")).ByMd4()
// Input file stream
file, _ := os.Open("test.txt")
hasher := dongle.Hash.FromFile(file).WithKey([]byte("dongle")).ByMd4()

// Check HMAC error
if hasher.Error != nil {
	fmt.Printf("HMAC error: %v\n", hasher.Error)
	return
}
```

## Output Data

```go
// Output Hex encoded string
hasher.ToHexString() // 7a9df5247cbf76a8bc17c9c4f5a75b6b
// Output Hex encoded byte slice
hasher.ToHexBytes()  // []byte("7a9df5247cbf76a8bc17c9c4f5a75b6b")

// Output Base64 encoded string
hasher.ToBase64String() // ep31JHy/dqi8F8nE9adbaw==
// Output Base64 encoded byte slice
hasher.ToBase64Bytes()  // []byte("ep31JHy/dqi8F8nE9adbaw==")

// Output unencoded raw string
hasher.ToRawString()
// Output unencoded raw byte slice
hasher.ToRawBytes()
```
