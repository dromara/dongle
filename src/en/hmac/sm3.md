---
title: SM3 Message Authentication Code Algorithm
head:
  - - meta
    - name: description
      content: HMAC-SM3 Algorithm|A lightweight, semantic, developer-friendly golang encoding & cryptography library
  - - meta
    - name: keywords
      content: message authentication code, hmac, sm3, hmac-sm3
---

# Hmac-Sm3

`Hmac-Sm3` is a message authentication code algorithm based on `sm3`. `dongle` supports standard and streaming `sm3` message authentication code algorithms and provides multiple output formats.

> Note: The `WithKey` method must be called before `BySm3`

## Input Data

```go
// Input string
hasher := dongle.Hash.FromString("hello world").WithKey([]byte("dongle")).BySm3()
// Input byte slice
hasher := dongle.Hash.FromBytes([]byte("hello world")).WithKey([]byte("dongle")).BySm3()
// Input file stream
file, _ := os.Open("test.txt")
hasher := dongle.Hash.FromFile(file).WithKey([]byte("dongle")).BySm3()

// Check HMAC error
if hasher.Error != nil {
	fmt.Printf("HMAC error: %v\n", hasher.Error)
	return
}
```

## Output Data

```go
// Output Hex encoded string
hasher.ToHexString() // 8c733aae1d553c466a08c3e9e5daac3e99ae220181c7c1bc8c2564961de751b3
// Output Hex encoded byte slice
hasher.ToHexBytes()  // []byte("8c733aae1d553c466a08c3e9e5daac3e99ae220181c7c1bc8c2564961de751b3")

// Output Base64 encoded string
hasher.ToBase64String() // jHM6rh1VPEZqCMPp5dqsPpmuIgGBx8G8jCVklh3nUbM=
// Output Base64 encoded byte slice
hasher.ToBase64Bytes()  // []byte("jHM6rh1VPEZqCMPp5dqsPpmuIgGBx8G8jCVklh3nUbM=")

// Output unencoded raw string
hasher.ToRawString()
// Output unencoded raw byte slice
hasher.ToRawBytes()
```
