---
title: MD5 Message Authentication Code Algorithm
head:
  - - meta
    - name: description
      content: HMAC-MD5 Algorithm | A lightweight, semantic and developer-friendly golang encoding & crypto library
  - - meta
    - name: keywords
      content: message authentication code, hmac, md5, hmac-md5
---

# Hmac-Md5

`Hmac-Md5` is a message authentication code algorithm based on `md5`. `dongle` supports standard and streaming `md5` message authentication code algorithms and provides multiple output formats.

> Note: The `WithKey` method must be called before `ByMd5`

## Input Data

```go
// Input string
hasher := dongle.Hash.FromString("hello world").WithKey([]byte("dongle")).ByMd5()
// Input byte slice
hasher := dongle.Hash.FromBytes([]byte("hello world")).WithKey([]byte("dongle")).ByMd5()
// Input file stream
file, _ := os.Open("test.txt")
hasher := dongle.Hash.FromFile(file).WithKey([]byte("dongle")).ByMd5()

// Check HMAC error
if hasher.Error != nil {
	fmt.Printf("HMAC error: %v\n", hasher.Error)
	return
}
```

## Output Data

```go
// Output Hex encoded string
hasher.ToHexString() // 4790626a275f776956386e5a3ea7b726
// Output Hex encoded byte slice
hasher.ToHexBytes()  // []byte("4790626a275f776956386e5a3ea7b726")

// Output Base64 encoded string
hasher.ToBase64String() // R5Biaidfd2lWOG5aPqe3Jg==
// Output Base64 encoded byte slice
hasher.ToBase64Bytes()  // []byte("R5Biaidfd2lWOG5aPqe3Jg==")

// Output unencoded raw string
hasher.ToRawString()
// Output unencoded raw byte slice
hasher.ToRawBytes()
```
