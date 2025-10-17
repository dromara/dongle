---
title: SHA1 Message Authentication Code Algorithm
head:
  - - meta
    - name: description
      content: HMAC-SHA1 Algorithm | A lightweight, semantic and developer-friendly golang encoding & crypto library
  - - meta
    - name: keywords
      content: message authentication code, hmac, sha1, hmac-sha1
---

# Hmac-Sha1

`Hmac-Sha1` is a message authentication code algorithm based on `sha1`. `dongle` supports standard and streaming `sha1` message authentication code algorithms and provides multiple output formats.

> Note: The `WithKey` method must be called before `BySha1`

## Input Data

```go
// Input string
hasher := dongle.Hash.FromString("hello world").WithKey([]byte("dongle")).BySha1()
// Input byte slice
hasher := dongle.Hash.FromBytes([]byte("hello world")).WithKey([]byte("dongle")).BySha1()
// Input file stream
file, _ := os.Open("test.txt")
hasher := dongle.Hash.FromFile(file).WithKey([]byte("dongle")).BySha1()

// Check HMAC error
if hasher.Error != nil {
	fmt.Printf("HMAC error: %v\n", hasher.Error)
	return
}
```

## Output Data

```go
// Output Hex encoded string
hasher.ToHexString() // 91c103ef93ba7420902b0d1bf0903251c94b4a62
// Output Hex encoded byte slice
hasher.ToHexBytes()  // []byte("91c103ef93ba7420902b0d1bf0903251c94b4a62")

// Output Base64 encoded string
hasher.ToBase64String() // kcED75O6dCCQKw0b8JAyUclLSmI=
// Output Base64 encoded byte slice
hasher.ToBase64Bytes()  // []byte("kcED75O6dCCQKw0b8JAyUclLSmI=")

// Output unencoded raw string
hasher.ToRawString()
// Output unencoded raw byte slice
hasher.ToRawBytes()
```
