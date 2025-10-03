---
head:
  - - meta
    - name: description
      content: HMAC-MD2 Algorithm | A lightweight, semantic and developer-friendly golang encoding & crypto library
  - - meta
    - name: keywords
      content: HMAC-MD2
---

# Hmac-Md2

`Hmac-Md2` is a message authentication code algorithm based on `md2`. `dongle` supports standard and streaming `md2` message authentication code algorithms and provides multiple output formats.

> Note: The `WithKey` method must be called before `ByMd2`

## Input Data

```go
// Input string
hasher := dongle.Hash.FromString("hello world").WithKey([]byte("dongle")).ByMd2()
// Input byte slice
hasher := dongle.Hash.FromBytes([]byte("hello world")).WithKey([]byte("dongle")).ByMd2()
// Input file stream
file, _ := os.Open("test.txt")
hasher := dongle.Hash.FromFile(file).WithKey([]byte("dongle")).ByMd2()

// Check HMAC error
if hasher.Error != nil {
	fmt.Printf("HMAC error: %v\n", hasher.Error)
	return
}
```

## Output Data

```go
// Output hex-encoded string
hasher.ToHexString() // 88ed6ef9ab699d03a702f2a6fb1c0673
// Output hex-encoded byte slice
hasher.ToHexBytes()  // []byte("88ed6ef9ab699d03a702f2a6fb1c0673")

// Output base64-encoded string
hasher.ToBase64String() // iO1u+atpnQOnAvKm+xwGcw==
// Output base64-encoded byte slice
hasher.ToBase64Bytes()  // []byte("iO1u+atpnQOnAvKm+xwGcw==")

// Output raw string
hasher.ToRawString()
// Output raw byte slice
hasher.ToRawBytes()
```
