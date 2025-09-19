---
title: Base64 Encoding/Decoding
head:
  - - meta
    - name: description
      content: Base64 Encoding/Decoding | A lightweight, semantic and developer-friendly golang encoding & crypto library
  - - meta
    - name: keywords
      content: dongle, base64, base64url
---

# Base64

Base64 is an encoding method that converts binary data to `ASCII` characters, using `64` characters (A-Z, a-z, 0-9, +, /) to represent data. `dongle` supports both standard `Base64` and `Base64Url` variants.

- [Base64Std](#base64std)
- [Base64Url](#base64url)

## Base64Std
> The default alphabet is `ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/`,
> You can customize the alphabet by setting `base64.StdAlphabet`

### Encoding Data

Input Data

```go
// Input string
encoder := dongle.Encode.FromString("hello world").ByBase64()

// Input byte slice
encoder := dongle.Encode.FromBytes([]byte("hello world")).ByBase64()

// Input file stream
file, _ := os.Open("test.txt")
encoder := dongle.Encode.FromFile(file).ByBase64()

// Check encoding error
if encoder.Error != nil {
	fmt.Printf("Encoding error: %v\n", encoder.Error)
	return
}
```

Output Data

```go
// Output string
encoder.ToString() // aGVsbG8gd29ybGQ=
// Output byte slice
encoder.ToBytes()  // []byte("aGVsbG8gd29ybGQ=")
```

### Decoding Data

Input Data

```go
// Input string
decoder := dongle.Decode.FromString("aGVsbG8gd29ybGQ=").ByBase64()

// Input byte slice
decoder := dongle.Decode.FromBytes([]byte("aGVsbG8gd29ybGQ=")).ByBase64()

// Input file stream
file, _ := os.Open("test.txt")
decoder := dongle.Decode.FromFile(file).ByBase64()

// Check decoding error
if decoder.Error != nil {
	fmt.Printf("Decoding error: %v\n", decoder.Error)
	return
}
```

Output Data

```go
// Output string
decoder.ToString() // hello world
// Output byte slice
decoder.ToBytes()  // []byte("hello world")
```

## Base64Url

> The default alphabet is `ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_`,
> You can customize the alphabet by setting `base64.URLAlphabet`

### Encoding Data

Input Data

```go
// Input string
encoder := dongle.Encode.FromString("https://dongle.go-pkg.com/api/v1/data+test").ByBase64Url()

// Input byte slice
encoder := dongle.Encode.FromBytes([]byte("https://dongle.go-pkg.com/api/v1/data+test")).ByBase64Url()

// Input file stream
file, _ := os.Open("test.txt")
encoder := dongle.Encode.FromFile(file).ByBase64Url()

// Check encoding error
if encoder.Error != nil {
	fmt.Printf("Encoding error: %v\n", encoder.Error)
	return
}
```

Output Data

```go
// Output string
encoder.ToString() // aHR0cHM6Ly9kb25nbGUuZ28tcGtnLmNvbS9hcGkvdjEvZGF0YSt0ZXN0
// Output byte slice
encoder.ToBytes()  // []byte("aHR0cHM6Ly9kb25nbGUuZ28tcGtnLmNvbS9hcGkvdjEvZGF0YSt0ZXN0")
```

### Decoding Data

Input Data

```go
// Input string
decoder := dongle.Decode.FromString("aHR0cHM6Ly9kb25nbGUuZ28tcGtnLmNvbS9hcGkvdjEvZGF0YSt0ZXN0").ByBase64Url()

// Input byte slice
decoder := dongle.Decode.FromBytes([]byte("aHR0cHM6Ly9kb25nbGUuZ28tcGtnLmNvbS9hcGkvdjEvZGF0YSt0ZXN0")).ByBase64Url()

// Input file stream
file, _ := os.Open("test.txt")
decoder := dongle.Decode.FromFile(file).ByBase64Url()

// Check decoding error
if decoder.Error != nil {
	fmt.Printf("Decoding error: %v\n", decoder.Error)
	return
}
```

Output Data

```go
// Output string
decoder.ToString() // https://dongle.go-pkg.com/api/v1/data+test
// Output byte slice
decoder.ToBytes()  // []byte("https://dongle.go-pkg.com/api/v1/data+test")
```
