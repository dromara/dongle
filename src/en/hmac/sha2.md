---
title: SHA2 Message Authentication Code Algorithm
head:
  - - meta
    - name: description
      content: HMAC-SHA2 Algorithm | A lightweight, semantic and developer-friendly golang encoding & crypto library
  - - meta
    - name: keywords
      content: message authentication code, hmac, sha2, sha224, sha256, sha384, sha512, hmac-sha2, hmac-sha224, hmac-sha256, hmac-sha384, hmac-sha512
---

# Hmac-Sha2

`Hmac-Sha2` is a series of message authentication code algorithms based on `sha2`, including `sha2-224`, `sha2-256`, `sha2-384`, and `sha2-512`. `dongle` supports all four `sha2` message authentication code algorithm variants.

- [Sha2-224](#sha2-224): Generates `28-byte` hash value
- [Sha2-256](#sha2-256): Generates `32-byte` hash value
- [Sha2-384](#sha2-384): Generates `48-byte` hash value
- [Sha2-512](#sha2-512): Generates `64-byte` hash value

> Note: The `WithKey` method must be called before `BySha2`

## Sha2-224

### Input Data

```go
// Input string
hasher := dongle.Hash.FromString("hello world").WithKey([]byte("dongle")).BySha2(224)
// Input byte slice
hasher := dongle.Hash.FromBytes([]byte("hello world")).WithKey([]byte("dongle")).BySha2(224)
// Input file stream
file, _ := os.Open("test.txt")
hasher := dongle.Hash.FromFile(file).WithKey([]byte("dongle")).BySha2(224)

// Check HMAC error
if hasher.Error != nil {
	fmt.Printf("HMAC error: %v\n", hasher.Error)
	return
}
```

### Output Data

```go
// Output Hex encoded string
hasher.ToHexString() // e15b9e5a7eccb1f17dc81dc07c909a891936dc3429dc0d940accbcec
// Output Hex encoded byte slice
hasher.ToHexBytes()  // []byte("e15b9e5a7eccb1f17dc81dc07c909a891936dc3429dc0d940accbcec")

// Output Base64 encoded string
hasher.ToBase64String() // 4VueWn7MsfF9yB3AfJCaiRk23DQp3A2UCsy87A==
// Output Base64 encoded byte slice
hasher.ToBase64Bytes()  // []byte("4VueWn7MsfF9yB3AfJCaiRk23DQp3A2UCsy87A==")

// Output unencoded raw string
hasher.ToRawString()
// Output unencoded raw byte slice
hasher.ToRawBytes()
```

## Sha2-256

### Input Data

```go
// Input string
hasher := dongle.Hash.FromString("hello world").WithKey([]byte("dongle")).BySha2(256)
// Input byte slice
hasher := dongle.Hash.FromBytes([]byte("hello world")).WithKey([]byte("dongle")).BySha2(256)
// Input file stream
file, _ := os.Open("test.txt")
hasher := dongle.Hash.FromFile(file).WithKey([]byte("dongle")).BySha2(256)

// Check HMAC error
if hasher.Error != nil {
	fmt.Printf("HMAC error: %v\n", hasher.Error)
	return
}
```

### Output Data

```go
// Output Hex encoded string
hasher.ToHexString() // 77f5c8ce4147600543e70b12701e7b78b5b95172332ebbb06de65fcea7112179
// Output Hex encoded byte slice
hasher.ToHexBytes()  // []byte("77f5c8ce4147600543e70b12701e7b78b5b95172332ebbb06de65fcea7112179")

// Output Base64 encoded string
hasher.ToBase64String() // d/XIzkFHYAVD5wsScB57eLW5UXIzLruwbeZfzqcRIXk=
// Output Base64 encoded byte slice
hasher.ToBase64Bytes()  // []byte("d/XIzkFHYAVD5wsScB57eLW5UXIzLruwbeZfzqcRIXk=")

// Output unencoded raw string
hasher.ToRawString()
// Output unencoded raw byte slice
hasher.ToRawBytes()
```

## Sha2-384

### Input Data

```go
// Input string
hasher := dongle.Hash.FromString("hello world").WithKey([]byte("dongle")).BySha2(384)
// Input byte slice
hasher := dongle.Hash.FromBytes([]byte("hello world")).WithKey([]byte("dongle")).BySha2(384)
// Input file stream
file, _ := os.Open("test.txt")
hasher := dongle.Hash.FromFile(file).WithKey([]byte("dongle")).BySha2(384)

// Check HMAC error
if hasher.Error != nil {
	fmt.Printf("HMAC error: %v\n", hasher.Error)
	return
}
```

### Output Data

```go
// Output Hex encoded string
hasher.ToHexString() // 421fcaa740216a31bbcd1f86f2212e0c68aa4b156a8ebc2ae55b3e75c4ee0509ea0325a0570ae739006b61d91d817fe8
// Output Hex encoded byte slice
hasher.ToHexBytes()  // []byte("421fcaa740216a31bbcd1f86f2212e0c68aa4b156a8ebc2ae55b3e75c4ee0509ea0325a0570ae739006b61d91d817fe8")

// Output Base64 encoded string
hasher.ToBase64String() // Qh/Kp0AhajG7zR+G8iEuDGiqSxVqjrwq5Vs+dcTuBQnqAyWgVwrnOQBrYdkdgX/o
// Output Base64 encoded byte slice
hasher.ToBase64Bytes()  // []byte("Qh/Kp0AhajG7zR+G8iEuDGiqSxVqjrwq5Vs+dcTuBQnqAyWgVwrnOQBrYdkdgX/o")

// Output unencoded raw string
hasher.ToRawString()
// Output unencoded raw byte slice
hasher.ToRawBytes()
```

## Sha2-512

### Input Data

```go
// Input string
hasher := dongle.Hash.FromString("hello world").WithKey([]byte("dongle")).BySha2(512)
// Input byte slice
hasher := dongle.Hash.FromBytes([]byte("hello world")).WithKey([]byte("dongle")).BySha2(512)
// Input file stream
file, _ := os.Open("test.txt")
hasher := dongle.Hash.FromFile(file).WithKey([]byte("dongle")).BySha2(512)

// Check HMAC error
if hasher.Error != nil {
	fmt.Printf("HMAC error: %v\n", hasher.Error)
	return
}
```

### Output Data

```go
// Output Hex encoded string
hasher.ToHexString() // d971b790bbc2a4ac81062bbffac693c9c234bae176c8faf5e304dbdb153032a826f12353964b4a4fb87abecd2dc237638a630cbad54a6b94b1f6ef5d5e2835d1
// Output Hex encoded byte slice
hasher.ToHexBytes()  // []byte("d971b790bbc2a4ac81062bbffac693c9c234bae176c8faf5e304dbdb153032a826f12353964b4a4fb87abecd2dc237638a630cbad54a6b94b1f6ef5d5e2835d1")

// Output Base64 encoded string
hasher.ToBase64String() // 2XG3kLvCpKyBBiu/+saTycI0uuF2yPr14wTb2xUwMqgm8SNTlktKT7h6vs0twjdjimMMutVKa5Sx9u9dXig10Q==
// Output Base64 encoded byte slice
hasher.ToBase64Bytes()  // []byte("2XG3kLvCpKyBBiu/+saTycI0uuF2yPr14wTb2xUwMqgm8SNTlktKT7h6vs0twjdjimMMutVKa5Sx9u9dXig10Q==")

// Output unencoded raw string
hasher.ToRawString()
// Output unencoded raw byte slice
hasher.ToRawBytes()
```



