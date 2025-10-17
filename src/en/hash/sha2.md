---
title: SHA2 Hash Algorithm
head:
  - - meta
    - name: description
      content: SHA2 Hash Algorithm | A lightweight, semantic and developer-friendly golang encoding & crypto library
  - - meta
    - name: keywords
      content: hashing, hash, sha2, sha224, sha256, sha384, sha512, hash-sha2, hash-sha224, hash-sha256, hash-sha384, hash-sha512
---

# Hash-Sha2

`Hash-Sha2` is a series of hash algorithms that produce hash values of different lengths, including `sha2-224`, `sha2-256`, `sha2-384`, and `sha2-512`. `dongle` supports all four `hash-sha2` variants.

- [Sha2-224](#sha2-224): Generates `28-byte` hash value
- [Sha2-256](#sha2-256): Generates `32-byte` hash value
- [Sha2-384](#sha2-384): Generates `48-byte` hash value
- [Sha2-512](#sha2-512): Generates `64-byte` hash value

## Sha2-224

### Input Data

```go
// Input string
hasher := dongle.Hash.FromString("hello world").BySha2(224)
// Input byte slice
hasher := dongle.Hash.FromBytes([]byte("hello world")).BySha2(224)
// Input file stream
file, _ := os.Open("test.txt")
hasher := dongle.Hash.FromFile(file).BySha2(224)

// Check hash error
if hasher.Error != nil {
	fmt.Printf("Hash error: %v\n", hasher.Error)
	return
}
```

### Output Data

```go
// Output Hex encoded string
hasher.ToHexString() // 2f05477fc24bb4faefd86517156dafdecec45b8ad3cf2522a563582b
// Output Hex encoded byte slice
hasher.ToHexBytes()  // []byte("2f05477fc24bb4faefd86517156dafdecec45b8ad3cf2522a563582b")

// Output Base64 encoded string
hasher.ToBase64String() // LwVHf8JLtPrv2GUXFW2v3s7EW4rTzyUipWNYKw==
// Output Base64 encoded byte slice
hasher.ToBase64Bytes()  // []byte("LwVHf8JLtPrv2GUXFW2v3s7EW4rTzyUipWNYKw==")

// Output unencoded raw string
hasher.ToRawString()
// Output unencoded raw byte slice
hasher.ToRawBytes()
```

## Sha2-256

### Input Data

```go
// Input string
hasher := dongle.Hash.FromString("hello world").BySha2(256)
// Input byte slice
hasher := dongle.Hash.FromBytes([]byte("hello world")).BySha2(256)
// Input file stream
file, _ := os.Open("test.txt")
hasher := dongle.Hash.FromFile(file).BySha2(256)

// Check hash error
if hasher.Error != nil {
	fmt.Printf("Hash error: %v\n", hasher.Error)
	return
}
```

### Output Data

```go
// Output Hex encoded string
hasher.ToHexString() // b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9
// Output Hex encoded byte slice
hasher.ToHexBytes()  // []byte("b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9")

// Output Base64 encoded string
hasher.ToBase64String() // uU0nuZNNPgilLlLX2n2r+sSE7+N6U4DukIj3rOLvzek=
// Output Base64 encoded byte slice
hasher.ToBase64Bytes()  // []byte("uU0nuZNNPgilLlLX2n2r+sSE7+N6U4DukIj3rOLvzek=")

// Output unencoded raw string
hasher.ToRawString()
// Output unencoded raw byte slice
hasher.ToRawBytes()
```

## Sha2-384

### Input Data

```go
// Input string
hasher := dongle.Hash.FromString("hello world").BySha2(384)
// Input byte slice
hasher := dongle.Hash.FromBytes([]byte("hello world")).BySha2(384)
// Input file stream
file, _ := os.Open("test.txt")
hasher := dongle.Hash.FromFile(file).BySha2(384)

// Check hash error
if hasher.Error != nil {
	fmt.Printf("Hash error: %v\n", hasher.Error)
	return
}
```

### Output Data

```go
// Output Hex encoded string
hasher.ToHexString() // fdbd8e75a67f29f701a4e040385e2e23986303ea10239211af907fcbb83578b3e417cb71ce646efd0819dd8c088de1bd
// Output Hex encoded byte slice
hasher.ToHexBytes()  // []byte("fdbd8e75a67f29f701a4e040385e2e23986303ea10239211af907fcbb83578b3e417cb71ce646efd0819dd8c088de1bd")

// Output Base64 encoded string
hasher.ToBase64String() // /b2OdaZ/KfcBpOBAOF4uI5hjA+oQI5IRr5B/y7g1eLPkF8txzmRu/QgZ3YwIjeG9
// Output Base64 encoded byte slice
hasher.ToBase64Bytes()  // []byte("/b2OdaZ/KfcBpOBAOF4uI5hjA+oQI5IRr5B/y7g1eLPkF8txzmRu/QgZ3YwIjeG9")

// Output unencoded raw string
hasher.ToRawString()
// Output unencoded raw byte slice
hasher.ToRawBytes()
```

## Sha2-512

### Input Data

```go
// Input string
hasher := dongle.Hash.FromString("hello world").BySha2(512)
// Input byte slice
hasher := dongle.Hash.FromBytes([]byte("hello world")).BySha2(512)
// Input file stream
file, _ := os.Open("test.txt")
hasher := dongle.Hash.FromFile(file).BySha2(512)

// Check hash error
if hasher.Error != nil {
	fmt.Printf("Hash error: %v\n", hasher.Error)
	return
}
```

### Output Data

```go
// Output Hex encoded string
hasher.ToHexString() // 309ecc489c12d6eb4cc40f50c902f2b4d0ed77ee511a7c7a9bcd3ca86d4cd86f989dd35bc5ff499670da34255b45b0cfd830e81f605dcf7dc5542e93ae9cd76f
// Output Hex encoded byte slice
hasher.ToHexBytes()  // []byte("309ecc489c12d6eb4cc40f50c902f2b4d0ed77ee511a7c7a9bcd3ca86d4cd86f989dd35bc5ff499670da34255b45b0cfd830e81f605dcf7dc5542e93ae9cd76f")

// Output Base64 encoded string
hasher.ToBase64String() // MJ7MSJwS1utMxA9QyQLytNDtd+5RGnx6m808qG1M2G+YndNbxf9JlnDaNCVbRbDP2DDoH2Bdz33FVC6TrpzXbw==
// Output Base64 encoded byte slice
hasher.ToBase64Bytes()  // []byte("MJ7MSJwS1utMxA9QyQLytNDtd+5RGnx6m808qG1M2G+YndNbxf9JlnDaNCVbRbDP2DDoH2Bdz33FVC6TrpzXbw==")

// Output unencoded raw string
hasher.ToRawString()
// Output unencoded raw byte slice
hasher.ToRawBytes()
```





