---
title: Blake2b Hash Algorithm
head:
  - - meta
    - name: description
      content: BLAKE2b Hash Algorithm|A lightweight, semantic, developer-friendly golang encoding & cryptography library
  - - meta
    - name: keywords
      content: hashing, hash, blake2b, blake2b-256, blake2b-384, blake2b-512, hash-blake2b, hash-blake2b-256, hash-blake2b-384, hash-blake2b-512
---

# Hash-Blake2b

`Hash-Blake2b` is a series of hash algorithms that produce hash values of different lengths, including `blake2b-256`, `blake2b-384`, and `blake2b-512`. `dongle` supports all three `hash-blake2b` variants.

 - [Blake2b-256](#blake2b-256): Generates 32-byte hash value
 - [Blake2b-384](#blake2b-384): Generates 48-byte hash value
 - [Blake2b-512](#blake2b-512): Generates 64-byte hash value

## Blake2b-256

### Input Data

```go
// Input string
hasher := dongle.Hash.FromString("hello world").ByBlake2b(256)
// Input byte slice
hasher := dongle.Hash.FromBytes([]byte("hello world")).ByBlake2b(256)
// Input file stream
file, _ := os.Open("test.txt")
hasher := dongle.Hash.FromFile(file).ByBlake2b(256)

// Check hash error
if hasher.Error != nil {
	fmt.Printf("Hash error: %v\n", hasher.Error)
	return
}
```

### Output Data

```go
// Output Hex encoded string
hasher.ToHexString() // 256c83b297114d201b30179f3f0ef0cace9783622da5974326b436178aeef610
// Output Hex encoded byte slice
hasher.ToHexBytes()  // []byte("256c83b297114d201b30179f3f0ef0cace9783622da5974326b436178aeef610")

// Output Base64 encoded string
hasher.ToBase64String() // JWyDspcRTSAbMBefPw7wys6Xg2ItpZdDJrQ2F4ru9hA=
// Output Base64 encoded byte slice
hasher.ToBase64Bytes()  // []byte("JWyDspcRTSAbMBefPw7wys6Xg2ItpZdDJrQ2F4ru9hA=")

// Output unencoded raw string
hasher.ToRawString()
// Output unencoded raw byte slice
hasher.ToRawBytes()
```

## Blake2b-384

### Input Data

```go
// Input string
hasher := dongle.Hash.FromString("hello world").ByBlake2b(384)
// Input byte slice
hasher := dongle.Hash.FromBytes([]byte("hello world")).ByBlake2b(384)
// Input file stream
file, _ := os.Open("test.txt")
hasher := dongle.Hash.FromFile(file).ByBlake2b(384)

// Check hash error
if hasher.Error != nil {
	fmt.Printf("Hash error: %v\n", hasher.Error)
	return
}
```

### Output Data

```go
// Output Hex encoded string
hasher.ToHexString() // 8c653f8c9c9aa2177fb6f8cf5bb914828faa032d7b486c8150663d3f6524b086784f8e62693171ac51fc80b7d2cbb12b
// Output Hex encoded byte slice
hasher.ToHexBytes()  // []byte("8c653f8c9c9aa2177fb6f8cf5bb914828faa032d7b486c8150663d3f6524b086784f8e62693171ac51fc80b7d2cbb12b")

// Output Base64 encoded string
hasher.ToBase64String() // jGU/jJyaohd/tvjPW7kUgo+qAy17SGyBUGY9P2UksIZ4T45iaTFxrFH8gLfSy7Er
// Output Base64 encoded byte slice
hasher.ToBase64Bytes()  // []byte("jGU/jJyaohd/tvjPW7kUgo+qAy17SGyBUGY9P2UksIZ4T45iaTFxrFH8gLfSy7Er")

// Output unencoded raw string
hasher.ToRawString()
// Output unencoded raw byte slice
hasher.ToRawBytes()
```

## Blake2b-512

### Input Data

```go
// Input string
hasher := dongle.Hash.FromString("hello world").ByBlake2b(512)
// Input byte slice
hasher := dongle.Hash.FromBytes([]byte("hello world")).ByBlake2b(512)
// Input file stream
file, _ := os.Open("test.txt")
hasher := dongle.Hash.FromFile(file).ByBlake2b(512)

// Check hash error
if hasher.Error != nil {
	fmt.Printf("Hash error: %v\n", hasher.Error)
	return
}
```

### Output Data

```go
// Output Hex encoded string
hasher.ToHexString() // 021ced8799296ceca557832ab941a50b4a11f83478cf141f51f933f653ab9fbcc05a037cddbed06e309bf334942c4e58cdf1a46e237911ccd7fcf9787cbc7fd0
// Output Hex encoded byte slice
hasher.ToHexBytes()  // []byte("021ced8799296ceca557832ab941a50b4a11f83478cf141f51f933f653ab9fbcc05a037cddbed06e309bf334942c4e58cdf1a46e237911ccd7fcf9787cbc7fd0")

// Output Base64 encoded string
hasher.ToBase64String() // Ahzth5kpbOylV4MquUGlC0oR+DR4zxQfUfkz9lOrn7zAWgN83b7QbjCb8zSULE5YzfGkbiN5EczX/Pl4fLx/0A==
// Output Base64 encoded byte slice
hasher.ToBase64Bytes()  // []byte("Ahzth5kpbOylV4MquUGlC0oR+DR4zxQfUfkz9lOrn7zAWgN83b7QbjCb8zSULE5YzfGkbiN5EczX/Pl4fLx/0A==")

// Output unencoded raw string
hasher.ToRawString()
// Output unencoded raw byte slice
hasher.ToRawBytes()
```