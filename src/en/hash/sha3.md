---
title: SHA3 Hash Algorithm
head:
  - - meta
    - name: description
      content: SHA3 Hash Algorithm, providing sha3-224, sha3-256, sha3-384, and sha3-512 variants, supports standard and streaming processing, string, byte and file input, and Hex and Base64 output formats
  - - meta
    - name: keywords
      content: dongle, go-dongle, hashing, hash, sha3, sha3-224, sha3-256, sha3-384, sha3-512, streaming processing, string input, byte input, file input, Hex, Base64
---

# Hash-Sha3

`Hash-Sha3` is a series of hash algorithms that produce hash values of different lengths, including `sha3-224`, `sha3-256`, `sha3-384`, and `sha3-512`. `dongle` supports all four `hash-sha3` variants.

- [Sha3-224](#sha3-224): Generates `28-byte` hash value
- [Sha3-256](#sha3-256): Generates `32-byte` hash value
- [Sha3-384](#sha3-384): Generates `48-byte` hash value
- [Sha3-512](#sha3-512): Generates `64-byte` hash value

## Sha3-224

### Input Data

```go
// Input string
hasher := dongle.Hash.FromString("hello world").BySha3(224)
// Input byte slice
hasher := dongle.Hash.FromBytes([]byte("hello world")).BySha3(224)
// Input file stream
file, _ := os.Open("test.txt")
hasher := dongle.Hash.FromFile(file).BySha3(224)

// Check hash error
if hasher.Error != nil {
	fmt.Printf("Hash error: %v\n", hasher.Error)
	return
}
```

### Output Data

```go
// Output Hex encoded string
hasher.ToHexString() // dfb7f18c77e928bb56faeb2da27291bd790bc1045cde45f3210bb6c5
// Output Hex encoded byte slice
hasher.ToHexBytes()  // []byte("dfb7f18c77e928bb56faeb2da27291bd790bc1045cde45f3210bb6c5")

// Output Base64 encoded string
hasher.ToBase64String() // 37fxjHfpKLtW+ustonKRvXkLwQRc3kXzIQu2xQ==
// Output Base64 encoded byte slice
hasher.ToBase64Bytes()  // []byte("37fxjHfpKLtW+ustonKRvXkLwQRc3kXzIQu2xQ==")

// Output unencoded raw string
hasher.ToRawString()
// Output unencoded raw byte slice
hasher.ToRawBytes()
```

## Sha3-256

### Input Data

```go
// Input string
hasher := dongle.Hash.FromString("hello world").BySha3(256)
// Input byte slice
hasher := dongle.Hash.FromBytes([]byte("hello world")).BySha3(256)
// Input file stream
file, _ := os.Open("test.txt")
hasher := dongle.Hash.FromFile(file).BySha3(256)

// Check hash error
if hasher.Error != nil {
	fmt.Printf("Hash error: %v\n", hasher.Error)
	return
}
```

### Output Data

```go
// Output Hex encoded string
hasher.ToHexString() // 644bcc7e564373040999aac89e7622f3ca71fba1d972fd94a31c3bfbf24e3938
// Output Hex encoded byte slice
hasher.ToHexBytes()  // []byte("644bcc7e564373040999aac89e7622f3ca71fba1d972fd94a31c3bfbf24e3938")

// Output Base64 encoded string
hasher.ToBase64String() // ZEvMflZDcwQJmarInnYi88px+6HZcv2Uoxw7+/JOOTg=
// Output Base64 encoded byte slice
hasher.ToBase64Bytes()  // []byte("ZEvMflZDcwQJmarInnYi88px+6HZcv2Uoxw7+/JOOTg=")

// Output unencoded raw string
hasher.ToRawString()
// Output unencoded raw byte slice
hasher.ToRawBytes()
```

## Sha3-384

### Input Data

```go
// Input string
hasher := dongle.Hash.FromString("hello world").BySha3(384)
// Input byte slice
hasher := dongle.Hash.FromBytes([]byte("hello world")).BySha3(384)
// Input file stream
file, _ := os.Open("test.txt")
hasher := dongle.Hash.FromFile(file).BySha3(384)

// Check hash error
if hasher.Error != nil {
	fmt.Printf("Hash error: %v\n", hasher.Error)
	return
}
```

### Output Data

```go
// Output Hex encoded string
hasher.ToHexString() // 83bff28dde1b1bf5810071c6643c08e5b05bdb836effd70b403ea8ea0a634dc4997eb1053aa3593f590f9c63630dd90b
// Output Hex encoded byte slice
hasher.ToHexBytes()  // []byte("83bff28dde1b1bf5810071c6643c08e5b05bdb836effd70b403ea8ea0a634dc4997eb1053aa3593f590f9c63630dd90b")

// Output Base64 encoded string
hasher.ToBase64String() // g7/yjd4bG/WBAHHGZDwI5bBb24Nu/9cLQD6o6gpjTcSZfrEFOqNZP1kPnGNjDdkL
// Output Base64 encoded byte slice
hasher.ToBase64Bytes()  // []byte("g7/yjd4bG/WBAHHGZDwI5bBb24Nu/9cLQD6o6gpjTcSZfrEFOqNZP1kPnGNjDdkL")

// Output unencoded raw string
hasher.ToRawString()
// Output unencoded raw byte slice
hasher.ToRawBytes()
```

## Sha3-512

### Input Data

```go
// Input string
hasher := dongle.Hash.FromString("hello world").BySha3(512)
// Input byte slice
hasher := dongle.Hash.FromBytes([]byte("hello world")).BySha3(512)
// Input file stream
file, _ := os.Open("test.txt")
hasher := dongle.Hash.FromFile(file).BySha3(512)

// Check hash error
if hasher.Error != nil {
	fmt.Printf("Hash error: %v\n", hasher.Error)
	return
}
```

### Output Data

```go
// Output Hex encoded string
hasher.ToHexString() // 840006653e9ac9e95117a15c915caab81662918e925de9e004f774ff82d7079a40d4d27b1b372657c61d46d470304c88c788b3a4527ad074d1dccbee5dbaa99a
// Output Hex encoded byte slice
hasher.ToHexBytes()  // []byte("840006653e9ac9e95117a15c915caab81662918e925de9e004f774ff82d7079a40d4d27b1b372657c61d46d470304c88c788b3a4527ad074d1dccbee5dbaa99a")

// Output Base64 encoded string
hasher.ToBase64String() // hAAGZT6ayelRF6FckVyquBZikY6SXengBPd0/4LXB5pA1NJ7GzcmV8YdRtRwMEyIx4izpFJ60HTR3MvuXbqpmg==
// Output Base64 encoded byte slice
hasher.ToBase64Bytes()  // []byte("hAAGZT6ayelRF6FckVyquBZikY6SXengBPd0/4LXB5pA1NJ7GzcmV8YdRtRwMEyIx4izpFJ60HTR3MvuXbqpmg==")

// Output unencoded raw string
hasher.ToRawString()
// Output unencoded raw byte slice
hasher.ToRawBytes()
```