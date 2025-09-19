---
title: Base32 Encoding/Decoding
head:
  - - meta
    - name: description
      content: Base32 Encoding/Decoding | A lightweight, semantic and developer-friendly golang encoding & crypto library
  - - meta
    - name: keywords
      content: dongle, base32, base32hex
---

# Base32

Base32 is an encoding method that converts binary data to `ASCII` characters, using `32` characters (A-Z, 2-7) to represent data. `dongle` supports both standard `Base32` and `Base32Hex` variants.

- [Base32Std](#base32std)
- [Base32Hex](#base32hex)

## Base32Std
> The default alphabet is `ABCDEFGHIJKLMNOPQRSTUVWXYZ234567`,
> You can customize the alphabet by setting `base32.StdAlphabet`

### Encoding Data

Input Data

```go
// Input string
encoder := dongle.Encode.FromString("hello world").ByBase32()

// Input byte slice
encoder := dongle.Encode.FromBytes([]byte("hello world")).ByBase32()

// Input file stream
file, _ := os.Open("test.txt")
encoder := dongle.Encode.FromFile(file).ByBase32()

// Check encoding error
if encoder.Error != nil {
	fmt.Printf("Encoding error: %v\n", encoder.Error)
	return
}
```

Output Data

```go
// Output string
encoder.ToString() // NBSWY3DPEB3W64TMMQ======
// Output byte slice
encoder.ToBytes()  // []byte("NBSWY3DPEB3W64TMMQ======")
```

### Decoding Data

Input Data

```go
// Input string
decoder := dongle.Decode.FromString("NBSWY3DPEB3W64TMMQ======").ByBase32()

// Input byte slice
decoder := dongle.Decode.FromBytes([]byte("NBSWY3DPEB3W64TMMQ======")).ByBase32()

// Input file stream
file, _ := os.Open("test.txt")
decoder := dongle.Decode.FromFile(file).ByBase32()

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

## Base32Hex

> The default alphabet is `0123456789ABCDEFGHIJKLMNOPQRSTUV`,
> You can customize the alphabet by setting `base32.HexAlphabet`

### Encoding Data

Input Data

```go
// Input string
encoder := dongle.Encode.FromString("hello world").ByBase32Hex()

// Input byte slice
encoder := dongle.Encode.FromBytes([]byte("hello world")).ByBase32Hex()

// Input file stream
file, _ := os.Open("test.txt")
encoder := dongle.Encode.FromFile(file).ByBase32Hex()

// Check encoding error
if encoder.Error != nil {
	fmt.Printf("Encoding error: %v\n", encoder.Error)
	return
}
```

Output Data

```go
// Output string
encoder.ToString() // D1IMOR3F41RMUSJCCG======
// Output byte slice
encoder.ToBytes()  // []byte("D1IMOR3F41RMUSJCCG======")
```

### Decoding Data

Input Data

```go
// Input string
decoder := dongle.Decode.FromString("D1IMOR3F41RMUSJCCG======").ByBase32Hex()

// Input byte slice
decoder := dongle.Decode.FromBytes([]byte("D1IMOR3F41RMUSJCCG======")).ByBase32Hex()

// Input file stream
file, _ := os.Open("test.txt")
decoder := dongle.Decode.FromFile(file).ByBase32Hex()

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