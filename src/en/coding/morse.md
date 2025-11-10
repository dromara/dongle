---
title: Morse Encoding/Decoding
head:
  - - meta
    - name: description
      content: Morse encoding/decoding, compliant with International Morse Code standard (ITU-R M.1677-1), supports custom dictionary and separator, supports standard and streaming processing, supports string, byte and file input, provides string and byte output
  - - meta
    - name: keywords
      content: dongle, go-dongle, encoding, decoding, Morse, Morse code, ITU-R M.1677-1, dictionary, separator, streaming processing, string input, byte input, file input, string output, byte output
---

# Morse

Morse is an encoding method that converts text to sequences of dots and dashes, following the International Morse Code standard (ITU-R M.1677-1). `dongle` supports standard and streaming `Morse` encoding, converting letters, numbers, and punctuation marks to standardized sequences of dots and dashes.
> The default separator is `space`,
> You can customize the separator by setting `morse.StdSeparator`

### Encoding Data
Input Data
```go
// Input string
encoder := dongle.Encode.FromString("hello world").ByMorse()
// Input byte slice
encoder := dongle.Encode.FromBytes([]byte("hello world")).ByMorse()
// Input file stream
file, _ := os.Open("test.txt")
encoder := dongle.Encode.FromFile(file).ByMorse()

// Check encoding error
if encoder.Error != nil {
	fmt.Printf("Encoding error: %v\n", encoder.Error)
	return
}
```

Output Data

```go
// Output string
encoder.ToString() // .... . .-.. .-.. --- / .-- --- .-. .-.. -..
// Output byte slice
encoder.ToBytes()  // []byte(".... . .-.. .-.. --- / .-- --- .-. .-.. -..")
```

### Decoding Data
Input Data

```go
// Input string
decoder := dongle.Decode.FromString(".... . .-.. .-.. --- / .-- --- .-. .-.. -..").ByMorse()
// Input byte slice
decoder := dongle.Decode.FromBytes([]byte(".... . .-.. .-.. --- / .-- --- .-. .-.. -..")).ByMorse()
// Input file stream
file, _ := os.Open("test.txt")
decoder := dongle.Decode.FromFile(file).ByMorse()

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
