---
head:
  - - meta
    - name: description
      content: SHA3 哈希算法|一个轻量级、语义化、对开发者友好的 golang 编码&密码库
  - - meta
    - name: keywords
      content: 哈希, hash, sha3, sha224, sha256, sha384, sha512
---

# Hash-Sha3

`Hash-Sha3` 是一系列产生不同长度哈希值的哈希算法，包括 `sha3-224`、`sha3-256`、`sha3-384` 和 `sha3-512`，`dongle` 支持所有四种 `hash-sha3` 变体。

- [Sha3-224](#sha3-224)：生成 28 字节哈希值
- [Sha3-256](#sha3-256)：生成 32 字节哈希值
- [Sha3-384](#sha3-384)：生成 48 字节哈希值
- [Sha3-512](#sha3-512)：生成 64 字节哈希值

## Sha3-224

### 输入数据

```go
// 输入字符串
hasher := dongle.Hash.FromString("hello world").BySha3(224)
// 输入字节切片
hasher := dongle.Hash.FromBytes([]byte("hello world")).BySha3(224)
// 输入文件流
file, _ := os.Open("test.txt")
hasher := dongle.Hash.FromFile(file).BySha3(224)

// 检查哈希错误
if hasher.Error != nil {
	fmt.Printf("哈希错误: %v\n", hasher.Error)
	return
}
```

### 输出数据

```go
// 输出 Hex 编码字符串
hasher.ToHexString() // dfb7f18c77e928bb56faeb2da27291bd790bc1045cde45f3210bb6c5
// 输出 Hex 编码字节切片
hasher.ToHexBytes()  // []byte("dfb7f18c77e928bb56faeb2da27291bd790bc1045cde45f3210bb6c5")

// 输出 Base64 编码字符串
hasher.ToBase64String() // 37fxjHfpKLtW+ustonKRvXkLwQRc3kXzIQu2xQ==
// 输出 Base64 编码字节切片
hasher.ToBase64Bytes()  // []byte("37fxjHfpKLtW+ustonKRvXkLwQRc3kXzIQu2xQ==")

// 输出未编码原始字符串
hasher.ToRawString()
// 输出未编码原始字节切片
hasher.ToRawBytes()
```

## Sha3-256

### 输入数据

```go
// 输入字符串
hasher := dongle.Hash.FromString("hello world").BySha3(256)
// 输入字节切片
hasher := dongle.Hash.FromBytes([]byte("hello world")).BySha3(256)
// 输入文件流
file, _ := os.Open("test.txt")
hasher := dongle.Hash.FromFile(file).BySha3(256)

// 检查哈希错误
if hasher.Error != nil {
	fmt.Printf("哈希错误: %v\n", hasher.Error)
	return
}
```

### 输出数据

```go
// 输出 Hex 编码字符串
hasher.ToHexString() // 644bcc7e564373040999aac89e7622f3ca71fba1d972fd94a31c3bfbf24e3938
// 输出 Hex 编码字节切片
hasher.ToHexBytes()  // []byte("644bcc7e564373040999aac89e7622f3ca71fba1d972fd94a31c3bfbf24e3938")

// 输出 Base64 编码字符串
hasher.ToBase64String() // ZEvMflZDcwQJmarInnYi88px+6HZcv2Uoxw7+/JOOTg=
// 输出 Base64 编码字节切片
hasher.ToBase64Bytes()  // []byte("ZEvMflZDcwQJmarInnYi88px+6HZcv2Uoxw7+/JOOTg=")

// 输出未编码原始字符串
hasher.ToRawString()
// 输出未编码原始字节切片
hasher.ToRawBytes()
```

## Sha3-384

### 输入数据

```go
// 输入字符串
hasher := dongle.Hash.FromString("hello world").BySha3(384)

// 输入字节切片
hasher := dongle.Hash.FromBytes([]byte("hello world")).BySha3(384)

// 输入文件流
file, _ := os.Open("test.txt")
hasher := dongle.Hash.FromFile(file).BySha3(384)

// 检查哈希错误
if hasher.Error != nil {
	fmt.Printf("哈希错误: %v\n", hasher.Error)
	return
}
```

### 输出数据

```go
// 输出 Hex 编码字符串
hasher.ToHexString() // 83bff28dde1b1bf5810071c6643c08e5b05bdb836effd70b403ea8ea0a634dc4997eb1053aa3593f590f9c63630dd90b
// 输出 Hex 编码字节切片
hasher.ToHexBytes()  // []byte("83bff28dde1b1bf5810071c6643c08e5b05bdb836effd70b403ea8ea0a634dc4997eb1053aa3593f590f9c63630dd90b")

// 输出 Base64 编码字符串
hasher.ToBase64String() // g7/yjd4bG/WBAHHGZDwI5bBb24Nu/9cLQD6o6gpjTcSZfrEFOqNZP1kPnGNjDdkL
// 输出 Base64 编码字节切片
hasher.ToBase64Bytes()  // []byte("g7/yjd4bG/WBAHHGZDwI5bBb24Nu/9cLQD6o6gpjTcSZfrEFOqNZP1kPnGNjDdkL")

// 输出未编码原始字符串
hasher.ToRawString()
// 输出未编码原始字节切片
hasher.ToRawBytes()
```

## Sha3-512

### 输入数据

```go
// 输入字符串
hasher := dongle.Hash.FromString("hello world").BySha3(512)

// 输入字节切片
hasher := dongle.Hash.FromBytes([]byte("hello world")).BySha3(512)

// 输入文件流
file, _ := os.Open("test.txt")
hasher := dongle.Hash.FromFile(file).BySha3(512)

// 检查哈希错误
if hasher.Error != nil {
	fmt.Printf("哈希错误: %v\n", hasher.Error)
	return
}
```

### 输出数据

```go
// 输出 Hex 编码字符串
hasher.ToHexString() // 840006653e9ac9e95117a15c915caab81662918e925de9e004f774ff82d7079a40d4d27b1b372657c61d46d470304c88c788b3a4527ad074d1dccbee5dbaa99a
// 输出 Hex 编码字节切片
hasher.ToHexBytes()  // []byte("840006653e9ac9e95117a15c915caab81662918e925de9e004f774ff82d7079a40d4d27b1b372657c61d46d470304c88c788b3a4527ad074d1dccbee5dbaa99a")

// 输出 Base64 编码字符串
hasher.ToBase64String() // hAAGZT6ayelRF6FckVyquBZikY6SXengBPd0/4LXB5pA1NJ7GzcmV8YdRtRwMEyIx4izpFJ60HTR3MvuXbqpmg==
// 输出 Base64 编码字节切片
hasher.ToBase64Bytes()  // []byte("hAAGZT6ayelRF6FckVyquBZikY6SXengBPd0/4LXB5pA1NJ7GzcmV8YdRtRwMEyIx4izpFJ60HTR3MvuXbqpmg==")

// 输出未编码原始字符串
hasher.ToRawString()
// 输出未编码原始字节切片
hasher.ToRawBytes()
```