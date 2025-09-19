---
head:
  - - meta
    - name: description
      content: SHA2 哈希算法|一个轻量级、语义化、对开发者友好的 golang 编码&密码库
  - - meta
    - name: keywords
      content: 哈希, hash, sha2, sha224, sha256, sha384, sha512
---

# Hash-Sha2

`Hash-Sha2` 是一系列产生不同长度哈希值的哈希算法，包括 `sha2-224`、`sha2-256`、`sha2-384` 和 `sha2-512`，`dongle` 支持所有四种 `hash-sha2` 变体。

- [Sha2-224](#sha2-224)：生成 28 字节哈希值
- [Sha2-256](#sha2-256)：生成 32 字节哈希值
- [Sha2-384](#sha2-384)：生成 48 字节哈希值
- [Sha2-512](#sha2-512)：生成 64 字节哈希值

## Sha2-224

### 输入数据

```go
// 输入字符串
hasher := dongle.Hash.FromString("hello world").BySha2(224)
// 输入字节切片
hasher := dongle.Hash.FromBytes([]byte("hello world")).BySha2(224)
// 输入文件流
file, _ := os.Open("test.txt")
hasher := dongle.Hash.FromFile(file).BySha2(224)

// 检查哈希错误
if hasher.Error != nil {
	fmt.Printf("哈希错误: %v\n", hasher.Error)
	return
}
```

### 输出数据

```go
// 输出 Hex 编码字符串
hasher.ToHexString() // 2f05477fc24bb4faefd86517156dafdecec45b8ad3cf2522a563582b
// 输出 Hex 编码字节切片
hasher.ToHexBytes()  // []byte("2f05477fc24bb4faefd86517156dafdecec45b8ad3cf2522a563582b")

// 输出 Base64 编码字符串
hasher.ToBase64String() // LwVHf8JLtPrv2GUXFW2v3s7EW4rTzyUipWNYKw==
// 输出 Base64 编码字节切片
hasher.ToBase64Bytes()  // []byte("LwVHf8JLtPrv2GUXFW2v3s7EW4rTzyUipWNYKw==")

// 输出未编码原始字符串
hasher.ToRawString()
// 输出未编码原始字节切片
hasher.ToRawBytes()
```

## Sha2-256

### 输入数据

```go
// 输入字符串
hasher := dongle.Hash.FromString("hello world").BySha2(256)

// 输入字节切片
hasher := dongle.Hash.FromBytes([]byte("hello world")).BySha2(256)

// 输入文件流
file, _ := os.Open("test.txt")
hasher := dongle.Hash.FromFile(file).BySha2(256)

// 检查哈希错误
if hasher.Error != nil {
	fmt.Printf("哈希错误: %v\n", hasher.Error)
	return
}
```

### 输出数据

```go
// 输出 Hex 编码字符串
hasher.ToHexString() // b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9
// 输出 Hex 编码字节切片
hasher.ToHexBytes()  // []byte("b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9")

// 输出 Base64 编码字符串
hasher.ToBase64String() // uU0nuZNNPgilLlLX2n2r+sSE7+N6U4DukIj3rOLvzek=
// 输出 Base64 编码字节切片
hasher.ToBase64Bytes()  // []byte("uU0nuZNNPgilLlLX2n2r+sSE7+N6U4DukIj3rOLvzek=")

// 输出未编码原始字符串
hasher.ToRawString()
// 输出未编码原始字节切片
hasher.ToRawBytes()
```

## Sha2-384

### 输入数据

```go
// 输入字符串
hasher := dongle.Hash.FromString("hello world").BySha2(384)

// 输入字节切片
hasher := dongle.Hash.FromBytes([]byte("hello world")).BySha2(384)

// 输入文件流
file, _ := os.Open("test.txt")
hasher := dongle.Hash.FromFile(file).BySha2(384)

// 检查哈希错误
if hasher.Error != nil {
	fmt.Printf("哈希错误: %v\n", hasher.Error)
	return
}
```

### 输出数据

```go
// 输出 Hex 编码字符串
hasher.ToHexString() // fdbd8e75a67f29f701a4e040385e2e23986303ea10239211af907fcbb83578b3e417cb71ce646efd0819dd8c088de1bd
// 输出 Hex 编码字节切片
hasher.ToHexBytes()  // []byte("fdbd8e75a67f29f701a4e040385e2e23986303ea10239211af907fcbb83578b3e417cb71ce646efd0819dd8c088de1bd")

// 输出 Base64 编码字符串
hasher.ToBase64String() // /b2OdaZ/KfcBpOBAOF4uI5hjA+oQI5IRr5B/y7g1eLPkF8txzmRu/QgZ3YwIjeG9
// 输出 Base64 编码字节切片
hasher.ToBase64Bytes()  // []byte("/b2OdaZ/KfcBpOBAOF4uI5hjA+oQI5IRr5B/y7g1eLPkF8txzmRu/QgZ3YwIjeG9")

// 输出未编码原始字符串
hasher.ToRawString()
// 输出未编码原始字节切片
hasher.ToRawBytes()
```

## Sha2-512

### 输入数据

```go
// 输入字符串
hasher := dongle.Hash.FromString("hello world").BySha2(512)

// 输入字节切片
hasher := dongle.Hash.FromBytes([]byte("hello world")).BySha2(512)

// 输入文件流
file, _ := os.Open("test.txt")
hasher := dongle.Hash.FromFile(file).BySha2(512)

// 检查哈希错误
if hasher.Error != nil {
	fmt.Printf("哈希错误: %v\n", hasher.Error)
	return
}
```

### 输出数据

```go
// 输出 Hex 编码字符串
hasher.ToHexString() // 309ecc489c12d6eb4cc40f50c902f2b4d0ed77ee511a7c7a9bcd3ca86d4cd86f989dd35bc5ff499670da34255b45b0cfd830e81f605dcf7dc5542e93ae9cd76f
// 输出 Hex 编码字节切片
hasher.ToHexBytes()  // []byte("309ecc489c12d6eb4cc40f50c902f2b4d0ed77ee511a7c7a9bcd3ca86d4cd86f989dd35bc5ff499670da34255b45b0cfd830e81f605dcf7dc5542e93ae9cd76f")

// 输出 Base64 编码字符串
hasher.ToBase64String() // MJ7MSJwS1utMxA9QyQLytNDtd+5RGnx6m808qG1M2G+YndNbxf9JlnDaNCVbRbDP2DDoH2Bdz33FVC6TrpzXbw==
// 输出 Base64 编码字节切片
hasher.ToBase64Bytes()  // []byte("MJ7MSJwS1utMxA9QyQLytNDtd+5RGnx6m808qG1M2G+YndNbxf9JlnDaNCVbRbDP2DDoH2Bdz33FVC6TrpzXbw==")

// 输出未编码原始字符串
hasher.ToRawString()
// 输出未编码原始字节切片
hasher.ToRawBytes()
```



