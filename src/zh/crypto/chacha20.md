---
title: ChaCha20 流密码加密算法
head:
  - - meta
    - name: description
      content: ChaCha20 流密码加密算法 | 一个轻量级、语义化、对开发者友好的 golang 密码库
  - - meta
    - name: keywords
      content: 加密, 解密, ChaCha20, 对称加密算法,流密码
---

# ChaCha20

ChaCha20 是一种现代高性能的流密码算法，使用固定长度的 `32` 字节密钥和 `12` 字节随机数对数据进行加密和解密。`dongle` 支持标准和流式 `ChaCha20` 加密，提供多种输入格式、输出格式和流式处理能力。

ChaCha20 是一种对称加密算法，加密和解密使用相同的密钥。ChaCha20 作为流密码可以处理任意长度的数据，无需数据对齐要求。

 注意事项

- **密钥长度**：ChaCha20 密钥必须是 `32` 字节
- **随机数长度**：ChaCha20 随机数必须是 `12` 字节
- **数据长度**：支持任意长度的数据，无对齐要求
- **随机数唯一性**：每个密钥下的随机数必须唯一，不可重复使用
- **安全性**：ChaCha20 提供高安全性，被广泛用于现代加密应用

导入相关模块：
```go
import (
    "github.com/dromara/dongle"
    "github.com/dromara/dongle/crypto/cipher"
)
```

## 创建 Cipher

```go
c := cipher.NewChaCha20Cipher()
// 设置密钥（必须是 32 字节）
c.SetKey([]byte("dongle1234567890abcdef123456789x"))
// 设置随机数（必须是 12 字节）
c.SetNonce([]byte("123456789012"))
```

## 加密数据

 输入数据

```go
// 输入字符串
encrypter := dongle.Encrypt.FromString("hello world").ByChaCha20(c)
// 输入字节切片
encrypter := dongle.Encrypt.FromBytes([]byte("hello world")).ByChaCha20(c)
// 输入文件流
file, _ := os.Open("test.txt")
encrypter := dongle.Encrypt.FromFile(file).ByChaCha20(c)

// 检查加密错误
if encrypter.Error != nil {
	fmt.Printf("加密错误: %v\n", encrypter.Error)
	return
}
```

 输出数据

```go
// 输出 Hex 编码字符串
hexString := encrypter.ToHexString() // 4a1c8f2d3e5a6b7c
// 输出 Hex 编码字节切片
hexBytes := encrypter.ToHexBytes()   // []byte("4a1c8f2d3e5a6b7c")

// 输出 Base64 编码字符串
base64String := encrypter.ToBase64String() // ShyPLT5aa3w=
// 输出 Base64 编码字节切片
base64Bytes := encrypter.ToBase64Bytes()   // []byte("ShyPLT5aa3w=")

// 输出未编码原始字符串
rawString := encrypter.ToRawString()
// 输出未编码原始字节切片
rawBytes := encrypter.ToRawBytes()
```

## 解密数据

 输入数据

```go
// 输入 Hex 编码字符串
decrypter := dongle.Decrypt.FromHexString(hexString).ByChaCha20(c)
// 输入 Hex 编码字节切片
decrypter := dongle.Decrypt.FromHexBytes(hexBytes).ByChaCha20(c)
// 输入 Hex 编码文件流
file, _ := os.Open("encrypted.hex")
decrypter := dongle.Decrypt.FromHexFile(file).ByChaCha20(c)

// 输入 Base64 编码字符串
decrypter := dongle.Decrypt.FromBase64String(base64String).ByChaCha20(c)
// 输入 Base64 编码字节切片
decrypter := dongle.Decrypt.FromBase64Bytes(base64Bytes).ByChaCha20(c)
// 输入 Base64 编码文件流
file, _ := os.Open("encrypted.base64")
decrypter := dongle.Decrypt.FromBase64File(file).ByChaCha20(c)

// 输入未编码原始字符串
decrypter := dongle.Decrypt.FromRawString(rawString).ByChaCha20(c)
// 输入未编码原始字节切片
decrypter := dongle.Decrypt.FromRawBytes(rawBytes).ByChaCha20(c)
// 输入未编码原始文件流
file, _ := os.Open("encrypted.bin") 
decrypter := dongle.Decrypt.FromRawFile(file).ByChaCha20(c)

// 检查解密错误
if decrypter.Error != nil {
	fmt.Printf("解密错误: %v\n", decrypter.Error)
	return
}
```

 输出数据

```go
// 输出解密后的字符串
decrypter.ToString() // hello world
// 输出解密后的字节切片
decrypter.ToBytes()  // []byte("hello world")
```