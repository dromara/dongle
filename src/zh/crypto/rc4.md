---
title: RC4 流密码加密算法
head:
  - - meta
    - name: description
      content: RC4 流密码加密算法|一个轻量级、语义化、对开发者友好的 golang 密码库
  - - meta
    - name: keywords
      content: 加密, 解密, RC4, 对称加密算法, 流密码
---

# RC4

RC4（Rivest Cipher 4）是一种流密码加密算法，使用可变长度的密钥（`1-256` 字节）对数据进行加密和解密。`dongle` 支持标准和流式 `RC4` 加密，提供多种输入格式、输出格式和流式处理能力。

RC4 是一种对称加密算法，加密和解密使用相同的密钥。由于 `RC4` 是流密码，它不需要填充，可以直接处理任意长度的数据。

导入相关模块：
```go
import (
    "github.com/dromara/dongle"
    "github.com/dromara/dongle/crypto/cipher"
)
```

## 创建 Cipher

```go
c := cipher.NewRc4Cipher()
// 设置密钥（1-256 字节）
c.SetKey([]byte("dongle"))  
```

## 加密数据
 输入数据

```go
// 输入字符串
encrypter := dongle.Encrypt.FromString("hello world").ByRc4(c)
// 输入字节切片
encrypter := dongle.Encrypt.FromBytes([]byte("hello world")).ByRc4(c)
// 输入文件流
file, _ := os.Open("test.txt")
encrypter := dongle.Encrypt.FromFile(file).ByRc4(c)

// 检查加密错误
if encrypter.Error != nil {
	fmt.Printf("加密错误: %v\n", encrypter.Error)
	return
}
```

 输出数据
```go
// 输出 Hex 编码字符串
hexString := encrypter.ToHexString() // eba154b4cb5a9038dbbf9d
// 输出 Hex 编码字节切片
hexBytes := encrypter.ToHexBytes()   // []byte("eba154b4cb5a9038dbbf9d")

// 输出 Base64 编码字符串
base64String := encrypter.ToBase64String() // 66FUtMtakDjbv50=
// 输出 Base64 编码字节切片
base64Bytes := encrypter.ToBase64Bytes()   // []byte("66FUtMtakDjbv50=")

// 输出未编码原始字符串
rawString := encrypter.ToRawString()
// 输出未编码原始字节切片
rawBytes := encrypter.ToRawBytes() 
```

## 解密数据

 输入数据
```go
// 输入 Hex 编码字符串
decrypter := dongle.Decrypt.FromHexString(hexString).ByRc4(c)
// 输入 Hex 编码字节切片
decrypter := dongle.Decrypt.FromHexBytes(hexBytes).ByRc4(c)
// 输入 Hex 编码文件流
file, _ := os.Open("encrypted.hex")
decrypter := dongle.Decrypt.FromHexFile(file).ByRc4(c)

// 输入 Base64 编码字符串
decrypter := dongle.Decrypt.FromBase64String(base64String).ByRc4(c)
// 输入 Base64 编码字节切片
decrypter := dongle.Decrypt.FromBase64Bytes(base64Bytes).ByRc4(c)
// 输入 Base64 编码文件流
file, _ := os.Open("encrypted.base64")
decrypter := dongle.Decrypt.FromBase64File(file).ByRc4(c)

// 输入未编码原始字符串
decrypter := dongle.Decrypt.FromRawString(rawString).ByRc4(c)
// 输入未编码原始字节切片
decrypter := dongle.Decrypt.FromRawBytes(rawBytes).ByRc4(c)
// 输入未编码原始文件流
file, _ := os.Open("encrypted.bin") 
decrypter := dongle.Decrypt.FromRawFile(file).ByRc4(c)

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