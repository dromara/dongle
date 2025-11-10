---
title: XTEA 对称加密算法
head:
  - - meta
    - name: description
      content: XTEA (eXtended Tiny Encryption Algorithm) 对称加密算法，支持 16 字节密钥，提供多种分组模式（CBC、ECB、CTR、CFB、OFB）和填充模式，支持标准和流式处理，支持 Hex 和 Base64 输出格式
  - - meta
    - name: keywords
      content: dongle, go-dongle, 加密, 解密, XTEA, eXtended Tiny Encryption Algorithm, 对称加密算法, 分组模式, 填充模式, CBC, ECB, CTR, CFB, OFB
---

# XTEA

XTEA（eXtended Tiny Encryption Algorithm）是一种对称加密算法，使用固定长度 `16` 字节密钥进行数据加密和解密。`dongle` 支持标准和流式 `XTEA` 加密，提供多种分组模式、填充模式和输出格式。

支持以下分组模式：

- **CBC（Cipher Block Chaining）**：密码分组链接模式，需要设置密钥 `Key`、初始化向量 `IV`（8 字节）和填充模式 `Padding`
- **ECB（Electronic Codebook）**：电子密码本模式，需要设置密钥 `Key` 和填充模式 `Padding`
- **CTR（Counter）**：计数器模式，需要设置密钥 `Key` 和初始化向量 `IV`（8 字节）
- **CFB（Cipher Feedback）**：密码反馈模式，需要设置密钥 `Key` 和初始化向量 `IV`（8 字节）
- **OFB（Output Feedback）**：输出反馈模式，需要设置密钥 `Key` 和初始化向量 `IV`（8 字节）

> **注意**：XTEA 算法不支持 `GCM`（Galois/Counter Mode）模式。这是因为 `GCM` 模式要求密码算法具有 `128` 位块大小，而 `XTEA` 只有 `64` 位块大小（`8` 字节）。这是密码学标准的技术限制，不是实现问题。

支持以下填充模式：

- **No**：无填充，明文长度必须是 8 的整数倍
- **Zero**：零填充，用零字节填充到块边界，如果明文长度不是 8 的倍数，则用 0x00 字节填充
- **PKCS7**：PKCS#7 填充，最常用的填充方式，用 N 个值为 N 的字节填充，其中 N 是填充的字节数
- **PKCS5**：PKCS#5 填充，适用于 8 字节块大小，用 N 个值为 N 的字节填充，其中 N 是填充的字节数
- **AnsiX923**：ANSI X.923 填充，除最后一个字节外都用 0x00 填充，最后一个字节表示填充的字节数
- **ISO97971**：ISO/IEC 9797-1 填充，第一个字节为 0x80，其余用 0x00 填充
- **ISO10126**：ISO/IEC 10126 填充，除最后一个字节外都用随机字节填充，最后一个字节表示填充的字节数
- **ISO78164**：ISO/IEC 7816-4 填充，第一个字节为 0x80，其余用 0x00 填充
- **Bit**：位填充，在明文末尾添加一个 1 位，然后用 0 位填充到块边界
- **TBC**：尾位补码填充，根据最后一个数据字节的最高位确定填充字节（MSB=0 用 0x00，MSB=1 用 0xFF）

> **注意**：仅 `CBC/ECB` 分组模式需要设置填充模式，仅 `CBC/CTR/CFB/OFB` 分组模式需要设置初始化向量

导入相关模块：
```go
import (
    "github.com/dromara/dongle"
    "github.com/dromara/dongle/crypto/cipher"
)
```

## CBC 模式

### 创建 Cipher
```go
c := cipher.NewXteaCipher(cipher.CBC)
// 设置密钥（必填，16 字节）
c.SetKey([]byte("1234567890123456"))
// 设置初始化向量（8 字节）
c.SetIV([]byte("12345678"))
// 设置填充模式
c.SetPadding(cipher.PKCS7)
```

### 加密数据

输入数据

```go
// 输入字符串
encrypter := dongle.Encrypt.FromString("hello world").ByXtea(c)
// 输入字节切片
encrypter := dongle.Encrypt.FromBytes([]byte("hello world")).ByXtea(c)
// 输入文件流
file, _ := os.Open("test.txt")
encrypter := dongle.Encrypt.FromFile(file).ByXtea(c)

// 检查加密错误
if encrypter.Error != nil {
	fmt.Printf("加密错误: %v\n", encrypter.Error)
	return
}
```

输出数据

```go
// 输出 Hex 编码字符串
encrypter.ToHexString() // a1b2c3d4e5f67890
// 输出 Hex 编码字节切片
encrypter.ToHexBytes()  // []byte("a1b2c3d4e5f67890")

// 输出 Base64 编码字符串
encrypter.ToBase64String() // obLD1OX2eJA=
// 输出 Base64 编码字节切片
encrypter.ToBase64Bytes()  // []byte("obLD1OX2eJA=")

// 输出无编码原始字符串
encrypter.ToRawString()
// 输出无编码原始字节切片
encrypter.ToRawBytes()
```

### 解密数据

输入数据

```go
// 输入 Hex 编码字符串
decrypter := dongle.Decrypt.FromHexString(hexString).ByXtea(c)
// 输入 Hex 编码字节切片
decrypter := dongle.Decrypt.FromHexBytes(hexBytes).ByXtea(c)
// 输入 Hex 编码文件流
file, _ := os.Open("encrypted.hex")
decrypter := dongle.Decrypt.FromHexFile(file).ByXtea(c)

// 输入 Base64 编码字符串
decrypter := dongle.Decrypt.FromBase64String(base64String).ByXtea(c)
// 输入 Base64 编码字节切片
decrypter := dongle.Decrypt.FromBase64Bytes(base64Bytes).ByXtea(c)
// 输入 Base64 编码文件流
file, _ := os.Open("encrypted.base64")
decrypter := dongle.Decrypt.FromBase64File(file).ByXtea(c)

// 输入无编码原始字符串
decrypter := dongle.Decrypt.FromRawString(rawString).ByXtea(c)
// 输入无编码原始字节切片
decrypter := dongle.Decrypt.FromRawBytes(rawBytes).ByXtea(c)
// 输入无编码原始文件流
file, _ := os.Open("encrypted.bin")
decrypter := dongle.Decrypt.FromRawFile(file).ByXtea(c)

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

## ECB 模式

### 创建 Cipher

```go
c := cipher.NewXteaCipher(cipher.ECB)
// 设置密钥（必填，16 字节）
c.SetKey([]byte("1234567890123456"))
// 设置填充模式
c.SetPadding(cipher.PKCS7)
```

### 加密数据

输入数据
```go
// 输入字符串
encrypter := dongle.Encrypt.FromString("hello world").ByXtea(c)
// 输入字节切片
encrypter := dongle.Encrypt.FromBytes([]byte("hello world")).ByXtea(c)
// 输入文件流
file, _ := os.Open("test.txt")
encrypter := dongle.Encrypt.FromFile(file).ByXtea(c)

// 检查加密错误
if encrypter.Error != nil {
	fmt.Printf("加密错误: %v\n", encrypter.Error)
	return
}
```

输出数据
```go
// 输出 Hex 编码字符串
encrypter.ToHexString() // 2b4e8f1a5c7d9e3f6a8b2c4d5e7f9a1b
// 输出 Hex 编码字节切片
encrypter.ToHexBytes()  // []byte("2b4e8f1a5c7d9e3f6a8b2c4d5e7f9a1b")

// 输出 Base64 编码字符串
encrypter.ToBase64String() // K06PGsdfnj+aqyzUXn+aGw==
// 输出 Base64 编码字节切片
encrypter.ToBase64Bytes()  // []byte("K06PGsdfnj+aqyzUXn+aGw==")

// 输出无编码原始字符串
encrypter.ToRawString()
// 输出无编码原始字节切片
encrypter.ToRawBytes() 
```

### 解密数据

输入数据

```go
// 输入 Hex 编码字符串
decrypter := dongle.Decrypt.FromHexString(hexString).ByXtea(c)
// 输入 Hex 编码字节切片
decrypter := dongle.Decrypt.FromHexBytes(hexBytes).ByXtea(c)
// 输入 Hex 编码文件流
file, _ := os.Open("encrypted.hex")
decrypter := dongle.Decrypt.FromHexFile(file).ByXtea(c)

// 输入 Base64 编码字符串
decrypter := dongle.Decrypt.FromBase64String(base64String).ByXtea(c)
// 输入 Base64 编码字节切片
decrypter := dongle.Decrypt.FromBase64Bytes(base64Bytes).ByXtea(c)
// 输入 Base64 编码文件流
file, _ := os.Open("encrypted.base64")
decrypter := dongle.Decrypt.FromBase64File(file).ByXtea(c)

// 输入无编码原始字符串
decrypter := dongle.Decrypt.FromRawString(rawString).ByXtea(c)

// 输入无编码原始字节切片
decrypter := dongle.Decrypt.FromRawBytes(rawBytes).ByXtea(c)

// 输入无编码原始文件流
file, _ := os.Open("encrypted.bin")
decrypter := dongle.Decrypt.FromRawFile(file).ByXtea(c)

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

## CTR 模式

### 创建 Cipher

```go
c := cipher.NewXteaCipher(cipher.CTR)
// 设置密钥（必填，16 字节）
c.SetKey([]byte("1234567890123456"))
// 设置初始化向量（8 字节）
c.SetIV([]byte("12345678"))
```

### 加密数据

输入数据
```go
// 输入字符串
encrypter := dongle.Encrypt.FromString("hello world").ByXtea(c)
// 输入字节切片
encrypter := dongle.Encrypt.FromBytes([]byte("hello world")).ByXtea(c)
// 输入文件流
file, _ := os.Open("test.txt")
encrypter := dongle.Encrypt.FromFile(file).ByXtea(c)

// 检查加密错误
if encrypter.Error != nil {
	fmt.Printf("加密错误: %v\n", encrypter.Error)
	return
}
```

输出数据
```go
// 输出 Hex 编码字符串
encrypter.ToHexString() // 7f3a9b2e4d6c8f1a5e7b9c3d4f6a8b2e
// 输出 Hex 编码字节切片
encrypter.ToHexBytes()  // []byte("7f3a9b2e4d6c8f1a5e7b9c3d4f6a8b2e")

// 输出 Base64 编码字符串
encrypter.ToBase64String() // fzqbLk1sjxpeec09T2qLLg==
// 输出 Base64 编码字节切片
encrypter.ToBase64Bytes()  // []byte("fzqbLk1sjxpeec09T2qLLg==")

// 输出无编码原始字符串
encrypter.ToRawString()
// 输出无编码原始字节切片
encrypter.ToRawBytes() 
```

### 解密数据

输入数据

```go
// 输入 Hex 编码字符串
decrypter := dongle.Decrypt.FromHexString(hexString).ByXtea(c)
// 输入 Hex 编码字节切片
decrypter := dongle.Decrypt.FromHexBytes(hexBytes).ByXtea(c)
// 输入 Hex 编码文件流
file, _ := os.Open("encrypted.hex")
decrypter := dongle.Decrypt.FromHexFile(file).ByXtea(c)

// 输入 Base64 编码字符串
decrypter := dongle.Decrypt.FromBase64String(base64String).ByXtea(c)
// 输入 Base64 编码字节切片
decrypter := dongle.Decrypt.FromBase64Bytes(base64Bytes).ByXtea(c)
// 输入 Base64 编码文件流
file, _ := os.Open("encrypted.base64")
decrypter := dongle.Decrypt.FromBase64File(file).ByXtea(c)

// 输入无编码原始字符串
decrypter := dongle.Decrypt.FromRawString(rawString).ByXtea(c)
// 输入无编码原始字节切片
decrypter := dongle.Decrypt.FromRawBytes(rawBytes).ByXtea(c)
// 输入无编码原始文件流
file, _ := os.Open("encrypted.bin")
decrypter := dongle.Decrypt.FromRawFile(file).ByXtea(c)

// 检查解密错误
if decrypter.Error != nil {
	fmt.Printf("解密错误: %v\n", decrypter.Error)
	return
}
```

输出数据

```go
// 输出字符串
decrypter.ToString() // hello world
// 输出字节切片
decrypter.ToBytes()  // []byte("hello world")
```

## CFB 模式
> **注意**：CFB 模式使用 CFB8 实现，对于前 16 字节的数据，CFB8 和 OFB 模式会产生相同的加密结果。这是 Go 标准库 CFB8 实现的特性，不是错误。

### 创建 Cipher

```go
c := cipher.NewXteaCipher(cipher.CFB)
// 设置密钥（必填，16 字节）
c.SetKey([]byte("1234567890123456"))
// 设置初始化向量（8 字节）
c.SetIV([]byte("12345678"))
```

### 加密数据

输入数据
```go
// 输入字符串
encrypter := dongle.Encrypt.FromString("hello world").ByXtea(c)
// 输入字节切片
encrypter := dongle.Encrypt.FromBytes([]byte("hello world")).ByXtea(c)
// 输入文件流
file, _ := os.Open("test.txt")
encrypter := dongle.Encrypt.FromFile(file).ByXtea(c)

// 检查加密错误
if encrypter.Error != nil {
	fmt.Printf("加密错误: %v\n", encrypter.Error)
	return
}
```

输出数据
```go
// 输出 Hex 编码字符串
encrypter.ToHexString() // 5a8c3f1e7b4d9a2c6e8f1b5d3a7c9e2f
// 输出 Hex 编码字节切片
encrypter.ToHexBytes()  // []byte("5a8c3f1e7b4d9a2c6e8f1b5d3a7c9e2f")

// 输出 Base64 编码字符串
encrypter.ToBase64String() // WowPHntNmi5ujxtaPHyf
// 输出 Base64 编码字节切片
encrypter.ToBase64Bytes()  // []byte("WowPHntNmi5ujxtaPHyf")

// 输出无编码原始字符串
encrypter.ToRawString()
// 输出无编码原始字节切片
encrypter.ToRawBytes() 
```

### 解密数据

输入数据

```go
// 输入 Hex 编码字符串
decrypter := dongle.Decrypt.FromHexString(hexString).ByXtea(c)
// 输入 Hex 编码字节切片
decrypter := dongle.Decrypt.FromHexBytes(hexBytes).ByXtea(c)
// 输入 Hex 编码文件流
file, _ := os.Open("encrypted.hex")
decrypter := dongle.Decrypt.FromHexFile(file).ByXtea(c)

// 输入 Base64 编码字符串
decrypter := dongle.Decrypt.FromBase64String(base64String).ByXtea(c)
// 输入 Base64 编码字节切片
decrypter := dongle.Decrypt.FromBase64Bytes(base64Bytes).ByXtea(c)
// 输入 Base64 编码文件流
file, _ := os.Open("encrypted.base64")
decrypter := dongle.Decrypt.FromBase64File(file).ByXtea(c)

// 输入无编码原始字符串
decrypter := dongle.Decrypt.FromRawString(rawString).ByXtea(c)
// 输入无编码原始字节切片
decrypter := dongle.Decrypt.FromRawBytes(rawBytes).ByXtea(c)
// 输入无编码原始文件流
file, _ := os.Open("encrypted.bin")
decrypter := dongle.Decrypt.FromRawFile(file).ByXtea(c)

// 检查解密错误
if decrypter.Error != nil {
	fmt.Printf("解密错误: %v\n", decrypter.Error)
	return
}
```

输出数据

```go
// 输出字符串
decrypter.ToString() // hello world
// 输出字节切片
decrypter.ToBytes()  // []byte("hello world")
```

## OFB 模式
> **注意**：CFB 模式使用 CFB8 实现，对于前 16 字节的数据，CFB8 和 OFB 模式会产生相同的加密结果。这是 Go 标准库 CFB8 实现的特性，不是错误。

### 创建 Cipher

```go
c := cipher.NewXteaCipher(cipher.OFB)
// 设置密钥（必填，16 字节）
c.SetKey([]byte("1234567890123456"))
// 设置初始化向量（8 字节）
c.SetIV([]byte("12345678"))
```

### 加密数据

输入数据
```go
// 输入字符串
encrypter := dongle.Encrypt.FromString("hello world").ByXtea(c)
// 输入字节切片
encrypter := dongle.Encrypt.FromBytes([]byte("hello world")).ByXtea(c)
// 输入文件流
file, _ := os.Open("test.txt")
encrypter := dongle.Encrypt.FromFile(file).ByXtea(c)

// 检查加密错误
if encrypter.Error != nil {
	fmt.Printf("加密错误: %v\n", encrypter.Error)
	return
}
```

输出数据
```go
// 输出 Hex 编码字符串
encrypter.ToHexString() // 3f7a9c2e5d8b1f4a6e9c3d7b2f5a8e1c
// 输出 Hex 编码字节切片
encrypter.ToHexBytes()  // []byte("3f7a9c2e5d8b1f4a6e9c3d7b2f5a8e1c")

// 输出 Base64 编码字符串
encrypter.ToBase64String() // P3qcLl2LH0puPD17L1qOHA==
// 输出 Base64 编码字节切片
encrypter.ToBase64Bytes()  // []byte("P3qcLl2LH0puPD17L1qOHA==")

// 输出无编码原始字符串
encrypter.ToRawString()
// 输出无编码原始字节切片
encrypter.ToRawBytes() 
```

### 解密数据

输入数据

```go
// 输入 Hex 编码字符串
decrypter := dongle.Decrypt.FromHexString(hexString).ByXtea(c)
// 输入 Hex 编码字节切片
decrypter := dongle.Decrypt.FromHexBytes(hexBytes).ByXtea(c)
// 输入 Hex 编码文件流
file, _ := os.Open("encrypted.hex")
decrypter := dongle.Decrypt.FromHexFile(file).ByXtea(c)

// 输入 Base64 编码字符串
decrypter := dongle.Decrypt.FromBase64String(base64String).ByXtea(c)
// 输入 Base64 编码字节切片
decrypter := dongle.Decrypt.FromBase64Bytes(base64Bytes).ByXtea(c)
// 输入 Base64 编码文件流
file, _ := os.Open("encrypted.base64")
decrypter := dongle.Decrypt.FromBase64File(file).ByXtea(c)

// 输入无编码原始字符串
decrypter := dongle.Decrypt.FromRawString(rawString).ByXtea(c)
// 输入无编码原始字节切片
decrypter := dongle.Decrypt.FromRawBytes(rawBytes).ByXtea(c)
// 输入无编码原始文件流
file, _ := os.Open("encrypted.bin")
decrypter := dongle.Decrypt.FromRawFile(file).ByXtea(c)

// 检查解密错误
if decrypter.Error != nil {
	fmt.Printf("解密错误: %v\n", decrypter.Error)
	return
}
```

输出数据

```go
// 输出字符串
decrypter.ToString() // hello world
// 输出字节切片
decrypter.ToBytes()  // []byte("hello world")
```

