---
title: Blowfish 对称加密算法
head:
  - - meta
    - name: description
      content: Blowfish 对称加密算法，支持 1-56 字节可变长度密钥，提供多种分组模式（CBC、ECB、CTR、CFB、OFB）和填充模式，支持标准和流式处理，支持 Hex 和 Base64 输出格式
  - - meta
    - name: keywords
      content: dongle, go-dongle, 加密, 解密, Blowfish, 对称加密算法, 分组模式, 填充模式, CBC, ECB, CTR, CFB, OFB
---

# Blowfish

Blowfish 是一种对称加密算法，支持可变长度的密钥，密钥长度为 `1` 到 `56` 字节。`dongle` 支持标准和流式 `Blowfish` 加密，提供多种分组模式、填充模式和输出格式。

支持以下分组模式：

- **CBC（Cipher Block Chaining）**：密码分组链接模式，需要设置密钥 `Key`、初始化向量 `IV`（8 字节）和填充模式 `Padding`
- **ECB（Electronic Codebook）**：电子密码本模式，需要设置密钥 `Key` 和填充模式 `Padding`
- **CTR（Counter）**：计数器模式，需要设置密钥 `Key` 和初始化向量 `IV`（8 字节）
- **CFB（Cipher Feedback）**：密码反馈模式，需要设置密钥 `Key` 和初始化向量 `IV`（8 字节）
- **OFB（Output Feedback）**：输出反馈模式，需要设置密钥 `Key` 和初始化向量 `IV`（8 字节）

> **注意**：Blowfish 算法不支持 `GCM`（Galois/Counter Mode）模式。这是因为 `GCM` 模式要求密码算法具有 `128` 位块大小，而 `Blowfish` 只有 `64` 位块大小（`8` 字节）。这是密码学标准的技术限制，不是实现问题。

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
c := cipher.NewBlowfishCipher(cipher.CBC)
// 设置密钥（1-56 字节）
c.SetKey([]byte("12345678"))
// 设置初始化向量（8 字节）
c.SetIV([]byte("87654321"))
// 设置填充模式
c.SetPadding(cipher.PKCS7)
```

### 加密数据

输入数据

```go
// 输入字符串
encrypter := dongle.Encrypt.FromString("hello world").ByBlowfish(c)
// 输入字节切片
encrypter := dongle.Encrypt.FromBytes([]byte("hello world")).ByBlowfish(c)
// 输入文件流
file, _ := os.Open("test.txt")
encrypter := dongle.Encrypt.FromFile(file).ByBlowfish(c)

// 检查加密错误
if encrypter.Error != nil {
	fmt.Printf("加密错误: %v\n", encrypter.Error)
	return
}
```

输出数据

```go
// 输出 Hex 编码字符串
encrypter.ToHexString() // f52a4cc3738f6ed0ee8fe4312fa9be82
// 输出 Hex 编码字节切片
encrypter.ToHexBytes()  // []byte("f52a4cc3738f6ed0ee8fe4312fa9be82")

// 输出 Base64 编码字符串
encrypter.ToBase64String() // 9SpMw3OPbtDuj+QxL6m+gg==
// 输出 Base64 编码字节切片
encrypter.ToBase64Bytes()  // []byte("9SpMw3OPbtDuj+QxL6m+gg==")

// 输出未编码原始字符串
encrypter.ToRawString()
// 输出未编码原始字节切片
encrypter.ToRawBytes()
```

### 解密数据

输入数据

```go
// 输入 Hex 编码字符串
decrypter := dongle.Decrypt.FromHexString(hexString).ByBlowfish(c)
// 输入 Hex 编码字节切片
decrypter := dongle.Decrypt.FromHexBytes(hexBytes).ByBlowfish(c)
// 输入 Hex 编码文件流
file, _ := os.Open("encrypted.hex")
decrypter := dongle.Decrypt.FromHexFile(file).ByBlowfish(c)

// 输入 Base64 编码字符串
decrypter := dongle.Decrypt.FromBase64String(base64String).ByBlowfish(c)
// 输入 Base64 编码字节切片
decrypter := dongle.Decrypt.FromBase64Bytes(base64Bytes).ByBlowfish(c)
// 输入 Base64 编码文件流
file, _ := os.Open("encrypted.base64")
decrypter := dongle.Decrypt.FromBase64File(file).ByBlowfish(c)

// 输入原始字符串
decrypter := dongle.Decrypt.FromRawString(rawString).ByBlowfish(c)
// 输入原始字节切片
decrypter := dongle.Decrypt.FromRawBytes(rawBytes).ByBlowfish(c)
// 输入原始文件流
file, _ := os.Open("encrypted.bin")
decrypter := dongle.Decrypt.FromRawFile(file).ByBlowfish(c)

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
c := cipher.NewBlowfishCipher(cipher.ECB)
// 设置密钥（1-56 字节）
c.SetKey([]byte("12345678"))
// 设置填充模式
c.SetPadding(cipher.PKCS7)
```

### 加密数据

输入数据
```go
// 输入字符串
encrypter := dongle.Encrypt.FromString("hello world").ByBlowfish(c)
// 输入字节切片
encrypter := dongle.Encrypt.FromBytes([]byte("hello world")).ByBlowfish(c)
// 输入文件流
file, _ := os.Open("test.txt")
encrypter := dongle.Encrypt.FromFile(file).ByBlowfish(c)

// 检查加密错误
if encrypter.Error != nil {
	fmt.Printf("加密错误: %v\n", encrypter.Error)
	return
}
```

输出数据
```go
// 输出 Hex 编码字符串
encrypter.ToHexString() // 77caf7bc47a73ead1497a822dd1a2bf0
// 输出 Hex 编码字节切片
encrypter.ToHexBytes()  // []byte("77caf7bc47a73ead1497a822dd1a2bf0")

// 输出 Base64 编码字符串
encrypter.ToBase64String() // d8r3vEenPq0Ul6gi3Ror8A==
// 输出 Base64 编码字节切片
encrypter.ToBase64Bytes()  // []byte("d8r3vEenPq0Ul6gi3Ror8A==")

// 输出未编码原始字符串
encrypter.ToRawString()
// 输出未编码原始字节切片
encrypter.ToRawBytes() 
```

### 解密数据

输入数据

```go
// 输入 Hex 编码字符串
decrypter := dongle.Decrypt.FromHexString(hexString).ByBlowfish(c)
// 输入 Hex 编码字节切片
decrypter := dongle.Decrypt.FromHexBytes(hexBytes).ByBlowfish(c)
// 输入 Hex 编码文件流
file, _ := os.Open("encrypted.hex")
decrypter := dongle.Decrypt.FromHexFile(file).ByBlowfish(c)

// 输入 Base64 编码字符串
decrypter := dongle.Decrypt.FromBase64String(base64String).ByBlowfish(c)
// 输入 Base64 编码字节切片
decrypter := dongle.Decrypt.FromBase64Bytes(base64Bytes).ByBlowfish(c)
// 输入 Base64 编码文件流
file, _ := os.Open("encrypted.base64")
decrypter := dongle.Decrypt.FromBase64File(file).ByBlowfish(c)

// 输入原始字符串
decrypter := dongle.Decrypt.FromRawString(rawString).ByBlowfish(c)

// 输入原始字节切片
decrypter := dongle.Decrypt.FromRawBytes(rawBytes).ByBlowfish(c)

// 输入原始文件流
file, _ := os.Open("encrypted.bin")
decrypter := dongle.Decrypt.FromRawFile(file).ByBlowfish(c)

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
c := cipher.NewBlowfishCipher(cipher.CTR)
// 设置密钥（1-56 字节）
c.SetKey([]byte("12345678"))
// 设置初始化向量（8 字节）
c.SetIV([]byte("87654321"))                   
```

### 加密数据

输入数据
```go
// 输入字符串
encrypter := dongle.Encrypt.FromString("hello world").ByBlowfish(c)
// 输入字节切片
encrypter := dongle.Encrypt.FromBytes([]byte("hello world")).ByBlowfish(c)
// 输入文件流
file, _ := os.Open("test.txt")
encrypter := dongle.Encrypt.FromFile(file).ByBlowfish(c)

// 检查加密错误
if encrypter.Error != nil {
	fmt.Printf("加密错误: %v\n", encrypter.Error)
	return
}
```

输出数据
```go
// 输出 Hex 编码字符串
encrypter.ToHexString() // 09f68045da3a38f2620280
// 输出 Hex 编码字节切片
encrypter.ToHexBytes()  // []byte("09f68045da3a38f2620280")

// 输出 Base64 编码字符串
encrypter.ToBase64String() // CfaARdo6OPJiAoA=
// 输出 Base64 编码字节切片
encrypter.ToBase64Bytes()  // []byte("CfaARdo6OPJiAoA=")

// 输出未编码原始字符串
encrypter.ToRawString()
// 输出未编码原始字节切片
encrypter.ToRawBytes() 
```

### 解密数据

输入数据

```go
// 输入 Hex 编码字符串
decrypter := dongle.Decrypt.FromHexString(hexString).ByBlowfish(c)
// 输入 Hex 编码字节切片
decrypter := dongle.Decrypt.FromHexBytes(hexBytes).ByBlowfish(c)
// 输入 Hex 编码文件流
file, _ := os.Open("encrypted.hex")
decrypter := dongle.Decrypt.FromHexFile(file).ByBlowfish(c)

// 输入 Base64 编码字符串
decrypter := dongle.Decrypt.FromBase64String(base64String).ByBlowfish(c)
// 输入 Base64 编码字节切片
decrypter := dongle.Decrypt.FromBase64Bytes(base64Bytes).ByBlowfish(c)
// 输入 Base64 编码文件流
file, _ := os.Open("encrypted.base64")
decrypter := dongle.Decrypt.FromBase64File(file).ByBlowfish(c)

// 输入原始字符串
decrypter := dongle.Decrypt.FromRawString(rawString).ByBlowfish(c)
// 输入原始字节切片
decrypter := dongle.Decrypt.FromRawBytes(rawBytes).ByBlowfish(c)
// 输入原始文件流
file, _ := os.Open("encrypted.bin")
decrypter := dongle.Decrypt.FromRawFile(file).ByBlowfish(c)

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
c := cipher.NewBlowfishCipher(cipher.CFB)
// 设置密钥（1-56 字节）
c.SetKey([]byte("12345678"))
// 设置初始化向量（8 字节）
c.SetIV([]byte("87654321"))                   
```

### 加密数据

输入数据
```go
// 输入字符串
encrypter := dongle.Encrypt.FromString("hello world").ByBlowfish(c)
// 输入字节切片
encrypter := dongle.Encrypt.FromBytes([]byte("hello world")).ByBlowfish(c)
// 输入文件流
file, _ := os.Open("test.txt")
encrypter := dongle.Encrypt.FromFile(file).ByBlowfish(c)

// 检查加密错误
if encrypter.Error != nil {
	fmt.Printf("加密错误: %v\n", encrypter.Error)
	return
}
```

输出数据
```go
// 输出 Hex 编码字符串
encrypter.ToHexString() // 09f68045da3a38f217a836
// 输出 Hex 编码字节切片
encrypter.ToHexBytes()  // []byte("09f68045da3a38f217a836")

// 输出 Base64 编码字符串
encrypter.ToBase64String() // CfaARdo6OPIXqDY=
// 输出 Base64 编码字节切片
encrypter.ToBase64Bytes()  // []byte("CfaARdo6OPIXqDY=")

// 输出未编码原始字符串
encrypter.ToRawString()
// 输出未编码原始字节切片
encrypter.ToRawBytes() 
```

### 解密数据

输入数据

```go
// 输入 Hex 编码字符串
decrypter := dongle.Decrypt.FromHexString(hexString).ByBlowfish(c)
// 输入 Hex 编码字节切片
decrypter := dongle.Decrypt.FromHexBytes(hexBytes).ByBlowfish(c)
// 输入 Hex 编码文件流
file, _ := os.Open("encrypted.hex")
decrypter := dongle.Decrypt.FromHexFile(file).ByBlowfish(c)

// 输入 Base64 编码字符串
decrypter := dongle.Decrypt.FromBase64String(base64String).ByBlowfish(c)
// 输入 Base64 编码字节切片
decrypter := dongle.Decrypt.FromBase64Bytes(base64Bytes).ByBlowfish(c)
// 输入 Base64 编码文件流
file, _ := os.Open("encrypted.base64")
decrypter := dongle.Decrypt.FromBase64File(file).ByBlowfish(c)

// 输入原始字符串
decrypter := dongle.Decrypt.FromRawString(rawString).ByBlowfish(c)
// 输入原始字节切片
decrypter := dongle.Decrypt.FromRawBytes(rawBytes).ByBlowfish(c)
// 输入原始文件流
file, _ := os.Open("encrypted.bin")
decrypter := dongle.Decrypt.FromRawFile(file).ByBlowfish(c)

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
c := cipher.NewBlowfishCipher(cipher.OFB)
// 设置密钥（1-56 字节）
c.SetKey([]byte("12345678"))
// 设置初始化向量（8 字节）
c.SetIV([]byte("87654321"))                  
```

### 加密数据

输入数据
```go
// 输入字符串
encrypter := dongle.Encrypt.FromString("hello world").ByBlowfish(c)
// 输入字节切片
encrypter := dongle.Encrypt.FromBytes([]byte("hello world")).ByBlowfish(c)
// 输入文件流
file, _ := os.Open("test.txt")
encrypter := dongle.Encrypt.FromFile(file).ByBlowfish(c)

// 检查加密错误
if encrypter.Error != nil {
	fmt.Printf("加密错误: %v\n", encrypter.Error)
	return
}
```

输出数据
```go
// 输出 Hex 编码字符串
encrypter.ToHexString() // 09f68045da3a38f2613a97
// 输出 Hex 编码字节切片
encrypter.ToHexBytes()  // []byte("09f68045da3a38f2613a97")

// 输出 Base64 编码字符串
encrypter.ToBase64String() // CfaARdo6OPJhOpc=
// 输出 Base64 编码字节切片
encrypter.ToBase64Bytes()  // []byte("CfaARdo6OPJhOpc=")

// 输出未编码原始字符串
encrypter.ToRawString()
// 输出未编码原始字节切片
encrypter.ToRawBytes() 
```

### 解密数据

输入数据

```go
// 输入 Hex 编码字符串
decrypter := dongle.Decrypt.FromHexString(hexString).ByBlowfish(c)
// 输入 Hex 编码字节切片
decrypter := dongle.Decrypt.FromHexBytes(hexBytes).ByBlowfish(c)
// 输入 Hex 编码文件流
file, _ := os.Open("encrypted.hex")
decrypter := dongle.Decrypt.FromHexFile(file).ByBlowfish(c)

// 输入 Base64 编码字符串
decrypter := dongle.Decrypt.FromBase64String(base64String).ByBlowfish(c)
// 输入 Base64 编码字节切片
decrypter := dongle.Decrypt.FromBase64Bytes(base64Bytes).ByBlowfish(c)
// 输入 Base64 编码文件流
file, _ := os.Open("encrypted.base64")
decrypter := dongle.Decrypt.FromBase64File(file).ByBlowfish(c)

// 输入原始字符串
decrypter := dongle.Decrypt.FromRawString(rawString).ByBlowfish(c)
// 输入原始字节切片
decrypter := dongle.Decrypt.FromRawBytes(rawBytes).ByBlowfish(c)
// 输入原始文件流
file, _ := os.Open("encrypted.bin")
decrypter := dongle.Decrypt.FromRawFile(file).ByBlowfish(c)

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



