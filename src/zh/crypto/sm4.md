---
title: SM4 对称加密算法
head:
  - - meta
    - name: description
      content: SM4 对称加密算法 | 一个轻量级、语义化、对开发者友好的 golang 密码库
  - - meta
    - name: keywords
      content: 加密, 解密, SM4, 对称加密算法, 国密算法, 分组模式, 填充模式, CBC, ECB, CTR, GCM, CFB, OFB
---

# SM4

`SM4` 是一种对称加密算法，是中国国家密码管理局发布的商用对称分组密码算法，支持 `16` 字节密钥长度。`dongle` 支持标准和流式 `SM4` 加密，提供多种分组模式、填充模式和输出格式。

支持以下分组模式：

- **CBC（Cipher Block Chaining）**：密码分组链接模式，需要设置密钥 `Key`、初始化向量 `IV`（16 字节）和填充模式`Padding`
- **ECB（Electronic Codebook）**：电子密码本模式，需要设置密钥 `Key` 和填充模式`Padding`
- **CTR（Counter）**：计数器模式，需要设置密钥 `Key` 和初始化向量 `IV`（12 字节）
- **GCM（Galois/Counter Mode）**：伽罗瓦/计数器模式，需要设置密钥 `Key`、随机数 `Nonce`（12 字节）和额外的认证数据 `AAD`（可选）
- **CFB（Cipher Feedback）**：密码反馈模式，需要设置密钥 `Key` 和初始化向量 `IV`（16 字节）
- **OFB（Output Feedback）**：输出反馈模式，需要设置密钥 `Key` 和初始化向量 `IV`（16 字节）

支持以下填充模式：

- **No**：无填充，明文长度必须是 16 的整数倍
- **Zero**：零填充，用零字节填充到块边界，如果明文长度不是 16 的倍数，则用 0x00 字节填充
- **PKCS7**：PKCS#7 填充，最常用的填充方式，用 N 个值为 N 的字节填充，其中 N 是填充的字节数
- **PKCS5**：PKCS#5 填充，适用于 8 字节块大小，用 N 个值为 N 的字节填充，其中 N 是填充的字节数
- **AnsiX923**：ANSI X.923 填充，除最后一个字节外都用 0x00 填充，最后一个字节表示填充的字节数
- **ISO97971**：ISO/IEC 9797-1 填充，第一个字节为 0x80，其余用 0x00 填充
- **ISO10126**：ISO/IEC 10126 填充，除最后一个字节外都用随机字节填充，最后一个字节表示填充的字节数
- **ISO78164**：ISO/IEC 7816-4 填充，第一个字节为 0x80，其余用 0x00 填充
- **Bit**：位填充，在明文末尾添加一个 1 位，然后用 0 位填充到块边界

> **注意**：仅 `CBC/ECB` 分组模式需要填充

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
c := cipher.NewSm4Cipher(cipher.CBC)
// 设置密钥（16 字节)
c.SetKey([]byte("dongle1234567890"))
// 设置初始化向量（16 字节)
c.SetIV([]byte("1234567890123456"))
// 设置填充模式（可选，默认为 PKCS7，只有 CBC/ECB 分组模式才需要设置填充模式）
c.SetPadding(cipher.PKCS7)          
```

### 加密数据

 输入数据

```go
// 输入字符串
encrypter := dongle.Encrypt.FromString("hello world").BySm4(c)
// 输入字节切片
encrypter := dongle.Encrypt.FromBytes([]byte("hello world")).BySm4(c)
// 输入文件流
file, _ := os.Open("test.txt")
encrypter := dongle.Encrypt.FromFile(file).BySm4(c)

// 检查加密错误
if encrypter.Error != nil {
    fmt.Printf("加密错误: %v\n", encrypter.Error)
    return
}
```

 输出数据

```go
// 输出 Hex 编码字符串
encrypter.ToHexString() // 48c6bc076e1da2946e1c0e59e9c91ae9
// 输出 Hex 编码字节切片
encrypter.ToHexBytes()  // []byte("48c6bc076e1da2946e1c0e59e9c91ae9")

// 输出 Base64 编码字符串
encrypter.ToBase64String() // SMa8B24dopRuHA5Z6cka6Q==
// 输出 Base64 编码字节切片
encrypter.ToBase64Bytes()  // []byte("SMa8B24dopRuHA5Z6cka6Q==")

// 输出未编码原始字符串
encrypter.ToRawString()
// 输出未编码原始字节切片
encrypter.ToRawBytes()
```

### 解密数据

 输入数据

```go
// 输入 Hex 编码字符串
decrypter := dongle.Decrypt.FromHexString(hexString).BySm4(c)
// 输入 Hex 编码字节切片
decrypter := dongle.Decrypt.FromHexBytes(hexBytes).BySm4(c)
// 输入 Hex 编码文件
file, _ := os.Open("encrypted.hex")
decrypter := dongle.Decrypt.FromHexFile(file).BySm4(c)

// 输入 Base64 编码字符串
decrypter := dongle.Decrypt.FromBase64String(base64String).BySm4(c)
// 输入 Base64 编码字节切片
decrypter := dongle.Decrypt.FromBase64Bytes(base64Bytes).BySm4(c)
// 输入 Base64 编码文件流
file, _ := os.Open("encrypted.base64")
decrypter := dongle.Decrypt.FromBase64File(file).BySm4(c)

// 输入原始字符串
decrypter := dongle.Decrypt.FromRawString(rawString).BySm4(c)
// 输入原始字节切片
decrypter := dongle.Decrypt.FromRawBytes(rawBytes).BySm4(c)
// 输入原始文件流
file, _ := os.Open("encrypted.bin")
decrypter := dongle.Decrypt.FromRawFile(file).BySm4(c)

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
c := cipher.NewSm4Cipher(cipher.ECB)
// 设置密钥（16 字节)
c.SetKey([]byte("dongle1234567890"))
// 设置填充模式（可选，默认为 PKCS7，只有 CBC/ECB 分组模式才需要设置填充模式）
c.SetPadding(cipher.PKCS7) 
```

### 加密数据

输入数据
```go
// 输入字符串
encrypter := dongle.Encrypt.FromString("hello world").BySm4(c)
// 输入字节切片
encrypter := dongle.Encrypt.FromBytes([]byte("hello world")).BySm4(c)
// 输入文件流
file, _ := os.Open("test.txt")
encrypter := dongle.Encrypt.FromFile(file).BySm4(c)

// 检查加密错误
if encrypter.Error != nil {
    fmt.Printf("加密错误: %v\n", encrypter.Error)
    return
}
```

输出数据
```go
// 输出 Hex 编码字符串
encrypter.ToHexString() // 48c6bc076e1da2946e1c0e59e9c91ae9
// 输出 Hex 编码字节切片
encrypter.ToHexBytes()  // []byte("48c6bc076e1da2946e1c0e59e9c91ae9")

// 输出 Base64 编码字符串
encrypter.ToBase64String() // SMa8B24dopRuHA5Z6cka6Q==
// 输出 Base64 编码字节切片
encrypter.ToBase64Bytes()  // []byte("SMa8B24dopRuHA5Z6cka6Q==")

// 输出未编码原始字符串
encrypter.ToRawString()
// 输出未编码原始字节切片
encrypter.ToRawBytes() 
```

### 解密数据

输入数据
```go
// 输入 Hex 编码字符串
decrypter := dongle.Decrypt.FromHexString(hexString).BySm4(c)
// 输入 Hex 编码字节切片
decrypter := dongle.Decrypt.FromHexBytes(hexBytes).BySm4(c)
// 输入 Hex 编码文件流
file, _ := os.Open("encrypted.hex")
decrypter := dongle.Decrypt.FromHexFile(file).BySm4(c)

// 输入 Base64 编码字符串
decrypter := dongle.Decrypt.FromBase64String(base64String).BySm4(c)
// 输入 Base64 编码字节切片
decrypter := dongle.Decrypt.FromBase64Bytes(base64Bytes).BySm4(c)
// 输入 Base64 编码文件流
file, _ := os.Open("encrypted.base64")
decrypter := dongle.Decrypt.FromBase64File(file).BySm4(c)

// 输入原始字符串
decrypter := dongle.Decrypt.FromRawString(rawString).BySm4(c)
// 输入原始字节切片
decrypter := dongle.Decrypt.FromRawBytes(rawBytes).BySm4(c)
// 输入原始文件流
file, _ := os.Open("encrypted.bin")
decrypter := dongle.Decrypt.FromRawFile(file).BySm4(c)

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
c := cipher.NewSm4Cipher(cipher.CTR)
// 设置密钥（16 字节)
c.SetKey([]byte("dongle1234567890"))
// 设置初始化向量（12 字节)
c.SetIV([]byte("123456789012"))      
```

### 加密数据

 输入数据
```go
// 输入字符串
encrypter := dongle.Encrypt.FromString("hello world").BySm4(c)
// 输入字节切片
encrypter := dongle.Encrypt.FromBytes([]byte("hello world")).BySm4(c)
// 输入文件流
file, _ := os.Open("test.txt")
encrypter := dongle.Encrypt.FromFile(file).BySm4(c)

// 检查加密错误
if encrypter.Error != nil {
    fmt.Printf("加密错误: %v\n", encrypter.Error)
    return
}
```

 输出数据
```go
// 输出 Hex 编码字符串
encrypter.ToHexString() // 48c6bc076e1da2946e1c0e59e9c91ae9
// 输出 Hex 编码字节切片
encrypter.ToHexBytes()  // []byte("48c6bc076e1da2946e1c0e59e9c91ae9")

// 输出 Base64 编码字符串
encrypter.ToBase64String() // SMa8B24dopRuHA5Z6cka6Q==
// 输出 Base64 编码字节切片
encrypter.ToBase64Bytes()  // []byte("SMa8B24dopRuHA5Z6cka6Q==")

// 输出未编码原始字符串
encrypter.ToRawString()
// 输出未编码原始字节切片
encrypter.ToRawBytes() 
```

### 解密数据

 输入数据

```go
// 输入 Hex 编码字符串
decrypter := dongle.Decrypt.FromHexString(hexString).BySm4(c)
// 输入 Hex 编码字节切片
decrypter := dongle.Decrypt.FromHexBytes(hexBytes).BySm4(c)
// 输入 Hex 编码文件流
file, _ := os.Open("encrypted.hex")
decrypter := dongle.Decrypt.FromHexFile(file).BySm4(c)

// 输入 Base64 编码字符串
decrypter := dongle.Decrypt.FromBase64String(base64String).BySm4(c)
// 输入 Base64 编码字节切片
decrypter := dongle.Decrypt.FromBase64Bytes(base64Bytes).BySm4(c)
// 输入 Base64 编码文件流
file, _ := os.Open("encrypted.base64")
decrypter := dongle.Decrypt.FromBase64File(file).BySm4(c)

// 输入原始字符串
decrypter := dongle.Decrypt.FromRawString(rawString).BySm4(c)
// 输入原始字节切片
decrypter := dongle.Decrypt.FromRawBytes(rawBytes).BySm4(c)
// 输入原始文件流
file, _ := os.Open("encrypted.bin")
decrypter := dongle.Decrypt.FromRawFile(file).BySm4(c)

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

## GCM 模式

GCM 模式提供认证加密功能，支持额外的认证数据（AAD）。

### 创建 Cipher

```go
c := cipher.NewSm4Cipher(cipher.GCM)
// 设置密钥（16 字节)
c.SetKey([]byte("dongle1234567890"))
// 设置随机数（12 字节)
c.SetNonce([]byte("123456789012"))
// 设置额外的认证数据（可选）
c.SetAAD([]byte("additional data")) 
```

### 加密数据

 输入数据
```go
// 输入字符串
encrypter := dongle.Encrypt.FromString("hello world").BySm4(c)
// 输入字节切片
encrypter := dongle.Encrypt.FromBytes([]byte("hello world")).BySm4(c)
// 输入文件流
file, _ := os.Open("test.txt")
encrypter := dongle.Encrypt.FromFile(file).BySm4(c)

// 检查加密错误
if encrypter.Error != nil {
    fmt.Printf("加密错误: %v\n", encrypter.Error)
    return
}
```

 输出数据
```go
// 输出 Hex 编码字符串
encrypter.ToHexString() // 48c6bc076e1da2946e1c0e59e9c91ae9
// 输出 Hex 编码字节切片
encrypter.ToHexBytes()  // []byte("48c6bc076e1da2946e1c0e59e9c91ae9")

// 输出 Base64 编码字符串
encrypter.ToBase64String() // SMa8B24dopRuHA5Z6cka6Q==
// 输出 Base64 编码字节切片
encrypter.ToBase64Bytes()  // []byte("SMa8B24dopRuHA5Z6cka6Q==")

// 输出未编码原始字符串
encrypter.ToRawString()
// 输出未编码原始字节切片
encrypter.ToRawBytes() 
```

### 解密数据

 输入数据

```go
// 输入 Hex 编码字符串
decrypter := dongle.Decrypt.FromHexString(hexString).BySm4(c)
// 输入 Hex 编码字节切片
decrypter := dongle.Decrypt.FromHexBytes(hexBytes).BySm4(c)
// 输入 Hex 编码文件流
file, _ := os.Open("encrypted.hex")
decrypter := dongle.Decrypt.FromHexFile(file).BySm4(c)

// 输入 Base64 编码字符串
decrypter := dongle.Decrypt.FromBase64String(base64String).BySm4(c)
// 输入 Base64 编码字节切片
decrypter := dongle.Decrypt.FromBase64Bytes(base64Bytes).BySm4(c)
// 输入 Base64 编码文件流
file, _ := os.Open("encrypted.base64")
decrypter := dongle.Decrypt.FromBase64File(file).BySm4(c)

// 输入原始字符串
decrypter := dongle.Decrypt.FromRawString(rawString).BySm4(c)
// 输入原始字节切片
decrypter := dongle.Decrypt.FromRawBytes(rawBytes).BySm4(c)
// 输入原始文件流
file, _ := os.Open("encrypted.bin")
decrypter := dongle.Decrypt.FromRawFile(file).BySm4(c)

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

### 创建 Cipher

```go
c := cipher.NewSm4Cipher(cipher.CFB)
// 设置密钥（16 字节)
c.SetKey([]byte("dongle1234567890"))
// 设置初始化向量（16 字节)
c.SetIV([]byte("1234567890123456"))  
```

### 加密数据

 输入数据
```go
// 输入字符串
encrypter := dongle.Encrypt.FromString("hello world").BySm4(c)
// 输入字节切片
encrypter := dongle.Encrypt.FromBytes([]byte("hello world")).BySm4(c)
// 输入文件流
file, _ := os.Open("test.txt")
encrypter := dongle.Encrypt.FromFile(file).BySm4(c)

// 检查加密错误
if encrypter.Error != nil {
    fmt.Printf("加密错误: %v\n", encrypter.Error)
    return
}
```

 输出数据
```go
// 输出 Hex 编码字符串
encrypter.ToHexString() // 48c6bc076e1da2946e1c0e59e9c91ae9
// 输出 Hex 编码字节切片
encrypter.ToHexBytes()  // []byte("48c6bc076e1da2946e1c0e59e9c91ae9")

// 输出 Base64 编码字符串
encrypter.ToBase64String() // SMa8B24dopRuHA5Z6cka6Q==
// 输出 Base64 编码字节切片
encrypter.ToBase64Bytes()  // []byte("SMa8B24dopRuHA5Z6cka6Q==")

// 输出未编码原始字符串
encrypter.ToRawString()
// 输出未编码原始字节切片
encrypter.ToRawBytes() 
```

### 解密数据

 输入数据
```go
// 输入 Hex 编码字符串
decrypter := dongle.Decrypt.FromHexString(hexString).BySm4(c)
// 输入 Hex 编码字节切片
decrypter := dongle.Decrypt.FromHexBytes(hexBytes).BySm4(c)
// 输入 Hex 编码文件流
file, _ := os.Open("encrypted.hex")
decrypter := dongle.Decrypt.FromHexFile(file).BySm4(c)

// 输入 Base64 编码字符串
decrypter := dongle.Decrypt.FromBase64String(base64String).BySm4(c)
// 输入 Base64 编码字节切片
decrypter := dongle.Decrypt.FromBase64Bytes(base64Bytes).BySm4(c)
// 输入 Base64 编码文件流
file, _ := os.Open("encrypted.base64")
decrypter := dongle.Decrypt.FromBase64File(file).BySm4(c)

// 输入原始字符串
decrypter := dongle.Decrypt.FromRawString(rawString).BySm4(c)
// 输入原始字节切片
decrypter := dongle.Decrypt.FromRawBytes(rawBytes).BySm4(c)
// 输入原始文件流
file, _ := os.Open("encrypted.bin")
decrypter := dongle.Decrypt.FromRawFile(file).BySm4(c)

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

### 创建 Cipher

```go
c := cipher.NewSm4Cipher(cipher.OFB)
// 设置密钥（16 字节)
c.SetKey([]byte("dongle1234567890"))
// 设置初始化向量（16 字节)
c.SetIV([]byte("1234567890123456"))  
```

### 加密数据

 输入数据
```go
// 输入字符串
encrypter := dongle.Encrypt.FromString("hello world").BySm4(c)
// 输入字节切片
encrypter := dongle.Encrypt.FromBytes([]byte("hello world")).BySm4(c)
// 输入文件流
file, _ := os.Open("test.txt")
encrypter := dongle.Encrypt.FromFile(file).BySm4(c)

// 检查加密错误
if encrypter.Error != nil {
    fmt.Printf("加密错误: %v\n", encrypter.Error)
    return
}
```

 输出数据
```go
// 输出 Hex 编码字符串
encrypter.ToHexString() // 48c6bc076e1da2946e1c0e59e9c91ae9
// 输出 Hex 编码字节切片
encrypter.ToHexBytes()  // []byte("48c6bc076e1da2946e1c0e59e9c91ae9")

// 输出 Base64 编码字符串
encrypter.ToBase64String() // SMa8B24dopRuHA5Z6cka6Q==
// 输出 Base64 编码字节切片
encrypter.ToBase64Bytes()  // []byte("SMa8B24dopRuHA5Z6cka6Q==")

// 输出未编码原始字符串
encrypter.ToRawString()
// 输出未编码原始字节切片
encrypter.ToRawBytes() 
```

### 解密数据

 输入数据

```go
// 输入 Hex 编码字符串
decrypter := dongle.Decrypt.FromHexString(hexString).BySm4(c)
// 输入 Hex 编码字节切片
decrypter := dongle.Decrypt.FromHexBytes(hexBytes).BySm4(c)
// 输入 Hex 编码文件流
file, _ := os.Open("encrypted.hex")
decrypter := dongle.Decrypt.FromHexFile(file).BySm4(c)

// 输入 Base64 编码字符串
decrypter := dongle.Decrypt.FromBase64String(base64String).BySm4(c)
// 输入 Base64 编码字节切片
decrypter := dongle.Decrypt.FromBase64Bytes(base64Bytes).BySm4(c)
// 输入 Base64 编码文件流
file, _ := os.Open("encrypted.base64")
decrypter := dongle.Decrypt.FromBase64File(file).BySm4(c)

// 输入原始字符串
decrypter := dongle.Decrypt.FromRawString(rawString).BySm4(c)
// 输入原始字节切片
decrypter := dongle.Decrypt.FromRawBytes(rawBytes).BySm4(c)
// 输入原始文件流
file, _ := os.Open("encrypted.bin")
decrypter := dongle.Decrypt.FromRawFile(file).BySm4(c)

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


