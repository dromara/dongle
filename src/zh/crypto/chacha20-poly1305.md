---
head:
  - - meta
    - name: description
      content: ChaCha20-Poly1305 加密算法|一个轻量级、语义化、对开发者友好的 golang 编码&密码库
  - - meta
    - name: keywords
      content: chacha20-poly1305, 加密, 解密, 认证加密, AEAD, 对称加密
---

# ChaCha20-Poly1305

ChaCha20-Poly1305 是一种现代高性能的认证加密算法(AEAD)，结合了 `ChaCha20` 流密码和 `Poly1305` 消息认证码。使用固定长度的 `32` 字节密钥和 `12` 字节随机数对数据进行加密和认证。`dongle` 支持标准和流式 `ChaCha20-Poly1305` 加密，提供多种输入格式、输出格式和流式处理能力。

ChaCha20-Poly1305 是一种对称加密算法，加密和解密使用相同的密钥。作为 `AEAD` 算法，它不仅提供机密性保护，还提供完整性和真实性验证，能够检测数据篡改。

注意事项

- **密钥长度**：ChaCha20-Poly1305 密钥必须是 `32` 字节
- **随机数长度**：ChaCha20-Poly1305 随机数必须是 `12` 字节
- **附加数据**：可选的附加认证数据(AAD)，用于验证但不加密
- **认证标签**：加密后的数据包含 `16` 字节的认证标签
- **随机数唯一性**：每个密钥下的随机数必须唯一，不可重复使用
- **安全性**：ChaCha20-Poly1305 提供高安全性，被 `TLS1.3` 等标准广泛采用

导入相关模块：
```go
import (
    "github.com/dromara/dongle"
    "github.com/dromara/dongle/crypto/cipher"
)
```

## 创建 Cipher

```go
c := cipher.NewChaCha20Poly1305Cipher()
// 设置密钥（必须是 32 字节）
c.SetKey([]byte("dongle1234567890abcdef123456789x"))
// 设置随机数（必须是 12 字节）
c.SetNonce([]byte("123456789012"))
// 设置附加认证数据（可选）
c.SetAAD([]byte("additional authenticated data"))
```

## 加密数据

输入数据

```go
// 输入字符串
encrypter := dongle.Encrypt.FromString("hello world").ByChaCha20Poly1305(c)
// 输入字节切片
encrypter := dongle.Encrypt.FromBytes([]byte("hello world")).ByChaCha20Poly1305(c)
// 输入文件流
file, _ := os.Open("test.txt")
encrypter := dongle.Encrypt.FromFile(file).ByChaCha20Poly1305(c)

// 检查加密错误
if encrypter.Error != nil {
	fmt.Printf("加密错误: %v\n", encrypter.Error)
	return
}
```

输出数据

```go
// 输出 Hex 编码字符串
hexString := encrypter.ToHexString() // 4a1c8f2d3e5a6b7c...
// 输出 Hex 编码字节切片
hexBytes := encrypter.ToHexBytes()   // []byte("4a1c8f2d3e5a6b7c...")

// 输出 Base64 编码字符串
base64String := encrypter.ToBase64String() // ShyPLT5aa3w=...
// 输出 Base64 编码字节切片
base64Bytes := encrypter.ToBase64Bytes()   // []byte("ShyPLT5aa3w=...")

// 输出未编码原始字符串
rawString := encrypter.ToRawString()
// 输出未编码原始字节切片
rawBytes := encrypter.ToRawBytes()
```

## 解密数据

输入数据

```go
// 输入 Hex 编码字符串
decrypter := dongle.Decrypt.FromHexString(hexString).ByChaCha20Poly1305(c)
// 输入 Hex 编码字节切片
decrypter := dongle.Decrypt.FromHexBytes(hexBytes).ByChaCha20Poly1305(c)
// 输入 Hex 编码文件流
file, _ := os.Open("encrypted.hex")
decrypter := dongle.Decrypt.FromHexFile(file).ByChaCha20Poly1305(c)

// 输入 Base64 编码字符串
decrypter := dongle.Decrypt.FromBase64String(base64String).ByChaCha20Poly1305(c)
// 输入 Base64 编码字节切片
decrypter := dongle.Decrypt.FromBase64Bytes(base64Bytes).ByChaCha20Poly1305(c)
// 输入 Base64 编码文件流
file, _ := os.Open("encrypted.base64")
decrypter := dongle.Decrypt.FromBase64File(file).ByChaCha20Poly1305(c)

// 输入未编码原始字符串
decrypter := dongle.Decrypt.FromRawString(rawString).ByChaCha20Poly1305(c)
// 输入未编码原始字节切片
decrypter := dongle.Decrypt.FromRawBytes(rawBytes).ByChaCha20Poly1305(c)
// 输入未编码原始文件流
file, _ := os.Open("encrypted.bin") 
decrypter := dongle.Decrypt.FromRawFile(file).ByChaCha20Poly1305(c)

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