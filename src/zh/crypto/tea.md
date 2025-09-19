---
head:
  - - meta
    - name: description
      content: TEA 加密算法|一个轻量级、语义化、对开发者友好的 golang 编码&密码库
  - - meta
    - name: keywords
      content: tea, 加密, 解密, 对称加密, 分组密码
---

# TEA

TEA（Tiny Encryption Algorithm）是一种简单高效的分组密码算法，使用固定长度的 `16` 字节密钥对数据进行加密和解密。`dongle` 支持标准 `TEA` 加密，提供多种输入格式、输出格式和流式处理能力。

TEA 是一种对称加密算法，加密和解密使用相同的密钥。TEA 使用 `8` 字节的数据块进行加密，数据长度必须是 `8` 的倍数。

 注意事项

- **密钥长度**：TEA 密钥必须是 `16` 字节
- **数据长度**：输入数据长度必须是 `8` 字节的倍数
- **轮数设置**：支持自定义轮数，默认 `64` 轮，常用的还有 `32` 轮
- **数据对齐**：如果数据长度不是 `8` 的倍数，需要手动填充
- **安全性**：TEA 算法相对简单，适合对性能要求较高但安全性要求不是极高的场景

导入相关模块：
```go
import (
    "github.com/dromara/dongle"
    "github.com/dromara/dongle/crypto/cipher"
)
```

## 创建 Cipher

```go
c := cipher.NewTeaCipher()
// 设置密钥（必须是 16 字节）
c.SetKey([]byte("dongle1234567890"))
// 设置轮数（可选，默认 64 轮）
c.SetRounds(64)
```

## 加密数据

 输入数据

```go
// 输入字符串（必须是 8 字节的倍数）
encrypter := dongle.Encrypt.FromString("12345678").ByTea(c)
// 输入字节切片（必须是 8 字节的倍数）
encrypter := dongle.Encrypt.FromBytes([]byte("12345678")).ByTea(c)
// 输入文件流
file, _ := os.Open("test.txt")
encrypter := dongle.Encrypt.FromFile(file).ByTea(c)

// 检查加密错误
if encrypter.Error != nil {
	fmt.Printf("加密错误: %v\n", encrypter.Error)
	return
}
```

 输出数据

```go
// 输出 Hex 编码字符串
hexString := encrypter.ToHexString() // a97fc8fdda9bebc7
// 输出 Hex 编码字节切片
hexBytes := encrypter.ToHexBytes()   // []byte("a97fc8fdda9bebc7")

// 输出 Base64 编码字符串
base64String := encrypter.ToBase64String() // qX/I/dqb68c=
// 输出 Base64 编码字节切片
base64Bytes := encrypter.ToBase64Bytes()   // []byte("qX/I/dqb68c=")

// 输出未编码原始字符串
rawString := encrypter.ToRawString()
// 输出未编码原始字节切片
rawBytes := encrypter.ToRawBytes()
```

## 解密数据

 输入数据

```go
// 输入 Hex 编码字符串
decrypter := dongle.Decrypt.FromHexString(hexString).ByTea(c)
// 输入 Hex 编码字节切片
decrypter := dongle.Decrypt.FromHexBytes(hexBytes).ByTea(c)
// 输入 Hex 编码文件流
file, _ := os.Open("encrypted.hex")
decrypter := dongle.Decrypt.FromHexFile(file).ByTea(c)

// 输入 Base64 编码字符串
decrypter := dongle.Decrypt.FromBase64String(base64String).ByTea(c)
// 输入 Base64 编码字节切片
decrypter := dongle.Decrypt.FromBase64Bytes(base64Bytes).ByTea(c)
// 输入 Base64 编码文件流
file, _ := os.Open("encrypted.base64")
decrypter := dongle.Decrypt.FromBase64File(file).ByTea(c)

// 输入未编码原始字符串
decrypter := dongle.Decrypt.FromRawString(rawString).ByTea(c)
// 输入未编码原始字节切片
decrypter := dongle.Decrypt.FromRawBytes(rawBytes).ByTea(c)
// 输入未编码原始文件流
file, _ := os.Open("encrypted.bin") 
decrypter := dongle.Decrypt.FromRawFile(file).ByTea(c)

// 检查解密错误
if decrypter.Error != nil {
	fmt.Printf("解密错误: %v\n", decrypter.Error)
	return
}
```

 输出数据

```go
// 输出解密后的字符串
decrypter.ToString() // 12345678
// 输出解密后的字节切片
decrypter.ToBytes()  // []byte("12345678")
```