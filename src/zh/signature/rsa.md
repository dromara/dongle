---
title: RSA 数字签名算法
head:
  - - meta
    - name: description
      content: RSA 数字签名算法，支持 PKCS1 和 PKCS8 密钥格式，支持多种哈希算法，使用私钥进行签名、公钥进行验证，支持标准和流式处理，支持 Hex 和 Base64 输出格式
  - - meta
    - name: keywords
      content: dongle, go-dongle, 签名, 验证, RSA, 数字签名算法, 非对称加密, 私钥签名, 公钥验证, PKCS1, PKCS8, PSS, PKCS1v15, 哈希算法, Hex, Base64
---

# RSA

RSA 数字签名是一种基于非对称加密的数字签名算法，使用私钥进行签名，公钥进行验证。`dongle` 支持标准和流式 `RSA` 数字签名，提供多种密钥格式、哈希算法和输出格式。

支持以下密钥格式：

- **PKCS1**：PKCS#1 格式，使用 `PKCS1v15` 填充模式，`无需`指定哈希算法
- **PKCS8**：PKCS#8 格式，使用 `PSS` 填充模式，`必须`指定哈希算法，提供更好的安全性

支持以下哈希算法：

- **MD4**：MD4 哈希算法（不推荐用于生产环境）
- **MD5**：MD5 哈希算法（不推荐用于生产环境）
- **SHA1**：SHA-1 哈希算法（不推荐用于生产环境）
- **SHA224**：SHA-224 哈希算法
- **SHA256**：SHA-256 哈希算法（推荐）
- **SHA384**：SHA-384 哈希算法
- **SHA512**：SHA-512 哈希算法
- **MD5SHA1**：MD5-SHA1 哈希算法
- **RIPEMD160**：RIPEMD160 哈希算法
- **SHA3_224**：SHA3_224 哈希算法
- **SHA3_256**：SHA3_256 哈希算法
- **SHA3_384**：SHA3_384 哈希算法
- **SHA3_512**：SHA3_512 哈希算法
- **SHA512_224**：SHA512_224 哈希算法
- **SHA512_256**：SHA512_256 哈希算法
- **BLAKE2s_256**：BLAKE2s_256 哈希算法
- **BLAKE2b_256**：BLAKE2b_256 哈希算法
- **BLAKE2b_384**：BLAKE2b_384 哈希算法
- **BLAKE2b_512**：BLAKE2b_512 哈希算法

注意事项：

- **密钥长度**：推荐使用 `2048` 位或更长的密钥长度以确保安全性
- **密钥格式**：推荐使用 `PKCS8` 格式，它使用更安全的 `PSS` 填充模式
- **哈希算法**：推荐使用 `SHA256` 或更强的哈希算法，避免使用 `MD5` 和 `SHA1`
- **私钥安全**：私钥必须妥善保管，不能泄露，只有私钥持有者才能生成有效签名
- **签名验证**：任何人都可以使用公钥验证签名的有效性

导入相关模块：
```go
import (
    "crypto"
    "github.com/dromara/dongle"
    "github.com/dromara/dongle/crypto/keypair"
)
```

## 创建密钥对
```go
kp := keypair.NewRsaKeyPair()
// 设置密钥格式（可选，默认为 PKCS8）
kp.SetFormat(keypair.PKCS8)
// 设置哈希算法（可选，默认为 SHA256，只有 PKCS8 密钥格式才需要设置哈希算法）
kp.SetHash(crypto.SHA256)   
```

### 生成密钥对

```go
// 生成 2048 位密钥对
err := kp.GenKeyPair(2048)
if err != nil {
    panic(err)
}

// 获取 PEM 格式公钥
publicKey := kp.PublicKey  
// 获取 PEM 格式私钥
privateKey := kp.PrivateKey
```

### 从已有 PEM 格式密钥设置密钥对

```go
// 设置 PEM 格式公钥
kp.PublicKey = []byte(`-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCqzZNa9VrcewyU6wDoV7Y9kAHq
X1VK0B3Rb6GNmQe4zLEfce7cVTaLrc4VGTKl35tADG1cRHqtaG4S/WttpiGZBhxJ
y4MpOXb6eIPiVLsn2lL+rJo5XdbSr3gyjxEOQQ97ihtw4lDd5wMo4bIOuw1LtMez
HC1outlM6x+/BB0BSQIDAQAB
-----END PUBLIC KEY-----`)

// 设置 PEM 格式私钥
kp.PrivateKey = []byte(`-----BEGIN PRIVATE KEY-----
MIICdQIBADANBgkqhkiG9w0BAQEFAASCAl8wggJbAgEAAoGBAKrNk1r1Wtx7DJTr
AOhXtj2QAepfVUrQHdFvoY2ZB7jMsR9x7txVNoutzhUZMqXfm0AMbVxEeq1obhL9
a22mIZkGHEnLgyk5dvp4g+JUuyfaUv6smjld1tKveDKPEQ5BD3uKG3DiUN3nAyjh
sg67DUu0x7McLWi62UzrH78EHQFJAgMBAAECgYAeo3nHWzPNURVUsUMcan96U5bE
YA2AugxfQVMNf2HvOGidZ2adh3udWrQY/MglERNcTd5gKriG2rDEH0liBecIrNKs
BL4lV+qHEGRUcnDDdtUBdGInEU8lve5keDgmX+/huXSRJ+3tYA5u9j+32RquVczv
Idtb5XnBLUl61k0osQJBAON5+eJjtw6xpn+pveU92BSHvaJYVyrLHwUjR07aNKb7
GlGVM3MGf1FCa8WQUo9uUzYxGLtg5Qf3sqwOrwPd5UsCQQDAOF/zWqGuY3HfV/1w
giXiWp8rc+S8tanMj5M37QQbYW5YLjUmJImoklVahv3qlgLZdEN5ZSueM5jfoSFt
Nts7AkBKoRDvSiGbi4MBbTHkzLZgfewkH/FxE7S4nctePk553fXTgCyh9ya8BRuQ
dHnxnpNkOxVPHEnnpEcVFbgrf5gjAkB7KmRI4VTiEfRgINhTJAG0VU7SH/N7+4cuf
PzfA+7ywG5c8Fa79wOB0SoB1KeUjcSLo5Ssj2fwea1F9dAeU90LAkBJQFofveaD
a3YlN4EQZOcCvJKmg7xwWuGxFVTZDVVEws7UCQbEOEEXZrNd9x0IF5kpPLR+rxua
RPgUNaDGIh5o
-----END PRIVATE KEY-----`)
```

### 从已有 DER 格式密钥设置密钥对

```go
// 设置经过 base64 编码的 DER 格式公钥
kp.SetPublicKey([]byte("MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCqzZNa9VrcewyU6wDoV7Y9kAHqX1VK0B3Rb6GNmQe4zLEfce7cVTaLrc4VGTKl35tADG1cRHqtaG4S/WttpiGZBhxJy4MpOXb6eIPiVLsn2lL+rJo5XdbSr3gyjxEOQQ97ihtw4lDd5wMo4bIOuw1LtMezHC1outlM6x+/BB0BSQIDAQAB"))
// 设置经过 base64 编码的 DER 格式私钥
kp.SetPrivateKey([]byte("MIICdQIBADANBgkqhkiG9w0BAQEFAASCAl8wggJbAgEAAoGBAKrNk1r1Wtx7DJTrAOhXtj2QAepfVUrQHdFvoY2ZB7jMsR9x7txVNoutzhUZMqXfm0AMbVxEeq1obhL9a22mIZkGHEnLgyk5dvp4g+JUuyfaUv6smjld1tKveDKPEQ5BD3uKG3DiUN3nAyjhsg67DUu0x7McLWi62UzrH78EHQFJAgMBAAECgYAeo3nHWzPNURVUsUMcan96U5bEYA2AugxfQVMNf2HvOGidZ2adh3udWrQY/MglERNcTd5gKriG2rDEH0liBecIrNKsBL4lV+qHEGRUcnDDdtUBdGInEU8lve5keDgmX+/huXSRJ+3tYA5u9j+32RquVczvIdtb5XnBLUl61k0osQJBAON5+eJjtw6xpn+pveU92BSHvaJYVyrLHwUjR07aNKb7GlGVM3MGf1FCa8WQUo9uUzYxGLtg5Qf3sqwOrwPd5UsCQQDAOF/zWqGuY3HfV/1wgiXiWp8rc+S8tanMj5M37QQbYW5YLjUmJImoklVahv3qlgLZdEN5ZSueM5jfoSFtNts7AkBKoRDvSiGbi4MBbTHkzLZgfewkH/FxE7S4nctePk553fXTgCyh9ya8BRuQdHnxnpNkOxVPHEnnpEcVFbgrf5gjAkB7KmRI4VTiEfRgINhTJAG0VU7SH/N7+4cufPzfA+7ywG5c8Fa79wOB0SoB1KeUjcSLo5Ssj2fwea1F9dAeU90LAkBJQFofveaDa3YlN4EQZOcCvJKmg7xwWuGxFVTZDVVEws7UCQbEOEEXZrNd9x0IF5kpPLR+rxuaRPgUNaDGIh5o"))
```

### 将 `DER` 格式密钥格式化成 `PEM` 格式

```go
// 将 base64 编码的 DER 格式公钥格式化为 PEM 格式
publicKey, err := kp.FormatPublicKey([]byte("MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCqzZNa9VrcewyU6wDoV7Y9kAHqX1VK0B3Rb6GNmQe4zLEfce7cVTaLrc4VGTKl35tADG1cRHqtaG4S/WttpiGZBhxJy4MpOXb6eIPiVLsn2lL+rJo5XdbSr3gyjxEOQQ97ihtw4lDd5wMo4bIOuw1LtMezHC1outlM6x+/BB0BSQIDAQAB"))

// 将 base64 编码的 DER 格式私钥格式化为 PEM 格式
privateKey, err :=kp.FormatPrivateKey([]byte("+JUuyfaUv6smjld1tKveDKPEQ5BD3uKG3DiUN3nAyjhsg67DUu0x7McLWi62UzrH78EHQFJAgMBAAECgYAeo3nHWzPNURVUsUMcan96U5bEYA2AugxfQVMNf2HvOGidZ2adh3udWrQY/MglERNcTd5gKriG2rDEH0liBecIrNKsBL4lV+qHEGRUcnDDdtUBdGInEU8lve5keDgmX+/huXSRJ+3tYA5u9j+32RquVczvIdtb5XnBLUl61k0osQJBAON5+eJjtw6xpn+pveU92BSHvaJYVyrLHwUjR07aNKb7GlGVM3MGf1FCa8WQUo9uUzYxGLtg5Qf3sqwOrwPd5UsCQQDAOF/zWqGuY3HfV/1wgiXiWp8rc+S8tanMj5M37QQbYW5YLjUmJImoklVahv3qlgLZdEN5ZSueM5jfoSFtNts7AkBKoRDvSiGbi4MBbTHkzLZgfewkH/FxE7S4nctePk553fXTgCyh9ya8BRuQdHnxnpNkOxVPHEnnpEcVFbgrf5gjAkB7KmRI4VTiEfRgINhTJAG0VU7SH/N7+4cufPzfA+7ywG5c8Fa79wOB0SoB1KeUjcSLo5Ssj2fwea1F9dAeU90LAkBJQFofveaDa3YlN4EQZOcCvJKmg7xwWuGxFVTZDVVEws7UCQbEOEEXZrNd9x0IF5kpPLR+rxuaRPgUNaDGIh5o"))
```

### 将 `PEM` 格式密钥压缩成 `DER` 格式

```go
// 将 PEM 格式公钥压缩成经过 base64 编码的 DER 格式(去掉 PEM 格式公钥的头尾和换行符)
publicKey, err := kp.CompressPublicKey([]byte(`-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCqzZNa9VrcewyU6wDoV7Y9kAHq
X1VK0B3Rb6GNmQe4zLEfce7cVTaLrc4VGTKl35tADG1cRHqtaG4S/WttpiGZBhxJ
y4MpOXb6eIPiVLsn2lL+rJo5XdbSr3gyjxEOQQ97ihtw4lDd5wMo4bIOuw1LtMez
HC1outlM6x+/BB0BSQIDAQAB
-----END PUBLIC KEY-----`))

// 将 PEM 格式私钥压缩成经过 base64 编码的 DER 格式(去掉 PEM 格式私钥的头尾和换行符)
privateKey, err :=kp.CompressPrivateKey([]byte(`-----BEGIN PRIVATE KEY-----
MIICdQIBADANBgkqhkiG9w0BAQEFAASCAl8wggJbAgEAAoGBAKrNk1r1Wtx7DJTr
AOhXtj2QAepfVUrQHdFvoY2ZB7jMsR9x7txVNoutzhUZMqXfm0AMbVxEeq1obhL9
a22mIZkGHEnLgyk5dvp4g+JUuyfaUv6smjld1tKveDKPEQ5BD3uKG3DiUN3nAyjh
sg67DUu0x7McLWi62UzrH78EHQFJAgMBAAECgYAeo3nHWzPNURVUsUMcan96U5bE
YA2AugxfQVMNf2HvOGidZ2adh3udWrQY/MglERNcTd5gKriG2rDEH0liBecIrNKs
BL4lV+qHEGRUcnDDdtUBdGInEU8lve5keDgmX+/huXSRJ+3tYA5u9j+32RquVczv
Idtb5XnBLUl61k0osQJBAON5+eJjtw6xpn+pveU92BSHvaJYVyrLHwUjR07aNKb7
GlGVM3MGf1FCa8WQUo9uUzYxGLtg5Qf3sqwOrwPd5UsCQQDAOF/zWqGuY3HfV/1w
giXiWp8rc+S8tanMj5M37QQbYW5YLjUmJImoklVahv3qlgLZdEN5ZSueM5jfoSFt
Nts7AkBKoRDvSiGbi4MBbTHkzLZgfewkH/FxE7S4nctePk553fXTgCyh9ya8BRuQ
dHnxnpNkOxVPHEnnpEcVFbgrf5gjAkB7KmRI4VTiEfRgINhTJAG0VU7SH/N7+4cuf
PzfA+7ywG5c8Fa79wOB0SoB1KeUjcSLo5Ssj2fwea1F9dAeU90LAkBJQFofveaD
a3YlN4EQZOcCvJKmg7xwWuGxFVTZDVVEws7UCQbEOEEXZrNd9x0IF5kpPLR+rxua
RPgUNaDGIh5o
-----END PRIVATE KEY-----`))
```

## 私钥签名

### 输入数据

```go
// 输入字符串
signer := dongle.Sign.FromString("hello world").ByRsa(kp)
// 输入字节切片
signer := dongle.Sign.FromBytes([]byte("hello world")).ByRsa(kp)
// 输入文件流
file, _ := os.Open("test.txt")
signer := dongle.Sign.FromFile(file).ByRsa(kp)

// 检查签名错误
if signer.Error != nil {
	fmt.Printf("签名错误: %v\n", signer.Error)
	return
}
```

### 输出数据

```go
// 输出 Hex 编码签名字符串
hexString := signer.ToHexString() // 7fae94fd1a8b880d8d5454dd8df30c40...
// 输出 Hex 编码签名字节切片
hexBytes := signer.ToHexBytes()  // []byte("7fae94fd1a8b880d8d5454dd8df30c40...")

// 输出 Base64 编码签名字符串
base64String := signer.ToBase64String() // f66U/RqLiA2NVFTdjfMMQA==...
// 输出 Base64 编码签名字节切片
base64Bytes := signer.ToBase64Bytes()  // []byte("f66U/RqLiA2NVFTdjfMMQA==...")

// 输出未编码原始签名字符串
rawString := signer.ToRawString()
// 输出未编码原始签名字节切片
rawBytes := signer.ToRawBytes()
```

## 公钥验证

> 注意：`WithXxxSign` 方法必须在 `ByRsa` 之前调用

### 输入数据

```go
// 输入字符串
verifier := dongle.Verify.FromString("hello world")
// 输入字节切片
verifier := dongle.Verify.FromBytes([]byte("hello world"))
// 输入文件流
file, _ := os.Open("test.txt")
verifier := dongle.Verify.FromFile(file)

// 设置 Hex 编码签名
verifier.WithHexSign(rawBytes).ByRsa(kp)
// 设置 Base64 编码签名
verifier.WithBase64Sign(rawBytes).ByRsa(kp)
// 设置未编码原始签名
verifier.WithRawSign(rawBytes).ByRsa(kp)

// 检查验证错误
if verifier.Error != nil {
    fmt.Printf("验证错误: %v\n", verifier.Error)
    return
}
```

### 输出数据
```go
// 输出验证结果
verifier.ToBool() // true 或 false
```


