---
head:
  - - meta
    - name: description
      content: RSA 加密算法|一个轻量级、语义化、对开发者友好的 golang 编码&密码库
  - - meta
    - name: keywords
      content: rsa, 加密, 解密, 签名, 验证, 非对称加密, 公钥加密
---

# RSA

RSA 是一种非对称加密算法，使用公钥进行加密，私钥进行解密。`dongle` 支持标准 `RSA` 加密，提供多种密钥格式、哈希算法和输出格式。

支持以下密钥格式：

- **PKCS1**：PKCS#1 格式，使用 `PKCS1v15` 填充模式，`无需`指定哈希算法
- **PKCS8**：PKCS#8 格式，使用 `PSS` 填充模式，`需要`指定哈希算法，提供更好的安全性

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
- **密钥格式**：推荐使用 `PKCS8` 格式，它使用更安全的 `OAEP` 填充模式
- **哈希算法**：推荐使用 `SHA256` 或更强的哈希算法，避免使用 `MD5` 和 `SHA1`
- **数据长度限制**：RSA 加密的数据长度受密钥长度限制，对于大量数据建议使用混合加密
- **私钥安全**：私钥必须妥善保管，不能泄露

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
// 设置哈希算法（可选，默认为 SHA256）
kp.SetHash(crypto.SHA256)   
```

### 生成密钥对

```go
// 生成 2048 位密钥对
kp.GenKeyPair(2048)

// 获取 PEM 格式公钥
publicKey := kp.PublicKey  
// 获取 PEM 格式私钥
privateKey := kp.PrivateKey
```

### 从已有 PEM 密钥设置密钥对

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

### 从已有 PEM 密钥文件加载密钥对

```go
// 从 PEM 文件加载公钥
publicKeyFile, _ := os.Open("public_key.pem")
kp.LoadPublicKey(publicKeyFile)

// 从 PEM 文件加载私钥
privateKeyFile, _ := os.Open("private_key.pem")
kp.LoadPrivateKey(privateKeyFile)
```

### 从已有字符串密钥设置密钥对

```go
// 设置字符串格式公钥，会自动转换成对应的 PEM 格式公钥
kp.SetPublicKey([]byte("MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCqzZNa9VrcewyU6wDoV7Y9kAHqX1VK0B3Rb6GNmQe4zLEfce7cVTaLrc4VGTKl35tADG1cRHqtaG4S/WttpiGZBhxJy4MpOXb6eIPiVLsn2lL+rJo5XdbSr3gyjxEOQQ97ihtw4lDd5wMo4bIOuw1LtMezHC1outlM6x+/BB0BSQIDAQAB"))
// 设置字符串格式私钥，会自动转换成对应的 PEM 格式私钥
kp.SetPrivateKey([]byte("MIICdQIBADANBgkqhkiG9w0BAQEFAASCAl8wggJbAgEAAoGBAKrNk1r1Wtx7DJTrAOhXtj2QAepfVUrQHdFvoY2ZB7jMsR9x7txVNoutzhUZMqXfm0AMbVxEeq1obhL9a22mIZkGHEnLgyk5dvp4g+JUuyfaUv6smjld1tKveDKPEQ5BD3uKG3DiUN3nAyjhsg67DUu0x7McLWi62UzrH78EHQFJAgMBAAECgYAeo3nHWzPNURVUsUMcan96U5bEYA2AugxfQVMNf2HvOGidZ2adh3udWrQY/MglERNcTd5gKriG2rDEH0liBecIrNKsBL4lV+qHEGRUcnDDdtUBdGInEU8lve5keDgmX+/huXSRJ+3tYA5u9j+32RquVczvIdtb5XnBLUl61k0osQJBAON5+eJjtw6xpn+pveU92BSHvaJYVyrLHwUjR07aNKb7GlGVM3MGf1FCa8WQUo9uUzYxGLtg5Qf3sqwOrwPd5UsCQQDAOF/zWqGuY3HfV/1wgiXiWp8rc+S8tanMj5M37QQbYW5YLjUmJImoklVahv3qlgLZdEN5ZSueM5jfoSFtNts7AkBKoRDvSiGbi4MBbTHkzLZgfewkH/FxE7S4nctePk553fXTgCyh9ya8BRuQdHnxnpNkOxVPHEnnpEcVFbgrf5gjAkB7KmRI4VTiEfRgINhTJAG0VU7SH/N7+4cufPzfA+7ywG5c8Fa79wOB0SoB1KeUjcSLo5Ssj2fwea1F9dAeU90LAkBJQFofveaDa3YlN4EQZOcCvJKmg7xwWuGxFVTZDVVEws7UCQbEOEEXZrNd9x0IF5kpPLR+rxuaRPgUNaDGIh5o"))
```

## 公钥加密

输入数据
```go
// 输入字符串
encrypter := dongle.Encrypt.FromString("hello world").ByRsa(kp)
// 输入字节切片
encrypter := dongle.Encrypt.FromBytes([]byte("hello world")).ByRsa(kp)
// 输入文件流
file, _ := os.Open("test.txt")
encrypter := dongle.Encrypt.FromFile(file).ByRsa(kp)

// 检查加密错误
if encrypter.Error != nil {
	fmt.Printf("加密错误: %v\n", encrypter.Error)
	return
}
```

输出数据
```go
// 输出 Hex 编码字符串
hexString := encrypter.ToHexString() // 例如：7fae94fd1a8b880d8d5454dd8df30c40...
// 输出 Hex 编码字节切片
hexBytes := encrypter.ToHexBytes()  // 例如：[]byte("7fae94fd1a8b880d8d5454dd8df30c40...")

// 输出 Base64 编码字符串
base64String := encrypter.ToBase64String() // 例如：f66U/RqLiA2NVFTdjfMMQA==...
// 输出 Base64 编码字节切片
base64Bytes := encrypter.ToBase64Bytes()  // 例如：[]byte("f66U/RqLiA2NVFTdjfMMQA==...")

// 输出未编码原始字符串
rawString := encrypter.ToRawString()
// 输出未编码原始字节切片
rawBytes := encrypter.ToRawBytes()  
```
## 私钥解密

输入数据
```go
// 输入 Hex 编码字符串
decrypter := dongle.Decrypt.FromHexString(hexString).ByRsa(kp)
// 输入 Hex 编码字节切片
decrypter := dongle.Decrypt.FromHexBytes(hexBytes).ByRsa(kp)
// 输入 Hex 编码文件流
file, _ := os.Open("encrypted.hex")
decrypter := dongle.Decrypt.FromHexFile(file).ByRsa(kp)

// 输入 Base64 编码字符串
decrypter := dongle.Decrypt.FromBase64String(base64String).ByRsa(kp)
// 输入 Base64 编码字节切片
decrypter := dongle.Decrypt.FromBase64Bytes(base64Bytes).ByRsa(kp)
// 输入 Base64 编码文件流
file, _ := os.Open("encrypted.base64")
decrypter := dongle.Decrypt.FromBase64File(file).ByRsa(kp)

// 输入原始字符串
decrypter := dongle.Decrypt.FromRawString(rawString).ByRsa(kp)
// 输入原始字节切片
decrypter := dongle.Decrypt.FromRawBytes(rawBytes).ByRsa(kp)
// 输入原始文件流
file, _ := os.Open("encrypted.bin")
decrypter := dongle.Decrypt.FromRawFile(file).ByRsa(kp)

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
decrypter.ToBytes() // []byte("hello world")
```