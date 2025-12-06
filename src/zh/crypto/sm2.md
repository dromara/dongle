---
title: SM2 非对称椭圆曲线加密算法
head:
  - - meta
    - name: description
      content: SM2 非对称加密算法，中国国家密码管理局制定的国产商用密码算法，基于椭圆曲线密码学，支持 C1C3C2 和 C1C2C3 两种密文顺序，使用公钥加密私钥解密，支持标准和流式处理，支持 Hex 和 Base64 输出格式
  - - meta
    - name: keywords
      content: dongle, go-dongle, 加密, 解密, SM2, 非对称加密算法, 公钥加密, 私钥解密, 国密算法, 椭圆曲线, C1C3C2, C1C2C3, PKCS8, SPKI
---

# SM2

SM2 是由中国国家密码管理局制定的椭圆曲线公钥密码算法（GM/T 0003-2012），是中国商用密码标准的核心算法之一。`dongle` 支持标准和流式 `SM2` 加密，提供多种密文格式和性能优化选项。

支持以下密文格式：

- **C1C3C2**：国密标准推荐格式（默认），密文结构为 `0x04 || C1(64字节) || C3(32字节) || C2(密文数据)`
  - C1：椭圆曲线点（随机数生成）
  - C3：SM3 消息摘要（用于完整性验证）
  - C2：加密后的数据
- **C1C2C3**：旧标准兼容格式，密文结构为 `0x04 || C1(64字节) || C2(密文数据) || C3(32字节)`

支持以下性能优化选项：

- **Window 窗口大小**：控制椭圆曲线运算的预计算窗口（2-6），默认为 4
  - 窗口越大，加密速度越快，但内存占用略高
  - 推荐使用默认值 4 或 5 以获得最佳性能

注意事项：

- **密钥格式**：使用 `PKCS#8` 格式存储私钥，使用 `SPKI/PKIX` 格式存储公钥
- **密文顺序**：加密和解密必须使用相同的密文顺序（C1C3C2 或 C1C2C3）
- **数据安全**：SM2 提供 256 位安全强度，相当于 RSA 3072 位
- **互操作性**：与 OpenSSL 等库互操作时，需明确指定相同的密文顺序
- **私钥安全**：私钥必须妥善保管，不能泄露
- **标准符合**：完全符合 GM/T 0003.4-2012（加密算法）和 GM/T 0003.5-2012（曲线参数）

导入相关模块：
```go
import (
    "github.com/dromara/dongle"
    "github.com/dromara/dongle/crypto/keypair"
)
```

## 创建密钥对

```go
kp := keypair.NewSm2KeyPair()
// 设置密文顺序（可选，默认为 C1C3C2）
kp.SetOrder(keypair.C1C3C2)
// 设置窗口大小（可选，默认为 4，范围 2-6）
kp.SetWindow(4)
```

### 生成密钥对

```go
// 生成 SM2 密钥对（256 位椭圆曲线）
err := kp.GenKeyPair()
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
MFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAEVJKqUmu59VTLhqCiVBmKqRjL5MXy
RHKwFAI+qG2Hqy5Wf5cLRlIf7aSMKqwGvYpP6gVOqQpvBdDQhDqr8rqrYA==
-----END PUBLIC KEY-----`)

// 设置 PEM 格式私钥
kp.PrivateKey = []byte(`-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqBHM9VAYItBG0wawIBAQQgKvp8GZUkqT8UH/Z5
u8mjNM0JIvqmFolR6LczGEZmSvmhRANCAARUkqpSa7n1VMuGoKJUGYqpGMvkxfJE
crAUAj6obYerLlZ/lwtGUh/tpIwqrAa9ik/qBU6pCm8F0NCEOqvyuqtg
-----END PRIVATE KEY-----`)
```

### 从已有 DER 格式密钥设置密钥对

```go
// 设置 Base64 编码的 DER 格式公钥
kp.SetPublicKey([]byte("MFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAEVJKqUmu59VTLhqCiVBmKqRjL5MXyRHKwFAI+qG2Hqy5Wf5cLRlIf7aSMKqwGvYpP6gVOqQpvBdDQhDqr8rqrYA=="))

// 设置 Base64 编码的 DER 格式私钥
kp.SetPrivateKey([]byte("MIGHAgEAMBMGByqGSM49AgEGCCqBHM9VAYItBG0wawIBAQQgKvp8GZUkqT8UH/Z5u8mjNM0JIvqmFolR6LczGEZmSvmhRANCAARUkqpSa7n1VMuGoKJUGYqpGMvkxfJEcrAUAj6obYerLlZ/lwtGUh/tpIwqrAa9ik/qBU6pCm8F0NCEOqvyuqtg"))
```

### 将 `DER` 格式密钥格式化成 `PEM` 格式

```go
// 将 base64 编码的 DER 格式公钥格式化为 PEM 格式
publicKey, err := kp.FormatPublicKey([]byte("MFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAEVJKqUmu59VTLhqCiVBmKqRjL5MXyRHKwFAI+qG2Hqy5Wf5cLRlIf7aSMKqwGvYpP6gVOqQpvBdDQhDqr8rqrYA=="))

// 将 base64 编码的 DER 格式私钥格式化为 PEM 格式
privateKey, err := kp.FormatPrivateKey([]byte("MIGHAgEAMBMGByqGSM49AgEGCCqBHM9VAYItBG0wawIBAQQgKvp8GZUkqT8UH/Z5u8mjNM0JIvqmFolR6LczGEZmSvmhRANCAARUkqpSa7n1VMuGoKJUGYqpGMvkxfJEcrAUAj6obYerLlZ/lwtGUh/tpIwqrAa9ik/qBU6pCm8F0NCEOqvyuqtg"))
```

### 将 `PEM` 格式密钥压缩成 `DER` 格式

```go
// 将 PEM 格式公钥压缩成经过 base64 编码的 DER 格式(去掉 PEM 格式公钥的头尾和换行符)
publicKey, err := kp.CompressPublicKey([]byte(`-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAEVJKqUmu59VTLhqCiVBmKqRjL5MXy
RHKwFAI+qG2Hqy5Wf5cLRlIf7aSMKqwGvYpP6gVOqQpvBdDQhDqr8rqrYA==
-----END PUBLIC KEY-----`))

// 将 PEM 格式私钥压缩成经过 base64 编码的 DER 格式(去掉 PEM 格式私钥的头尾和换行符)
privateKey, err := kp.CompressPrivateKey([]byte(`-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqBHM9VAYItBG0wawIBAQQgKvp8GZUkqT8UH/Z5
u8mjNM0JIvqmFolR6LczGEZmSvmhRANCAARUkqpSa7n1VMuGoKJUGYqpGMvkxfJE
crAUAj6obYerLlZ/lwtGUh/tpIwqrAa9ik/qBU6pCm8F0NCEOqvyuqtg
-----END PRIVATE KEY-----`))
```

## 公钥加密

输入数据
```go
// 输入字符串
encrypter := dongle.Encrypt.FromString("hello world").BySm2(kp)
// 输入字节切片
encrypter := dongle.Encrypt.FromBytes([]byte("hello world")).BySm2(kp)
// 输入文件流
file, _ := os.Open("test.txt")
encrypter := dongle.Encrypt.FromFile(file).BySm2(kp)

// 检查加密错误
if encrypter.Error != nil {
	fmt.Printf("加密错误: %v\n", encrypter.Error)
	return
}
```

输出数据
```go
// 输出 Hex 编码字符串
hexString := encrypter.ToHexString() // 例如：047fae94fd1a8b880d8d5454dd8df30c40...
// 输出 Hex 编码字节切片
hexBytes := encrypter.ToHexBytes()   // 例如：[]byte("047fae94fd1a8b880d8d5454dd8df30c40...")

// 输出 Base64 编码字符串
base64String := encrypter.ToBase64String() // 例如：BH+ulP0ai4gNjVRU3Y3zDEA=...
// 输出 Base64 编码字节切片
base64Bytes := encrypter.ToBase64Bytes()   // 例如：[]byte("BH+ulP0ai4gNjVRU3Y3zDEA=...")

// 输出未编码原始字符串
rawString := encrypter.ToRawString()
// 输出未编码原始字节切片
rawBytes := encrypter.ToRawBytes()  
```

## 私钥解密

输入数据
```go
// 输入 Hex 编码字符串
decrypter := dongle.Decrypt.FromHexString(hexString).BySm2(kp)
// 输入 Hex 编码字节切片
decrypter := dongle.Decrypt.FromHexBytes(hexBytes).BySm2(kp)
// 输入 Hex 编码文件流
file, _ := os.Open("encrypted.hex")
decrypter := dongle.Decrypt.FromHexFile(file).BySm2(kp)

// 输入 Base64 编码字符串
decrypter := dongle.Decrypt.FromBase64String(base64String).BySm2(kp)
// 输入 Base64 编码字节切片
decrypter := dongle.Decrypt.FromBase64Bytes(base64Bytes).BySm2(kp)
// 输入 Base64 编码文件流
file, _ := os.Open("encrypted.base64")
decrypter := dongle.Decrypt.FromBase64File(file).BySm2(kp)

// 输入原始字符串
decrypter := dongle.Decrypt.FromRawString(rawString).BySm2(kp)
// 输入原始字节切片
decrypter := dongle.Decrypt.FromRawBytes(rawBytes).BySm2(kp)
// 输入原始文件流
file, _ := os.Open("encrypted.bin")
decrypter := dongle.Decrypt.FromRawFile(file).BySm2(kp)

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