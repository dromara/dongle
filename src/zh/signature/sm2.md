---
title: SM2 数字签名算法
head:
  - - meta
    - name: description
      content: SM2 数字签名算法，中国国家密码管理局制定的国产商用密码算法，基于椭圆曲线密码学，使用私钥进行签名、公钥进行验证，签名支持 ASN.1 DER 与固定 64 字节 r || s 两种格式，支持标准和流式处理，支持 Hex 和 Base64 输出格式
  - - meta
    - name: keywords
      content: dongle, go-dongle, 签名, 验证, SM2, 数字签名算法, 非对称加密, 椭圆曲线, 私钥签名, 公钥验证, 国密算法, ASN1, Bytes, PKCS8, SPKI, UID, SM3
---

# SM2

SM2 是由中国国家密码管理局制定的椭圆曲线公钥密码算法（GM/T 0003-2012），是中国商用密码标准的核心算法之一。`dongle` 支持标准和流式 `SM2` 数字签名，提供符合 GM/T 0009-2012 标准的签名和验证功能。

SM2 签名算法特点：

- **国密标准**：完全符合 GM/T 0009-2012 数字签名标准
- **安全性高**：使用 256 位椭圆曲线，提供相当于 RSA 3072 位的安全强度
- **用户标识**：支持自定义 UID（用户标识），默认使用 `"1234567812345678"`
- **哈希算法**：内置使用 SM3 哈希算法进行消息摘要
- **签名格式**：默认使用 ASN.1 DER 格式（`SEQUENCE { r, s }`），可通过 `SetSingMode(keypair.Bytes)` 切换为固定 64 字节的 `r || s` 格式
- **性能优化**：支持窗口大小优化，提升签名和验证性能

注意事项：

- **密钥格式**：使用 `PKCS#8` 格式存储私钥，使用 `SPKI/PKIX` 格式存储公钥
- **签名格式**：签名和验证必须使用相同的 `SingMode`；默认 `ASN1`，与 BouncyCastle、Java 等互操作通常使用 ASN.1，部分网关或嵌入式设备使用固定 64 字节裸签名
- **密钥材料**：`SetPublicKey` / `SetPrivateKey` 除 PEM 外，还接受 base64 或 hex 编码的 DER，以及裸密钥材料（公钥为 65 字节非压缩点，私钥为 32 字节标量），并统一归一化为 PEM
- **UID 一致性**：签名和验证必须使用相同的 UID，否则验证会失败
- **默认 UID**：如果未设置 UID，将使用默认值 `"1234567812345678"`（符合 GM/T 0009-2012）
- **私钥安全**：私钥必须妥善保管，不能泄露，只有私钥持有者才能生成有效签名
- **签名验证**：任何人都可以使用公钥验证签名的有效性
- **标准符合**：完全符合 GM/T 0009-2012（数字签名算法）标准

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
// 设置用户标识 UID（可选，默认为 "1234567812345678"）
kp.SetUID([]byte("user@example.com"))
// 设置签名格式（可选，默认为 ASN1）
kp.SetSingMode(keypair.ASN1) // 或 keypair.Bytes
// 设置窗口大小（可选，默认为 4，范围 2-6，用于性能优化）
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
MFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAEv6TXzg5xkLbTkzQzmucCcGbVF1pv
BuOVxSa7tZEvT1bEKqF7WJx8UQ/a7R5YDslbMxPByZGqfPaeQEpwv3emQg==
-----END PUBLIC KEY-----`)

// 设置 PEM 格式私钥
kp.PrivateKey = []byte(`-----BEGIN PRIVATE KEY-----
MIGTAgEAMBMGByqGSM49AgEGCCqBHM9VAYItBHkwdwIBAQQgsXklJOzFBfCXQGaP
5kVornBxt1WjgUIv21Imv7ALAtygCgYIKoEcz1UBgi2hRANCAAS/pNfODnGQttOT
NDOa5wJwZtUXWm8G45XFJru1kS9PVsQqoXtYnHxRD9rtHlgOyVszE8HJkap89p5A
SnC/d6ZC
-----END PRIVATE KEY-----`)
```

### 从已有 DER 格式密钥设置密钥对

除 base64 编码的 DER 外，`SetPublicKey` / `SetPrivateKey` 还接受 hex 编码的 DER 以及裸密钥材料（公钥为 65 字节非压缩点，私钥为 32 字节标量），并将结果统一归一化为 PEM。

```go
// 设置 Base64 编码的 DER 格式公钥
kp.SetPublicKey([]byte("MFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAEv6TXzg5xkLbTkzQzmucCcGbVF1pvBuOVxSa7tZEvT1bEKqF7WJx8UQ/a7R5YDslbMxPByZGqfPaeQEpwv3emQg=="))

// 设置 Base64 编码的 DER 格式私钥
kp.SetPrivateKey([]byte("MIGTAgEAMBMGByqGSM49AgEGCCqBHM9VAYItBHkwdwIBAQQgsXklJOzFBfCXQGaP5kVornBxt1WjgUIv21Imv7ALAtygCgYIKoEcz1UBgi2hRANCAAS/pNfODnGQttOTNDOa5wJwZtUXWm8G45XFJru1kS9PVsQqoXtYnHxRD9rtHlgOyVszE8HJkap89p5ASnC/d6ZC"))
```

### 将 `DER` 格式密钥格式化成 `PEM` 格式

```go
// 将 base64 编码的 DER 格式公钥格式化为 PEM 格式
publicKey, err := kp.FormatPublicKey([]byte("MFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAEv6TXzg5xkLbTkzQzmucCcGbVF1pvBuOVxSa7tZEvT1bEKqF7WJx8UQ/a7R5YDslbMxPByZGqfPaeQEpwv3emQg=="))

// 将 base64 编码的 DER 格式私钥格式化为 PEM 格式
privateKey, err := kp.FormatPrivateKey([]byte("MIGTAgEAMBMGByqGSM49AgEGCCqBHM9VAYItBHkwdwIBAQQgsXklJOzFBfCXQGaP5kVornBxt1WjgUIv21Imv7ALAtygCgYIKoEcz1UBgi2hRANCAAS/pNfODnGQttOTNDOa5wJwZtUXWm8G45XFJru1kS9PVsQqoXtYnHxRD9rtHlgOyVszE8HJkap89p5ASnC/d6ZC"))
```

### 将 `PEM` 格式密钥压缩成 `DER` 格式

```go
// 将 PEM 格式公钥压缩成经过 base64 编码的 DER 格式(提取 PEM 中的 base64 编码 DER)
publicKey := kp.CompressPublicKey([]byte(`-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAEv6TXzg5xkLbTkzQzmucCcGbVF1pv
BuOVxSa7tZEvT1bEKqF7WJx8UQ/a7R5YDslbMxPByZGqfPaeQEpwv3emQg==
-----END PUBLIC KEY-----`))

// 将 PEM 格式私钥压缩成经过 base64 编码的 DER 格式(提取 PEM 中的 base64 编码 DER)
privateKey := kp.CompressPrivateKey([]byte(`-----BEGIN PRIVATE KEY-----
MIGTAgEAMBMGByqGSM49AgEGCCqBHM9VAYItBHkwdwIBAQQgsXklJOzFBfCXQGaP
5kVornBxt1WjgUIv21Imv7ALAtygCgYIKoEcz1UBgi2hRANCAAS/pNfODnGQttOT
NDOa5wJwZtUXWm8G45XFJru1kS9PVsQqoXtYnHxRD9rtHlgOyVszE8HJkap89p5A
SnC/d6ZC
-----END PRIVATE KEY-----`))
```

> `CompressPublicKey` / `CompressPrivateKey` 通过 `pem.Decode` 解析输入，因此可以处理带有 `Bag Attributes` 等可选块头的 PEM。

## 私钥签名

> SM2 流式签名会在内部缓存全部数据，在 `Close` 时一次性签名并输出。

### 输入数据

```go
// 输入字符串
signer := dongle.Sign.FromString("hello world").BySm2(kp)
// 输入字节切片
signer := dongle.Sign.FromBytes([]byte("hello world")).BySm2(kp)
// 输入文件流
file, _ := os.Open("test.txt")
signer := dongle.Sign.FromFile(file).BySm2(kp)

// 检查签名错误
if signer.Error != nil {
	fmt.Printf("签名错误: %v\n", signer.Error)
	return
}
```

### 输出数据

```go
// 输出 Hex 编码签名字符串
hexString := signer.ToHexString() // 例如：3045022100a1b2c3d4e5f6...
// 输出 Hex 编码签名字节切片
hexBytes := signer.ToHexBytes()   // 例如：[]byte("3045022100a1b2c3d4e5f6...")

// 输出 Base64 编码签名字符串
base64String := signer.ToBase64String() // 例如：MEUCIQCobLPeVv...
// 输出 Base64 编码签名字节切片
base64Bytes := signer.ToBase64Bytes()   // 例如：[]byte("MEUCIQCobLPeVv...")

// 输出未编码原始签名字符串
rawString := signer.ToRawString()
// 输出未编码原始签名字节切片
rawBytes := signer.ToRawBytes()
```

> 切换到 `keypair.Bytes` 后，`ToRawBytes()` 输出固定 `64` 字节的 `r || s`（`r`、`s` 各 32 字节），`ToHexString()` 输出 128 个十六进制字符。

## 公钥验证

> 注意：`WithXxxSign` 方法必须在 `BySm2` 之前调用

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
verifier.WithHexSign(hexBytes).BySm2(kp)
// 设置 Base64 编码签名
verifier.WithBase64Sign(base64Bytes).BySm2(kp)
// 设置未编码原始签名
verifier.WithRawSign(rawBytes).BySm2(kp)

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
