---
head:
  - - meta
    - name: description
      content: HMAC-BLAKE2b算法|一个轻量级、语义化、对开发者友好的 golang 编码&密码库
  - - meta
    - name: keywords
      content: HMAC-BLAKE2b
---

# Hmac-Blake2b

`Hmac-Blake2b` 是一种基于 `blake2b` 的消息认证码算法，`dongle` 支持标准 `blake2b` 消息认证码算法，提供多种输出格式。

> 注意：`WithKey` 方法必须在 `ByBlake2b` 之前调用

## 支持的哈希算法

- [Blake2b-256](#blake2b-256)：生成 32 字节哈希值
- [Blake2b-384](#blake2b-384)：生成 48 字节哈希值
- [Blake2b-512](#blake2b-512)：生成 64 字节哈希值

## Blake2b-256

### 输入数据

```go
// 输入字符串
hasher := dongle.Hash.FromString("hello world").WithKey([]byte("dongle")).ByBlake2b(256)

// 输入字节切片
hasher := dongle.Hash.FromBytes([]byte("hello world")).WithKey([]byte("dongle")).ByBlake2b(256)

// 输入文件流
file, _ := os.Open("test.txt")
hasher := dongle.Hash.FromFile(file).WithKey([]byte("dongle")).ByBlake2b(256)

// 检查 HMAC 错误
if hasher.Error != nil {
	fmt.Printf("HMAC 错误: %v\n", hasher.Error)
	return
}
```

### 输出数据

```go
// 输出 Hex 编码字符串
hasher.ToHexString() // 11de19238a5d5414bc8f9effb2a5f004a4210804668d25d252d0733c26670a0d
// 输出 Hex 编码字节切片
hasher.ToHexBytes()  // []byte("11de19238a5d5414bc8f9effb2a5f004a4210804668d25d252d0733c26670a0d")

// 输出 Base64 编码字符串
hasher.ToBase64String() // Ed4ZI4pdVBS8j57/sqXwBKQhCARmjSXSUtBzPCZnCg0=
// 输出 Base64 编码字节切片
hasher.ToBase64Bytes()  // []byte("Ed4ZI4pdVBS8j57/sqXwBKQhCARmjSXSUtBzPCZnCg0=")

// 输出未编码原始字符串
hasher.ToRawString()
// 输出未编码原始字节切片
hasher.ToRawBytes()
```

## Blake2b-384

### 输入数据

```go
// 输入字符串
hasher := dongle.Hash.FromString("hello world").WithKey([]byte("dongle")).ByBlake2b(384)

// 输入字节切片
hasher := dongle.Hash.FromBytes([]byte("hello world")).WithKey([]byte("dongle")).ByBlake2b(384)

// 输入文件流
file, _ := os.Open("test.txt")
hasher := dongle.Hash.FromFile(file).WithKey([]byte("dongle")).ByBlake2b(384)

// 检查 HMAC 错误
if hasher.Error != nil {
	fmt.Printf("HMAC 错误: %v\n", hasher.Error)
	return
}
```

### 输出数据

```go
// 输出 Hex 编码字符串
hasher.ToHexString() // 506c397b0b5d437342a07748d09612f9905ab21e6674d8409516a53cf341a1bc9052bf47edf85ffe506437acd1f91bc
// 输出 Hex 编码字节切片
hasher.ToHexBytes()  // []byte("506c397b0b5d437342a07748d09612f9905ab21e6674d8409516a53cf341a1bc9052bf47edf85ffe506437acd1f91bc")

// 输出 Base64 编码字符串
hasher.ToBase64String() // UGw5ewtdQ3NCoHdI0JYS+ZBash5mdNhAlRalPPNBobyQUr9H7fhf/lBkOnrNH5G8
// 输出 Base64 编码字节切片
hasher.ToBase64Bytes()  // []byte("UGw5ewtdQ3NCoHdI0JYS+ZBash5mdNhAlRalPPNBobyQUr9H7fhf/lBkOnrNH5G8")

// 输出未编码原始字符串
hasher.ToRawString()
// 输出未编码原始字节切片
hasher.ToRawBytes()
```

## Blake2b-512

### 输入数据

```go
// 输入字符串
hasher := dongle.Hash.FromString("hello world").WithKey([]byte("dongle")).ByBlake2b(512)

// 输入字节切片
hasher := dongle.Hash.FromBytes([]byte("hello world")).WithKey([]byte("dongle")).ByBlake2b(512)

// 输入文件流
file, _ := os.Open("test.txt")
hasher := dongle.Hash.FromFile(file).WithKey([]byte("dongle")).ByBlake2b(512)

// 检查 HMAC 错误
if hasher.Error != nil {
	fmt.Printf("HMAC 错误: %v\n", hasher.Error)
	return
}
```

### 输出数据

```go
// 输出 Hex 编码字符串
hasher.ToHexString() // 9ab7280ca18d0fca29034329eddecb36ecdcefe00758bbe966e30cfbf9774e3e21c2ee5be01fdc23c983d8849fcf2f0dcfd3a0e6ba92442cbd64a2342763d2ae
// 输出 Hex 编码字节切片
hasher.ToHexBytes()  // []byte("9ab7280ca18d0fca29034329eddecb36ecdcefe00758bbe966e30cfbf9774e3e21c2ee5be01fdc23c983d8849fcf2f0dcfd3a0e6ba92442cbd64a2342763d2ae")

// 输出 Base64 编码字符串
hasher.ToBase64String() // mrcoDKGND8opA0Mp7d7LNuzc7+AHWLvpZuMM+/l3Tj4hwu5b4B/cI8mD2ISfzy8Nz9Og5rqSRCy9ZKI0J2PSrg==
// 输出 Base64 编码字节切片
hasher.ToBase64Bytes()  // []byte("mrcoDKGND8opA0Mp7d7LNuzc7+AHWLvpZuMM+/l3Tj4hwu5b4B/cI8mD2ISfzy8Nz9Og5rqSRCy9ZKI0J2PSrg==")

// 输出未编码原始字符串
hasher.ToRawString()
// 输出未编码原始字节切片
hasher.ToRawBytes()
```
