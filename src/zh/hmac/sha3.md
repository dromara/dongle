---
head:
  - - meta
    - name: description
      content: HMAC-SHA3算法|一个轻量级、语义化、对开发者友好的 golang 编码&密码库
  - - meta
    - name: keywords
      content: HMAC-SHA3
---

# Hmac-Sha3

`Hmac-Sha3` 是一种基于 `sha3` 的消息认证码算法，`dongle` 支持标准 `sha3` 消息认证码算法，提供多种输出格式。

> 注意：`WithKey` 方法必须在 `BySha3` 之前调用

## 支持的哈希算法

- [Sha3-224](#sha3-224)：生成 28 字节哈希值
- [Sha3-256](#sha3-256)：生成 32 字节哈希值
- [Sha3-384](#sha3-384)：生成 48 字节哈希值
- [Sha3-512](#sha3-512)：生成 64 字节哈希值

## Sha3-224

### 输入数据

```go
// 输入字符串
hasher := dongle.Hash.FromString("hello world").WithKey([]byte("dongle")).BySha3(224)

// 输入字节切片
hasher := dongle.Hash.FromBytes([]byte("hello world")).WithKey([]byte("dongle")).BySha3(224)

// 输入文件流
file, _ := os.Open("test.txt")
hasher := dongle.Hash.FromFile(file).WithKey([]byte("dongle")).BySha3(224)

// 检查 HMAC 错误
if hasher.Error != nil {
	fmt.Printf("HMAC 错误: %v\n", hasher.Error)
	return
}
```

### 输出数据

```go
// 输出 Hex 编码字符串
hasher.ToHexString() // fb8f061d9d1dddd2f5d3b9064a5e98e3e4b6df27ea93ce67627583ce
// 输出 Hex 编码字节切片
hasher.ToHexBytes()  // []byte("fb8f061d9d1dddd2f5d3b9064a5e98e3e4b6df27ea93ce67627583ce")

// 输出 Base64 编码字符串
hasher.ToBase64String() // +48GHZ0d3dL107kGSl6Y4+S23yfqk85nYnWDzg==
// 输出 Base64 编码字节切片
hasher.ToBase64Bytes()  // []byte("+48GHZ0d3dL107kGSl6Y4+S23yfqk85nYnWDzg==")

// 输出未编码原始字符串
hasher.ToRawString()
// 输出未编码原始字节切片
hasher.ToRawBytes()
```

## Sha3-256

### 输入数据

```go
// 输入字符串
hasher := dongle.Hash.FromString("hello world").WithKey([]byte("dongle")).BySha3(256)

// 输入字节切片
hasher := dongle.Hash.FromBytes([]byte("hello world")).WithKey([]byte("dongle")).BySha3(256)

// 输入文件流
file, _ := os.Open("test.txt")
hasher := dongle.Hash.FromFile(file).WithKey([]byte("dongle")).BySha3(256)

// 检查 HMAC 错误
if hasher.Error != nil {
	fmt.Printf("HMAC 错误: %v\n", hasher.Error)
	return
}
```

### 输出数据

```go
// 输出 Hex 编码字符串
hasher.ToHexString() // 8193367fde28cf5c460adb449a04b3dd9c184f488bdccbabf0526c54f90c4460
// 输出 Hex 编码字节切片
hasher.ToHexBytes()  // []byte("8193367fde28cf5c460adb449a04b3dd9c184f488bdccbabf0526c54f90c4460")

// 输出 Base64 编码字符串
hasher.ToBase64String() // gZM2f94oz1xGCttEmgSz3ZwYT0iL3Mur8FJsVPkMRGA=
// 输出 Base64 编码字节切片
hasher.ToBase64Bytes()  // []byte("gZM2f94oz1xGCttEmgSz3ZwYT0iL3Mur8FJsVPkMRGA=")

// 输出未编码原始字符串
hasher.ToRawString()
// 输出未编码原始字节切片
hasher.ToRawBytes()
```

## Sha3-384

### 输入数据

```go
// 输入字符串
hasher := dongle.Hash.FromString("hello world").WithKey([]byte("dongle")).BySha3(384)

// 输入字节切片
hasher := dongle.Hash.FromBytes([]byte("hello world")).WithKey([]byte("dongle")).BySha3(384)

// 输入文件流
file, _ := os.Open("test.txt")
hasher := dongle.Hash.FromFile(file).WithKey([]byte("dongle")).BySha3(384)

// 检查 HMAC 错误
if hasher.Error != nil {
	fmt.Printf("HMAC 错误: %v\n", hasher.Error)
	return
}
```

### 输出数据

```go
// 输出 Hex 编码字符串
hasher.ToHexString() // 3f76f5cda69cada3ee6b33f8458cd498b063075db263dd8b33f2a3992a8804f9569a7c86ffa2b8f0748babeb7a6fc0e7
// 输出 Hex 编码字节切片
hasher.ToHexBytes()  // []byte("3f76f5cda69cada3ee6b33f8458cd498b063075db263dd8b33f2a3992a8804f9569a7c86ffa2b8f0748babeb7a6fc0e7")

// 输出 Base64 编码字符串
hasher.ToBase64String() // P3b1zaacraPuazP4RYzUmLBjB12yY92LM/KjmSqIBPlWmnyG/6K48HSLq+t6b8Dn
// 输出 Base64 编码字节切片
hasher.ToBase64Bytes()  // []byte("P3b1zaacraPuazP4RYzUmLBjB12yY92LM/KjmSqIBPlWmnyG/6K48HSLq+t6b8Dn")

// 输出未编码原始字符串
hasher.ToRawString()
// 输出未编码原始字节切片
hasher.ToRawBytes()
```

## Sha3-512

### 输入数据

```go
// 输入字符串
hasher := dongle.Hash.FromString("hello world").WithKey([]byte("dongle")).BySha3(512)

// 输入字节切片
hasher := dongle.Hash.FromBytes([]byte("hello world")).WithKey([]byte("dongle")).BySha3(512)

// 输入文件流
file, _ := os.Open("test.txt")
hasher := dongle.Hash.FromFile(file).WithKey([]byte("dongle")).BySha3(512)

// 检查 HMAC 错误
if hasher.Error != nil {
	fmt.Printf("HMAC 错误: %v\n", hasher.Error)
	return
}
```

### 输出数据

```go
// 输出 Hex 编码字符串
hasher.ToHexString() // a99653d0407d659eccdeed43bb7cccd2e2b05a2c34fd3467c4198cf2ad26a466738513e88839fb55e64eb49df65bc52ed0fec2775bd9e086edd4fb4024add4a2
// 输出 Hex 编码字节切片
hasher.ToHexBytes()  // []byte("a99653d0407d659eccdeed43bb7cccd2e2b05a2c34fd3467c4198cf2ad26a466738513e88839fb55e64eb49df65bc52ed0fec2775bd9e086edd4fb4024add4a2")

// 输出 Base64 编码字符串
hasher.ToBase64String() // qZZT0EB9ZZ7M3u1Du3zM0uKwWiw0/TRnxBmM8q0mpGZzhRPoiDn7VeZOtJ32W8Uu0P7Cd1vZ4Ibt1PtAJK3Uog==
// 输出 Base64 编码字节切片
hasher.ToBase64Bytes()  // []byte("qZZT0EB9ZZ7M3u1Du3zM0uKwWiw0/TRnxBmM8q0mpGZzhRPoiDn7VeZOtJ32W8Uu0P7Cd1vZ4Ibt1PtAJK3Uog==")

// 输出未编码原始字符串
hasher.ToRawString()
// 输出未编码原始字节切片
hasher.ToRawBytes()
```
