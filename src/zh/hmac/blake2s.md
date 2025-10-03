---
head:
  - - meta
    - name: description
      content: HMAC-BLAKE2s算法|一个轻量级、语义化、对开发者友好的 golang 编码&密码库
  - - meta
    - name: keywords
      content: HMAC-BLAKE2s
---

# Hmac-Blake2s

`Hmac-Blake2s` 是一种基于 `blake2s` 的消息认证码算法，`dongle` 支持标准和流式 `blake2s` 消息认证码算法，提供多种输出格式。

> 注意：`WithKey` 方法必须在 `ByBlake2s` 之前调用

## 支持的哈希算法

- [Blake2s-128](#blake2s-128)：生成 16 字节哈希值
- [Blake2s-256](#blake2s-256)：生成 32 字节哈希值

## Blake2s-128

### 输入数据

```go
// 输入字符串
hasher := dongle.Hash.FromString("hello world").WithKey([]byte("dongle")).ByBlake2s(128)

// 输入字节切片
hasher := dongle.Hash.FromBytes([]byte("hello world")).WithKey([]byte("dongle")).ByBlake2s(128)

// 输入文件流
file, _ := os.Open("test.txt")
hasher := dongle.Hash.FromFile(file).WithKey([]byte("dongle")).ByBlake2s(128)

// 检查 HMAC 错误
if hasher.Error != nil {
	fmt.Printf("HMAC 错误: %v\n", hasher.Error)
	return
}
```

### 输出数据

```go
// 输出 Hex 编码字符串
hasher.ToHexString() // 8e9dce350baec849c2bc163d0e73552a
// 输出 Hex 编码字节切片
hasher.ToHexBytes()  // []byte("8e9dce350baec849c2bc163d0e73552a")

// 输出 Base64 编码字符串
hasher.ToBase64String() // jp3ONQuuyEnCvBY9DnNVKg==
// 输出 Base64 编码字节切片
hasher.ToBase64Bytes()  // []byte("jp3ONQuuyEnCvBY9DnNVKg==")

// 输出未编码原始字符串
hasher.ToRawString()
// 输出未编码原始字节切片
hasher.ToRawBytes()
```

## Blake2s-256

### 输入数据

```go
// 输入字符串
hasher := dongle.Hash.FromString("hello world").WithKey([]byte("dongle")).ByBlake2s(256)

// 输入字节切片
hasher := dongle.Hash.FromBytes([]byte("hello world")).WithKey([]byte("dongle")).ByBlake2s(256)

// 输入文件流
file, _ := os.Open("test.txt")
hasher := dongle.Hash.FromFile(file).WithKey([]byte("dongle")).ByBlake2s(256)

// 检查 HMAC 错误
if hasher.Error != nil {
	fmt.Printf("HMAC 错误: %v\n", hasher.Error)
	return
}
```

### 输出数据

```go
// 输出 Hex 编码字符串
hasher.ToHexString() // 14953619e2781ed4a20f571d32d494af37b92e9bede33fbe429dff376f233af3
// 输出 Hex 编码字节切片
hasher.ToHexBytes()  // []byte("14953619e2781ed4a20f571d32d494af37b92e9bede33fbe429dff376f233af3")

// 输出 Base64 编码字符串
hasher.ToBase64String() // FJU2GeJ4HtSiD1cdMtSUrze5Lpvt4z++Qp3/N28jOvM=
// 输出 Base64 编码字节切片
hasher.ToBase64Bytes()  // []byte("FJU2GeJ4HtSiD1cdMtSUrze5Lpvt4z++Qp3/N28jOvM=")

// 输出未编码原始字符串
hasher.ToRawString()
// 输出未编码原始字节切片
hasher.ToRawBytes()
```
