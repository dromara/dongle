---
title: Blake2s 哈希算法
head:
  - - meta
    - name: description
      content: BLAKE2s 哈希算法 | 一个轻量级、语义化、对开发者友好的 golang 密码库
  - - meta
    - name: keywords
      content: 哈希, hash, blake2s, blake2s-128, blake2s-256, hash-blake2s, hash-blake2s-128, hash-blake256
---

# Hash-Blake2s

`Hash-Blake2s` 是一系列产生不同长度哈希值的哈希算法，包括 `blake2s-128` 和 `blake2s-256`，`dongle` 支持所有两种 `hash-blake2s` 变体。

- [Blake2s-128](#blake2s-128)：生成 16 字节哈希值
- [Blake2s-256](#blake2s-256)：生成 32 字节哈希值

## Blake2s-128

### 输入数据

```go
// 输入字符串（需要密钥）
hasher := dongle.Hash.FromString("hello world").WithKey([]byte("secret")).ByBlake2s(128)
// 输入字节切片（需要密钥）
hasher := dongle.Hash.FromBytes([]byte("hello world")).WithKey([]byte("secret")).ByBlake2s(128)
// 输入文件流（需要密钥）
file, _ := os.Open("test.txt")
hasher := dongle.Hash.FromFile(file).WithKey([]byte("secret")).ByBlake2s(128)

// 检查哈希错误
if hasher.Error != nil {
	fmt.Printf("哈希错误: %v\n", hasher.Error)
	return
}
```

### 输出数据

```go
// 输出 Hex 编码字符串
hasher.ToHexString() // 8f9dff49538583cb967e763c54d51280
// 输出 Hex 编码字节切片
hasher.ToHexBytes()  // []byte("8f9dff49538583cb967e763c54d51280")

// 输出 Base64 编码字符串
hasher.ToBase64String() // j53/SVOFg8uWfnY8VNUSgA==
// 输出 Base64 编码字节切片
hasher.ToBase64Bytes()  // []byte("j53/SVOFg8uWfnY8VNUSgA==")

// 输出未编码原始字符串
hasher.ToRawString()
// 输出未编码原始字节切片
hasher.ToRawBytes()
```

## Blake2s-256

### 输入数据

```go
// 输入字符串
hasher := dongle.Hash.FromString("hello world").ByBlake2s(256)
// 输入字节切片
hasher := dongle.Hash.FromBytes([]byte("hello world")).ByBlake2s(256)
// 输入文件流
file, _ := os.Open("test.txt")
hasher := dongle.Hash.FromFile(file).ByBlake2s(256)

// 检查哈希错误
if hasher.Error != nil {
	fmt.Printf("哈希错误: %v\n", hasher.Error)
	return
}
```

### 输出数据

```go
// 输出 Hex 编码字符串
hasher.ToHexString() // 9aec6806794561107e594b1f6a8a6b0c92a0cba9acf5e5e93cca06f781813b0b
// 输出 Hex 编码字节切片
hasher.ToHexBytes()  // []byte("9aec6806794561107e594b1f6a8a6b0c92a0cba9acf5e5e93cca06f781813b0b")

// 输出 Base64 编码字符串
hasher.ToBase64String() // muxoBnlFYRB+WUsfaoprDJKgy6ms9eXpPMoG94GBOws=
// 输出 Base64 编码字节切片
hasher.ToBase64Bytes()  // []byte("muxoBnlFYRB+WUsfaoprDJKgy6ms9eXpPMoG94GBOws=")

// 输出未编码原始字符串
hasher.ToRawString()
// 输出未编码原始字节切片
hasher.ToRawBytes()
```
