---
head:
  - - meta
    - name: description
      content: MD5 哈希算法|一个轻量级、语义化、对开发者友好的 golang 编码&密码库
  - - meta
    - name: keywords
      content: 哈希, hash, md5
---

# Hash-Md5

`Hash-Md5` 是一种产生 `16` 字节哈希值的哈希算法，`dongle` 支持标准和流式 `md5` 哈希算法，提供多种输出格式。

## 输入数据

```go
// 输入字符串
hasher := dongle.Hash.FromString("hello world").ByMd5()
// 输入字节切片
hasher := dongle.Hash.FromBytes([]byte("hello world")).ByMd5()
// 输入文件流
file, _ := os.Open("test.txt")
hasher := dongle.Hash.FromFile(file).ByMd5()

// 检查哈希错误
if hasher.Error != nil {
	fmt.Printf("哈希错误: %v\n", hasher.Error)
	return
}
```

## 输出数据

```go
// 输出 Hex 编码字符串
hasher.ToHexString() // 5eb63bbbe01eeed093cb22bb8f5acdc3
// 输出 Hex 编码字节切片
hasher.ToHexBytes()  // []byte("5eb63bbbe01eeed093cb22bb8f5acdc3")

// 输出 Base64 编码字符串
hasher.ToBase64String() // XrY7u+Ae7tCTyyK7j1rNww==
// 输出 Base64 编码字节切片
hasher.ToBase64Bytes()  // []byte("XrY7u+Ae7tCTyyK7j1rNww==")

// 输出未编码原始字符串
hasher.ToRawString()
// 输出未编码原始字节切片
hasher.ToRawBytes()
``` 