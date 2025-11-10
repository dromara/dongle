---
title: Ripemd160 哈希算法
head:
  - - meta
    - name: description
      content: RIPEMD160 哈希算法，生成 20 字节哈希值，支持标准和流式处理，支持字符串、字节与文件输入，支持 Hex 和 Base64 输出格式
  - - meta
    - name: keywords
      content: dongle, go-dongle, 哈希, 摘要, 校验, RIPEMD160, 流式处理, 字符串输入, 字节输入, 文件输入, Hex, Base64
---

# Hash-Ripemd160

`Hash-Ripemd160` 是一种产生 `20` 字节哈希值的哈希算法，`dongle` 支持标准和流式 `ripemd160` 哈希算法，提供多种输出格式。

## 输入数据

```go
// 输入字符串
hasher := dongle.Hash.FromString("hello world").ByRipemd160()
// 输入字节切片
hasher := dongle.Hash.FromBytes([]byte("hello world")).ByRipemd160()
// 输入文件流
file, _ := os.Open("test.txt")
hasher := dongle.Hash.FromFile(file).ByRipemd160()

// 检查哈希错误
if hasher.Error != nil {
	fmt.Printf("哈希错误: %v\n", hasher.Error)
	return
}
```

## 输出数据

```go
// 输出 Hex 编码字符串
hasher.ToHexString() // 98c615784ccb5fe5936fbc0cbe9dfdb408d92f0f
// 输出 Hex 编码字节切片
hasher.ToHexBytes()  // []byte("98c615784ccb5fe5936fbc0cbe9dfdb408d92f0f")

// 输出 Base64 编码字符串
hasher.ToBase64String() // mMYVeEzLX+WTb7wMvp39tAjZLw8=
// 输出 Base64 编码字节切片
hasher.ToBase64Bytes()  // []byte("mMYVeEzLX+WTb7wMvp39tAjZLw8=")

// 输出未编码原始字符串
hasher.ToRawString()
// 输出未编码原始字节切片
hasher.ToRawBytes()
```
