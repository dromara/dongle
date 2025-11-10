---
title: MD4 哈希算法
head:
  - - meta
    - name: description
      content: MD4 哈希算法，生成 16 字节哈希值，支持标准和流式处理，支持字符串、字节与文件输入，支持 Hex 和 Base64 输出格式
  - - meta
    - name: keywords
      content: dongle, go-dongle, 哈希, 摘要, 校验, MD4, 流式处理, 字符串输入, 字节输入, 文件输入, Hex, Base64
---

# Hash-Md4

`Hash-Md4` 是一种产生 `16` 字节哈希值的哈希算法，`dongle` 支持标准和流式 `md4` 哈希算法，提供多种输出格式。

## 输入数据

```go
// 输入字符串
hasher := dongle.Hash.FromString("hello world").ByMd4()
// 输入字节切片
hasher := dongle.Hash.FromBytes([]byte("hello world")).ByMd4()
// 输入文件流
file, _ := os.Open("test.txt")
hasher := dongle.Hash.FromFile(file).ByMd4()

// 检查哈希错误
if hasher.Error != nil {
	fmt.Printf("哈希错误: %v\n", hasher.Error)
	return
}
```

## 输出数据

```go
// 输出 Hex 编码字符串
hasher.ToHexString() // aa010fbc1d14c795d86ef98c95479d17
// 输出 Hex 编码字节切片
hasher.ToHexBytes()  // []byte("aa010fbc1d14c795d86ef98c95479d17")

// 输出 Base64 编码字符串
hasher.ToBase64String() // qgEPvB0Ux5XYbvmMlUedFw==
// 输出 Base64 编码字节切片
hasher.ToBase64Bytes()  // []byte("qgEPvB0Ux5XYbvmMlUedFw==")

// 输出未编码原始字符串
hasher.ToRawString()
// 输出未编码原始字节切片
hasher.ToRawBytes()
```