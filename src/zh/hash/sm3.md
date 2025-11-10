---
title: SM3 哈希算法
head:
  - - meta
    - name: description
      content: SM3 哈希算法，中国国家密码管理局发布的国密哈希算法，生成 32 字节哈希值，符合 GB/T 32918.1-2016 标准，支持标准和流式处理，支持字符串、字节与文件输入，支持 Hex 和 Base64 输出格式
  - - meta
    - name: keywords
      content: dongle, go-dongle, 哈希, 摘要, 校验, SM3, 国密算法, GB/T 32918.1-2016, 流式处理, 字符串输入, 字节输入, 文件输入, Hex, Base64
---

# Hash-Sm3

`Hash-SM3` 是一种产生 `32` 字节哈希值的国密哈希算法，是中国国家密码管理局发布的密码杂凑算法，符合 `GB/T 32918.1-2016` 标准。`dongle` 支持标准和流式 `SM3` 哈希算法，提供多种输出格式。

## 输入数据

```go
// 输入字符串
hasher := dongle.Hash.FromString("hello world").BySm3()
// 输入字节切片
hasher := dongle.Hash.FromBytes([]byte("hello world")).BySm3()
// 输入文件流
file, _ := os.Open("test.txt")
hasher := dongle.Hash.FromFile(file).BySm3()

// 检查哈希错误
if hasher.Error != nil {
	fmt.Printf("哈希错误: %v\n", hasher.Error)
	return
}
```

## 输出数据

```go
// 输出 Hex 编码字符串
hasher.ToHexString() // 44f0061e69fa6fdfc290c494654a05dc0c053da7e5c52b84ef93a9d67d3fff88
// 输出 Hex 编码字节切片
hasher.ToHexBytes()  // []byte("44f0061e69fa6fdfc290c494654a05dc0c053da7e5c52b84ef93a9d67d3fff88")

// 输出 Base64 编码字符串
hasher.ToBase64String() // RPAWHmn6b9/CkMSGVUoF3AwFPafly7hO+Trp1tP/+Ig=
// 输出 Base64 编码字节切片
hasher.ToBase64Bytes()  // []byte("RPAWHmn6b9/CkMSGVUoF3AwFPafly7hO+Trp1tP/+Ig=")

// 输出未编码原始字符串
hasher.ToRawString()
// 输出未编码原始字节切片
hasher.ToRawBytes()
```
