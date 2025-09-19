---
title: Base58 编码/解码
head:
  - - meta
    - name: description
      content: Base58 编码/解码 | 一个轻量级、语义化、对开发者友好的 golang 编码&密码库
  - - meta
    - name: keywords
      content: dongle, base58
---

# Base58

Base58 是一种将二进制数据编码为 `ASCII` 字符的编码方式，使用 `58` 个字符（1-9, A-Z, a-z，排除容易混淆的字符 0, O, I, l）来表示数据。`dongle` 支持标准 `Base58` 编码，遵循比特币风格的规范。

> 默认字符集为 `123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz`,
> 可以通过设置 `base58.StdAlphabet` 来自定义字符集

### 编码数据
输入数据

```go
// 输入字符串
encoder := dongle.Encode.FromString("hello world").ByBase58()
// 输入字节切片
encoder := dongle.Encode.FromBytes([]byte("hello world")).ByBase58()
// 输入文件流
file, _ := os.Open("test.txt")
encoder := dongle.Encode.FromFile(file).ByBase58()

// 检查编码错误
if encoder.Error != nil {
	fmt.Printf("编码错误: %v\n", encoder.Error)
	return
}
```

输出数据

```go
// 输出字符串
encoder.ToString() // StV1DL6CwTryKyV
// 输出字节切片
encoder.ToBytes()  // []byte("StV1DL6CwTryKyV")
```

### 解码数据
输入数据

```go
// 输入字符串
decoder := dongle.Decode.FromString("StV1DL6CwTryKyV").ByBase58()
// 输入字节切片
decoder := dongle.Decode.FromBytes([]byte("StV1DL6CwTryKyV")).ByBase58()
// 输入文件流
file, _ := os.Open("test.txt")
decoder := dongle.Decode.FromFile(file).ByBase58()

// 检查解码错误
if decoder.Error != nil {
	fmt.Printf("解码错误: %v\n", decoder.Error)
	return
}
```

输出数据

```go
// 输出字符串
decoder.ToString() // hello world
// 输出字节切片
decoder.ToBytes()  // []byte("hello world")
```

 