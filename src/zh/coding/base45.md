---
title: Base45 编码/解码
head:
  - - meta
    - name: description
      content: Base45 编码/解码，符合 RFC9285 规范，支持自定义字母表，支持标准和流式处理，支持字符串、字节与文件输入，提供字符串与字节输出
  - - meta
    - name: keywords
      content: dongle, go-dongle, 编码, 解码, Base45, RFC9285, 字母表, 自定义字符集, 流式处理, 字符串输入, 字节输入, 文件输入, 字符串输出, 字节输出
---

# Base45

Base45 是一种将二进制数据编码为 `ASCII` 字符的编码方式，使用 `45` 个字符（0-9, A-Z, 空格, $, %, *, +, -, ., /, :）来表示数据。`dongle` 支持标准和流式 `Base45` 编码，符合 `RFC9285` 规范。

> 默认字符集为 `0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:`,
> 可以通过设置 `base45.StdAlphabet` 来自定义字符集

### 编码数据
输入数据

```go
// 输入字符串
encoder := dongle.Encode.FromString("hello world").ByBase45()
// 输入字节切片
encoder := dongle.Encode.FromBytes([]byte("hello world")).ByBase45()
// 输入文件流
file, _ := os.Open("test.txt")
encoder := dongle.Encode.FromFile(file).ByBase45()

// 检查编码错误
if encoder.Error != nil {
	fmt.Printf("编码错误: %v\n", encoder.Error)
	return
}
```

输出数据

```go
// 输出字符串
encoder.ToString() // +8D VD82EK4F.KEA2
// 输出字节切片
encoder.ToBytes()  // []byte("+8D VD82EK4F.KEA2")
```

### 解码数据
输入数据

```go
// 输入字符串
decoder := dongle.Decode.FromString("+8D VD82EK4F.KEA2").ByBase45()
// 输入字节切片
decoder := dongle.Decode.FromBytes([]byte("+8D VD82EK4F.KEA2")).ByBase45()
// 输入文件流
file, _ := os.Open("test.txt")
decoder := dongle.Decode.FromFile(file).ByBase45()

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