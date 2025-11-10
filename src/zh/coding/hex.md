---
title: Hex 编码/解码
head:
  - - meta
    - name: description
      content: Hex 编码/解码，也称 Base16，使用 16 个字符（0-9, A-F），支持自定义大小写，支持标准和流式处理，支持字符串、字节与文件输入，提供字符串与字节输出
  - - meta
    - name: keywords
      content: dongle, go-dongle, 编码, 解码, Hex, Base16, 大小写, 自定义字符集, 流式处理, 字符串输入, 字节输入, 文件输入, 字符串输出, 字节输出
---

# Hex

Hex 是一种将二进制数据编码为 `ASCII` 字符的编码方式，使用 `16` 个字符（0-9, A-F）来表示数据。`dongle` 支持标准和流式 `Hex` 编码，也称为 `Base16` 编码。

### 编码数据
输入数据

```go
// 输入字符串
encoder := dongle.Encode.FromString("hello world").ByHex()
// 输入字节切片
encoder := dongle.Encode.FromBytes([]byte("hello world")).ByHex()
// 输入文件流
file, _ := os.Open("test.txt")
encoder := dongle.Encode.FromFile(file).ByHex()

// 检查编码错误
if encoder.Error != nil {
	fmt.Printf("编码错误: %v\n", encoder.Error)
	return
}
```

输出数据

```go
// 输出字符串
encoder.ToString() // 68656c6c6f20776f726c64
// 输出字节切片
encoder.ToBytes()  // []byte("68656c6c6f20776f726c64")
```

### 解码数据
输入数据

```go
// 输入字符串
decoder := dongle.Decode.FromString("68656c6c6f20776f726c64").ByHex()
// 输入字节切片
decoder := dongle.Decode.FromBytes([]byte("68656c6c6f20776f726c64")).ByHex()
// 输入文件流
file, _ := os.Open("test.txt")
decoder := dongle.Decode.FromFile(file).ByHex()

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


