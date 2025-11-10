---
title: Base100 编码/解码
head:
  - - meta
    - name: description
      content: Base100 编码/解码，使用 Emoji 字符进行表示（每个字节映射为一个 4 字节 UTF-8 表情），支持标准和流式处理，支持字符串、字节与文件输入，提供字符串与字节输出
  - - meta
    - name: keywords
      content: dongle, go-dongle, 编码, 解码, Base100, Emoji, UTF-8, 流式处理, 字符串输入, 字节输入, 文件输入, 字符串输出, 字节输出
---

# Base100

Base100 是一种将二进制数据编码为 `Emoji` 字符的编码方式，每个字节转换为一个 `4` 字节的 `UTF-8` 序列表示的表情符号。`dongle` 支持标准和流式 `Base100` 编码。

### 编码数据
输入数据

```go
// 输入字符串
encoder := dongle.Encode.FromString("hello world").ByBase100()
// 输入字节切片
encoder := dongle.Encode.FromBytes([]byte("hello world")).ByBase100()
// 输入文件流
file, _ := os.Open("test.txt")
encoder := dongle.Encode.FromFile(file).ByBase100()

// 检查编码错误
if encoder.Error != nil {
	fmt.Printf("编码错误: %v\n", encoder.Error)
	return
}
```

输出数据

```go
// 输出字符串
encoder.ToString() // 👟👜👣👣👦🐗👮👦👩👣👛
// 输出字节切片
encoder.ToBytes()  // []byte("👟👜👣👣👦🐗👮👦👩👣👛")
```

### 解码数据
输入数据

```go
// 输入字符串
decoder := dongle.Decode.FromString("👟👜👣👣👦🐗👮👦👩👣👛").ByBase100()
// 输入字节切片
decoder := dongle.Decode.FromBytes([]byte("👟👜👣👣👦🐗👮👦👩👣👛")).ByBase100()
// 输入文件流
file, _ := os.Open("test.txt")
decoder := dongle.Decode.FromFile(file).ByBase100()

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

 