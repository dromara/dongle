---
title: Base100 编码/解码
head:
  - - meta
    - name: description
      content: Base100 编码/解码 | 一个轻量级、语义化、对开发者友好的 golang 编码&密码库
  - - meta
    - name: keywords
      content: dongle, base100, emoji
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

 