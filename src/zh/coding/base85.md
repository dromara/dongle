---
title: Base85 编码/解码
head:
  - - meta
    - name: description
      content: Base85 编码/解码 | 一个轻量级、语义化、对开发者友好的 golang 编码&密码库
  - - meta
    - name: keywords
      content: dongle, base85, ascii85
---

# Base85

Base85 是一种将二进制数据编码为 `ASCII` 字符的编码方式，使用 `85` 个字符（ASCII 33-117，即 ! 到 u）来表示数据。`dongle` 支持标准和流式 `Base85` 编码，也称为 `ASCII85`，符合 `Adobe PostScript` 和 `PDF` 规范。

### 编码数据
输入数据

```go
// 输入字符串
encoder := dongle.Encode.FromString("hello world").ByBase85()
// 输入字节切片
encoder := dongle.Encode.FromBytes([]byte("hello world")).ByBase85()
// 输入文件流
file, _ := os.Open("test.txt")
encoder := dongle.Encode.FromFile(file).ByBase85()

// 检查编码错误
if encoder.Error != nil {
	fmt.Printf("编码错误: %v\n", encoder.Error)
	return
}
```

输出数据

```go
// 输出字符串
encoder.ToString() // BOu!rD]j7BEbo7
// 输出字节切片
encoder.ToBytes()  // []byte("BOu!rD]j7BEbo7")
```

### 解码数据
输入数据

```go
// 输入字符串
decoder := dongle.Decode.FromString("BOu!rD]j7BEbo7").ByBase85()
// 输入字节切片
decoder := dongle.Decode.FromBytes([]byte("BOu!rD]j7BEbo7")).ByBase85()
// 输入文件流
file, _ := os.Open("test.txt")
decoder := dongle.Decode.FromFile(file).ByBase85()

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

 