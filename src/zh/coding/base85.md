---
title: Base85 编码/解码
head:
  - - meta
    - name: description
      content: Base85 编码/解码，也称 ASCII85，符合 Adobe PostScript 和 PDF 规范，使用 85 个字符（ASCII 33-117），支持标准和流式处理，支持字符串、字节与文件输入，提供字符串与字节输出
  - - meta
    - name: keywords
      content: dongle, go-dongle, 编码, 解码, Base85, ASCII85, Adobe PostScript, PDF, 流式处理, 字符串输入, 字节输入, 文件输入, 字符串输出, 字节输出
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

 