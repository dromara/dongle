---
title: Unicode 编码/解码
head:
  - - meta
    - name: description
      content: Unicode 编码/解码，使用 \uXXXX 转义序列表示非 ASCII 字符，基于 strconv.QuoteToASCII 实现，支持标准和流式处理，支持字符串、字节与文件输入，提供字符串与字节输出
  - - meta
    - name: keywords
      content: dongle, go-dongle, 编码, 解码, Unicode, 转义序列, \uXXXX, ASCII, strconv.QuoteToASCII, 流式处理, 字符串输入, 字节输入, 文件输入, 字符串输出, 字节输出
---

# Unicode

Unicode 是一种将字节数据编码为 `Unicode` 转义序列的编码方式，使用 `\uXXXX` 格式来表示非 `ASCII` 字符。`dongle` 支持标准和流式 `Unicode` 编码，基于 `strconv.QuoteToASCII` 实现。

### 编码数据
输入数据

```go
// 输入字符串
encoder := dongle.Encode.FromString("你好世界").ByUnicode()
// 输入字节切片
encoder := dongle.Encode.FromBytes([]byte("你好世界")).ByUnicode()
// 输入文件流
file, _ := os.Open("test.txt")
encoder := dongle.Encode.FromFile(file).ByUnicode()

// 检查编码错误
if encoder.Error != nil {
    fmt.Printf("编码错误: %v\n", encoder.Error)
    return
}
```

输出数据

```go
// 输出字符串
encoder.ToString() // \u4f60\u597d\u4e16\u754c
// 输出字节切片
encoder.ToBytes()  // []byte("\u4f60\u597d\u4e16\u754c")
```

### 解码数据
输入数据

```go
// 输入字符串
decoder := dongle.Decode.FromString("\u4f60\u597d\u4e16\u754c").ByUnicode()
// 输入字节切片
decoder := dongle.Decode.FromBytes([]byte("\u4f60\u597d\u4e16\u754c")).ByUnicode()
// 输入文件流
file, _ := os.Open("test.txt")
decoder := dongle.Decode.FromFile(file).ByUnicode()

// 检查解码错误
if decoder.Error != nil {
    fmt.Printf("解码错误: %v\n", decoder.Error)
    return
}
```

输出数据

```go
// 输出字符串
decoder.ToString() // 你好世界
// 输出字节切片
decoder.ToBytes()  // []byte("你好世界")
```

