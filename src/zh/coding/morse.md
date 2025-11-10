---
title: Morse 编码/解码
head:
  - - meta
    - name: description
      content: Morse 编码/解码，遵循国际摩尔斯电码标准（ITU-R M.1677-1），支持自定义字典与分隔符，支持标准和流式处理，支持字符串、字节与文件输入，提供字符串与字节输出
  - - meta
    - name: keywords
      content: dongle, go-dongle, 编码, 解码, Morse, 摩尔斯电码, 摩斯码, ITU-R M.1677-1, 字典, 分隔符, 流式处理, 字符串输入, 字节输入, 文件输入, 字符串输出, 字节输出
---

# Morse

Morse 是一种将文本编码为点和划序列的编码方式，遵循国际摩尔斯电码标准（ITU-R M.1677-1）。`dongle` 支持标准和流式 `Morse` 编码，将字母、数字和标点符号转换为标准化的点和划序列。
> 默认分隔符是`空格`,
> 可以通过设置 `morse.StdSeparator` 来自定义分隔符

### 编码数据

```go
// 输入字符串
encoder := dongle.Encode.FromString("hello world").ByMorse()
// 输入字节切片
encoder := dongle.Encode.FromBytes([]byte("hello world")).ByMorse()
// 输入文件流
file, _ := os.Open("test.txt")
encoder := dongle.Encode.FromFile(file).ByMorse()

// 检查编码错误
if encoder.Error != nil {
	fmt.Printf("编码错误: %v\n", encoder.Error)
	return
}
```

输出数据

```go
// 输出字符串
encoder.ToString() // .... . .-.. .-.. --- / .-- --- .-. .-.. -..
// 输出字节切片
encoder.ToBytes()  // []byte(".... . .-.. .-.. --- / .-- --- .-. .-.. -..")
```

### 解码数据
输入数据

```go
// 输入字符串
decoder := dongle.Decode.FromString(".... . .-.. .-.. --- / .-- --- .-. .-.. -..").ByMorse()
// 输入字节切片
decoder := dongle.Decode.FromBytes([]byte(".... . .-.. .-.. --- / .-- --- .-. .-.. -..")).ByMorse()
// 输入文件流
file, _ := os.Open("test.txt")
decoder := dongle.Decode.FromFile(file).ByMorse()

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


