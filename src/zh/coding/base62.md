---
title: Base62 编码/解码
head:
  - - meta
    - name: description
      content: Base62 编码/解码 | 一个轻量级、语义化、对开发者友好的 golang 编码&密码库
  - - meta
    - name: keywords
      content: dongle, base62
---

# Base62

Base62 是一种将二进制数据编码为 `ASCII` 字符的编码方式，使用 `62` 个字符（0-9, A-Z, a-z）来表示数据。`dongle` 支持标准 `Base62` 编码。

> 默认字符集为 `0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz`,
> 可以通过设置 `base62.StdAlphabet` 来自定义字符集

### 编码数据
输入数据

```go
// 输入字符串
encoder := dongle.Encode.FromString("hello world").ByBase62()
// 输入字节切片
encoder := dongle.Encode.FromBytes([]byte("hello world")).ByBase62()
// 输入文件流
file, _ := os.Open("test.txt")
encoder := dongle.Encode.FromFile(file).ByBase62()

// 检查编码错误
if encoder.Error != nil {
	fmt.Printf("编码错误: %v\n", encoder.Error)
	return
}
```

输出数据

```go
// 输出字符串
encoder.ToString() // AAwf93rvy4aWQVw
// 输出字节切片
encoder.ToBytes()  // []byte("AAwf93rvy4aWQVw")
```

### 解码数据
输入数据

```go
// 输入字符串
decoder := dongle.Decode.FromString("AAwf93rvy4aWQVw").ByBase62()
// 输入字节切片
decoder := dongle.Decode.FromBytes([]byte("AAwf93rvy4aWQVw")).ByBase62()
// 输入文件流
file, _ := os.Open("test.txt")
decoder := dongle.Decode.FromFile(file).ByBase62()

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

 