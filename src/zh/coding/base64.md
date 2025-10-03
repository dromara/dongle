---
title: Base64 编码/解码
head:
  - - meta
    - name: description
      content: Base64 编码/解码 | 一个轻量级、语义化、对开发者友好的 golang 编码&密码库
  - - meta
    - name: keywords
      content: dongle, base64, base64url
---

# Base64

Base64 是一种将二进制数据编码为 `ASCII` 字符的编码方式，使用 `64` 个字符（A-Z, a-z, 0-9, +, /）来表示数据。`dongle` 支持标准和流式 `Base64` 编码以及标准和流式 `Base64Url` 编码。

- [Base64Std](#base64std)
- [Base64Url](#base64url)

## Base64Std
> 默认字符集为 `ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/`,
> 可以通过设置 `base64.StdAlphabet` 来自定义字符集

### 编码数据
输入数据

```go
// 输入字符串
encoder := dongle.Encode.FromString("hello world").ByBase64()
// 输入字节切片
encoder := dongle.Encode.FromBytes([]byte("hello world")).ByBase64()
// 输入文件流
file, _ := os.Open("test.txt")
encoder := dongle.Encode.FromFile(file).ByBase64()

// 检查编码错误
if encoder.Error != nil {
	fmt.Printf("编码错误: %v\n", encoder.Error)
	return
}
```

输出数据

```go
// 输出字符串
encoder.ToString() // aGVsbG8gd29ybGQ=
// 输出字节切片
encoder.ToBytes()  // []byte("aGVsbG8gd29ybGQ=")
```

### 解码数据
输入数据

```go
// 输入字符串
decoder := dongle.Decode.FromString("aGVsbG8gd29ybGQ=").ByBase64()
// 输入字节切片
decoder := dongle.Decode.FromBytes([]byte("aGVsbG8gd29ybGQ=")).ByBase64()
// 输入文件流
file, _ := os.Open("test.txt")
decoder := dongle.Decode.FromFile(file).ByBase64()

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

## Base64Url

> 默认字符集为 `ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_`,
> 可以通过设置 `base64.URLAlphabet` 来自定义字符集

### 编码数据
输入数据

```go
// 输入字符串
encoder := dongle.Encode.FromString("https://dongle.go-pkg.com/api/v1/data+test").ByBase64Url()
// 输入字节切片
encoder := dongle.Encode.FromBytes([]byte("https://dongle.go-pkg.com/api/v1/data+test")).ByBase64Url()
// 输入文件流
file, _ := os.Open("test.txt")
encoder := dongle.Encode.FromFile(file).ByBase64Url()

// 检查编码错误
if encoder.Error != nil {
	fmt.Printf("编码错误: %v\n", encoder.Error)
	return
}
```

输出数据

```go
// 输出字符串
encoder.ToString() // aHR0cHM6Ly9kb25nbGUuZ28tcGtnLmNvbS9hcGkvdjEvZGF0YSt0ZXN0
// 输出字节切片
encoder.ToBytes()  // []byte("aHR0cHM6Ly9kb25nbGUuZ28tcGtnLmNvbS9hcGkvdjEvZGF0YSt0ZXN0")
```

### 解码数据
输入数据

```go
// 输入字符串
decoder := dongle.Decode.FromString("aHR0cHM6Ly9kb25nbGUuZ28tcGtnLmNvbS9hcGkvdjEvZGF0YSt0ZXN0").ByBase64Url()
// 输入字节切片
decoder := dongle.Decode.FromBytes([]byte("aHR0cHM6Ly9kb25nbGUuZ28tcGtnLmNvbS9hcGkvdjEvZGF0YSt0ZXN0")).ByBase64Url()
// 输入文件流
file, _ := os.Open("test.txt")
decoder := dongle.Decode.FromFile(file).ByBase64Url()

// 检查解码错误
if decoder.Error != nil {
	fmt.Printf("解码错误: %v\n", decoder.Error)
	return
}
```

输出数据

```go
// 输出字符串
decoder.ToString() // https://dongle.go-pkg.com/api/v1/data+test
// 输出字节切片
decoder.ToBytes()  // []byte("https://dongle.go-pkg.com/api/v1/data+test")
```


