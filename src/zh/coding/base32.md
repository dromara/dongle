---
title: Base32 编码/解码
head:
  - - meta
    - name: description
      content: Base32 编码/解码，支持 Base32 与 Base32Hex 两种变体，支持自定义字母表，支持标准和流式处理，支持字符串、字节与文件输入，提供字符串与字节输出
  - - meta
    - name: keywords
      content: dongle, go-dongle, 编码, 解码, Base32, Base32Hex, 字母表, 自定义字符集, 流式处理, 字符串输入, 字节输入, 文件输入, 字符串输出, 字节输出
---

# Base32

Base32 是一种将二进制数据编码为 `ASCII` 字符的编码方式，使用 `32` 个字符（A-Z, 2-7）来表示数据。`dongle` 支持标准和流式 `Base32` 和 `Base32Hex` 两种变体。

- [Base32Std](#base32std)
- [Base32Hex](#base32hex)

## Base32Std
> 默认字符集为 `ABCDEFGHIJKLMNOPQRSTUVWXYZ234567`,
> 可以通过设置 `base32.StdAlphabet` 来自定义字符集

### 编码数据
输入数据

```go
// 输入字符串
encoder := dongle.Encode.FromString("hello world").ByBase32()
// 输入字节切片
encoder := dongle.Encode.FromBytes([]byte("hello world")).ByBase32()
// 输入文件流
file, _ := os.Open("test.txt")
encoder := dongle.Encode.FromFile(file).ByBase32()

// 检查编码错误
if encoder.Error != nil {
	fmt.Printf("编码错误: %v\n", encoder.Error)
	return
}
```

输出数据

```go
// 输出字符串
encoder.ToString() // NBSWY3DPEB3W64TMMQ======
// 输出字节切片
encoder.ToBytes()  // []byte("NBSWY3DPEB3W64TMMQ======")
```

### 解码数据
输入数据

```go
// 输入字符串
decoder := dongle.Decode.FromString("NBSWY3DPEB3W64TMMQ======").ByBase32()
// 输入字节切片
decoder := dongle.Decode.FromBytes([]byte("NBSWY3DPEB3W64TMMQ======")).ByBase32()
// 输入文件流
file, _ := os.Open("test.txt")
decoder := dongle.Decode.FromFile(file).ByBase32()

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

## Base32Hex

> 默认字符集为 `0123456789ABCDEFGHIJKLMNOPQRSTUV`,
> 可以通过设置 `base32.HexAlphabet` 来自定义字符集

### 编码数据
输入数据

```go
// 输入字符串
encoder := dongle.Encode.FromString("hello world").ByBase32Hex()
// 输入字节切片
encoder := dongle.Encode.FromBytes([]byte("hello world")).ByBase32Hex()
// 输入文件流
file, _ := os.Open("test.txt")
encoder := dongle.Encode.FromFile(file).ByBase32Hex()

// 检查编码错误
if encoder.Error != nil {
	fmt.Printf("编码错误: %v\n", encoder.Error)
	return
}
```

输出数据

```go
// 输出字符串
encoder.ToString() // D1IMOR3F41RMUSJCCG======
// 输出字节切片
encoder.ToBytes()  // []byte("D1IMOR3F41RMUSJCCG======")
```

### 解码数据
输入数据

```go
// 输入字符串
decoder := dongle.Decode.FromString("D1IMOR3F41RMUSJCCG======").ByBase32Hex()
// 输入字节切片
decoder := dongle.Decode.FromBytes([]byte("D1IMOR3F41RMUSJCCG======")).ByBase32Hex()
// 输入文件流
file, _ := os.Open("test.txt")
decoder := dongle.Decode.FromFile(file).ByBase32Hex()

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


