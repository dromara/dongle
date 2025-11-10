---
title: Blake2b 哈希算法
head:
  - - meta
    - name: description
      content: Blake2b 哈希算法，提供 blake2b-256、blake2b-384 与 blake2b-512 三种变体，支持标准和流式处理，支持字符串、字节与文件输入，支持 Hex 和 Base64 输出格式
  - - meta
    - name: keywords
      content: dongle, go-dongle, 哈希, 摘要, 校验, Blake2b, blake2b-256, blake2b-384, blake2b-512, 流式处理, 字符串输入, 字节输入, 文件输入, Hex, Base64
---

# Hash-Blake2b

`Hash-Blake2b` 是一系列产生不同长度哈希值的哈希算法，包括 `blake2b-256`、`blake2b-384` 和 `blake2b-512`，`dongle` 支持所有三种 `hash-blake2b` 变体。

- [Blake2b-256](#blake2b-256)：生成 32 字节哈希值
- [Blake2b-384](#blake2b-384)：生成 48 字节哈希值
- [Blake2b-512](#blake2b-512)：生成 64 字节哈希值

## Blake2b-256

### 输入数据

```go
// 输入字符串
hasher := dongle.Hash.FromString("hello world").ByBlake2b(256)
// 输入字节切片
hasher := dongle.Hash.FromBytes([]byte("hello world")).ByBlake2b(256)
// 输入文件流
file, _ := os.Open("test.txt")
hasher := dongle.Hash.FromFile(file).ByBlake2b(256)

// 检查哈希错误
if hasher.Error != nil {
	fmt.Printf("哈希错误: %v\n", hasher.Error)
	return
}
```

### 输出数据

```go
// 输出 Hex 编码字符串
hasher.ToHexString() // 256c83b297114d201b30179f3f0ef0cace9783622da5974326b436178aeef610
// 输出 Hex 编码字节切片
hasher.ToHexBytes()  // []byte("256c83b297114d201b30179f3f0ef0cace9783622da5974326b436178aeef610")

// 输出 Base64 编码字符串
hasher.ToBase64String() // JWyDspcRTSAbMBefPw7wys6Xg2ItpZdDJrQ2F4ru9hA=
// 输出 Base64 编码字节切片
hasher.ToBase64Bytes()  // []byte("JWyDspcRTSAbMBefPw7wys6Xg2ItpZdDJrQ2F4ru9hA=")

// 输出未编码原始字符串
hasher.ToRawString()
// 输出未编码原始字节切片
hasher.ToRawBytes()
```

## Blake2b-384

### 输入数据

```go
// 输入字符串
hasher := dongle.Hash.FromString("hello world").ByBlake2b(384)
// 输入字节切片
hasher := dongle.Hash.FromBytes([]byte("hello world")).ByBlake2b(384)
// 输入文件流
file, _ := os.Open("test.txt")
hasher := dongle.Hash.FromFile(file).ByBlake2b(384)

// 检查哈希错误
if hasher.Error != nil {
	fmt.Printf("哈希错误: %v\n", hasher.Error)
	return
}
```

### 输出数据

```go
// 输出 Hex 编码字符串
hasher.ToHexString() // 8c653f8c9c9aa2177fb6f8cf5bb914828faa032d7b486c8150663d3f6524b086784f8e62693171ac51fc80b7d2cbb12b
// 输出 Hex 编码字节切片
hasher.ToHexBytes()  // []byte("8c653f8c9c9aa2177fb6f8cf5bb914828faa032d7b486c8150663d3f6524b086784f8e62693171ac51fc80b7d2cbb12b")

// 输出 Base64 编码字符串
hasher.ToBase64String() // jGU/jJyaohd/tvjPW7kUgo+qAy17SGyBUGY9P2UksIZ4T45iaTFxrFH8gLfSy7Er
// 输出 Base64 编码字节切片
hasher.ToBase64Bytes()  // []byte("jGU/jJyaohd/tvjPW7kUgo+qAy17SGyBUGY9P2UksIZ4T45iaTFxrFH8gLfSy7Er")

// 输出未编码原始字符串
hasher.ToRawString()
// 输出未编码原始字节切片
hasher.ToRawBytes()
```

## Blake2b-512

### 输入数据

```go
// 输入字符串
hasher := dongle.Hash.FromString("hello world").ByBlake2b(512)
// 输入字节切片
hasher := dongle.Hash.FromBytes([]byte("hello world")).ByBlake2b(512)
// 输入文件流
file, _ := os.Open("test.txt")
hasher := dongle.Hash.FromFile(file).ByBlake2b(512)

// 检查哈希错误
if hasher.Error != nil {
	fmt.Printf("哈希错误: %v\n", hasher.Error)
	return
}
```

### 输出数据

```go
// 输出 Hex 编码字符串
hasher.ToHexString() // 021ced8799296ceca557832ab941a50b4a11f83478cf141f51f933f653ab9fbcc05a037cddbed06e309bf334942c4e58cdf1a46e237911ccd7fcf9787cbc7fd0
// 输出 Hex 编码字节切片
hasher.ToHexBytes()  // []byte("021ced8799296ceca557832ab941a50b4a11f83478cf141f51f933f653ab9fbcc05a037cddbed06e309bf334942c4e58cdf1a46e237911ccd7fcf9787cbc7fd0")

// 输出 Base64 编码字符串
hasher.ToBase64String() // Ahzth5kpbOylV4MquUGlC0oR+DR4zxQfUfkz9lOrn7zAWgN83b7QbjCb8zSULE5YzfGkbiN5EczX/Pl4fLx/0A==
// 输出 Base64 编码字节切片
hasher.ToBase64Bytes()  // []byte("Ahzth5kpbOylV4MquUGlC0oR+DR4zxQfUfkz9lOrn7zAWgN83b7QbjCb8zSULE5YzfGkbiN5EczX/Pl4fLx/0A==")

// 输出未编码原始字符串
hasher.ToRawString()
// 输出未编码原始字节切片
hasher.ToRawBytes()
```