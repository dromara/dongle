---
title: SHA2 消息认证码算法
head:
  - - meta
    - name: description
      content: HMAC-SHA2 消息认证码算法，基于 SHA2 哈希算法，使用密钥进行消息认证，提供 sha2-224、sha2-256、sha2-384 与 sha2-512 四种变体，支持标准和流式处理，支持字符串、字节与文件输入，支持 Hex 和 Base64 输出格式
  - - meta
    - name: keywords
      content: dongle, go-dongle, HMAC, 消息认证码, SHA2, sha2-224, sha2-256, sha2-384, sha2-512, 密钥, 流式处理, 字符串输入, 字节输入, 文件输入, Hex, Base64
---

# Hmac-Sha2

`Hmac-Sha2` 是一系列基于 `sha2` 的消息认证码算法，包括 `sha2-224`、`sha2-256`、`sha2-384` 和 `sha2-512`，`dongle` 支持所有四种 `sha2` 消息认证码算法变体。

- [Sha2-224](#sha2-224)：生成 28 字节哈希值
- [Sha2-256](#sha2-256)：生成 32 字节哈希值
- [Sha2-384](#sha2-384)：生成 48 字节哈希值
- [Sha2-512](#sha2-512)：生成 64 字节哈希值

> 注意：`WithKey` 方法必须在 `BySha2` 之前调用

## Sha2-224

### 输入数据

```go
// 输入字符串
hasher := dongle.Hash.FromString("hello world").WithKey([]byte("dongle")).BySha2(224)

// 输入字节切片
hasher := dongle.Hash.FromBytes([]byte("hello world")).WithKey([]byte("dongle")).BySha2(224)

// 输入文件流
file, _ := os.Open("test.txt")
hasher := dongle.Hash.FromFile(file).WithKey([]byte("dongle")).BySha2(224)

// 检查 HMAC 错误
if hasher.Error != nil {
	fmt.Printf("HMAC 错误: %v\n", hasher.Error)
	return
}
```

### 输出数据

```go
// 输出 Hex 编码字符串
hasher.ToHexString() // e15b9e5a7eccb1f17dc81dc07c909a891936dc3429dc0d940accbcec
// 输出 Hex 编码字节切片
hasher.ToHexBytes()  // []byte("e15b9e5a7eccb1f17dc81dc07c909a891936dc3429dc0d940accbcec")

// 输出 Base64 编码字符串
hasher.ToBase64String() // 4VueWn7MsfF9yB3AfJCaiRk23DQp3A2UCsy87A==
// 输出 Base64 编码字节切片
hasher.ToBase64Bytes()  // []byte("4VueWn7MsfF9yB3AfJCaiRk23DQp3A2UCsy87A==")

// 输出未编码原始字符串
hasher.ToRawString()
// 输出未编码原始字节切片
hasher.ToRawBytes()
```

## Sha2-256

### 输入数据

```go
// 输入字符串
hasher := dongle.Hash.FromString("hello world").WithKey([]byte("dongle")).BySha2(256)

// 输入字节切片
hasher := dongle.Hash.FromBytes([]byte("hello world")).WithKey([]byte("dongle")).BySha2(256)

// 输入文件流
file, _ := os.Open("test.txt")
hasher := dongle.Hash.FromFile(file).WithKey([]byte("dongle")).BySha2(256)

// 检查 HMAC 错误
if hasher.Error != nil {
	fmt.Printf("HMAC 错误: %v\n", hasher.Error)
	return
}
```

### 输出数据

```go
// 输出 Hex 编码字符串
hasher.ToHexString() // 77f5c8ce4147600543e70b12701e7b78b5b95172332ebbb06de65fcea7112179
// 输出 Hex 编码字节切片
hasher.ToHexBytes()  // []byte("77f5c8ce4147600543e70b12701e7b78b5b95172332ebbb06de65fcea7112179")

// 输出 Base64 编码字符串
hasher.ToBase64String() // d/XIzkFHYAVD5wsScB57eLW5UXIzLruwbeZfzqcRIXk=
// 输出 Base64 编码字节切片
hasher.ToBase64Bytes()  // []byte("d/XIzkFHYAVD5wsScB57eLW5UXIzLruwbeZfzqcRIXk=")

// 输出未编码原始字符串
hasher.ToRawString()
// 输出未编码原始字节切片
hasher.ToRawBytes()
```

## Sha2-384

### 输入数据

```go
// 输入字符串
hasher := dongle.Hash.FromString("hello world").WithKey([]byte("dongle")).BySha2(384)

// 输入字节切片
hasher := dongle.Hash.FromBytes([]byte("hello world")).WithKey([]byte("dongle")).BySha2(384)

// 输入文件流
file, _ := os.Open("test.txt")
hasher := dongle.Hash.FromFile(file).WithKey([]byte("dongle")).BySha2(384)

// 检查 HMAC 错误
if hasher.Error != nil {
	fmt.Printf("HMAC 错误: %v\n", hasher.Error)
	return
}
```

### 输出数据

```go
// 输出 Hex 编码字符串
hasher.ToHexString() // 421fcaa740216a31bbcd1f86f2212e0c68aa4b156a8ebc2ae55b3e75c4ee0509ea0325a0570ae739006b61d91d91d817fe8
// 输出 Hex 编码字节切片
hasher.ToHexBytes()  // []byte("421fcaa740216a31bbcd1f86f2212e0c68aa4b156a8ebc2ae55b3e75c4ee0509ea0325a0570ae739006b61d91d817fe8")

// 输出 Base64 编码字符串
hasher.ToBase64String() // Qh/Kp0AhajG7zR+G8iEuDGiqSxVqjrwq5Vs+dcTuBQnqAyWgVwrnOQBrYdkdgX/o
// 输出 Base64 编码字节切片
hasher.ToBase64Bytes()  // []byte("Qh/Kp0AhajG7zR+G8iEuDGiqSxVqjrwq5Vs+dcTuBQnqAyWgVwrnOQBrYdkdgX/o")

// 输出未编码原始字符串
hasher.ToRawString()
// 输出未编码原始字节切片
hasher.ToRawBytes()
```

## Sha2-512

### 输入数据

```go
// 输入字符串
hasher := dongle.Hash.FromString("hello world").WithKey([]byte("dongle")).BySha2(512)

// 输入字节切片
hasher := dongle.Hash.FromBytes([]byte("hello world")).WithKey([]byte("dongle")).BySha2(512)

// 输入文件流
file, _ := os.Open("test.txt")
hasher := dongle.Hash.FromFile(file).WithKey([]byte("dongle")).BySha2(512)

// 检查 HMAC 错误
if hasher.Error != nil {
	fmt.Printf("HMAC 错误: %v\n", hasher.Error)
	return
}
```

### 输出数据

```go
// 输出 Hex 编码字符串
hasher.ToHexString() // d971b790bbc2a4ac81062bbffac693c9c234bae176c8faf5e304dbdb153032a826f12353964b4a4fb87abecd2dc237638a630cbad54a6b94b1f6ef5d5e2835d1
// 输出 Hex 编码字节切片
hasher.ToHexBytes()  // []byte("d971b790bbc2a4ac81062bbffac693c9c234bae176c8faf5e304dbdb153032a826f12353964b4a4fb87abecd2dc237638a630cbad54a6b94b1f6ef5d5e2835d1")

// 输出 Base64 编码字符串
hasher.ToBase64String() // 2XG3kLvCpKyBBiu/+saTycI0uuF2yPr14wTb2xUwMqgm8SNTlktKT7h6vs0twjdjimMMutVKa5Sx9u9dXig10Q==
// 输出 Base64 编码字节切片
hasher.ToBase64Bytes()  // []byte("2XG3kLvCpKyBBiu/+saTycI0uuF2yPr14wTb2xUwMqgm8SNTlktKT7h6vs0twjdjimMMutVKa5Sx9u9dXig10Q==")

// 输出未编码原始字符串
hasher.ToRawString()
// 输出未编码原始字节切片
hasher.ToRawBytes()
```





