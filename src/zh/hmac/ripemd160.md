---
title: Ripemd160 消息认证码算法
head:
  - - meta
    - name: description
      content: Ripemd160 消息认证码算法 | 一个轻量级、语义化、对开发者友好的 golang 密码库
  - - meta
    - name: keywords
      content: 消息认证码, hmac, ripemd160, hmac-ripemd160
---

# Hmac-Ripemd160

`Hmac-Ripemd160` 是一种基于 `ripemd160` 的消息认证码算法，`dongle` 支持标准和流式 `ripemd160` 消息认证码算法，提供多种输出格式。

> 注意：`WithKey` 方法必须在 `ByRipemd160` 之前调用

## 输入数据

```go
// 输入字符串
hasher := dongle.Hash.FromString("hello world").WithKey([]byte("dongle")).ByRipemd160()
// 输入字节切片
hasher := dongle.Hash.FromBytes([]byte("hello world")).WithKey([]byte("dongle")).ByRipemd160()
// 输入文件流
file, _ := os.Open("test.txt")
hasher := dongle.Hash.FromFile(file).WithKey([]byte("dongle")).ByRipemd160()

// 检查 HMAC 错误
if hasher.Error != nil {
	fmt.Printf("HMAC 错误: %v\n", hasher.Error)
	return
}
```

## 输出数据

```go
// 输出 Hex 编码字符串
hasher.ToHexString() // 3691ad040e80c43dc6e8ffe9bc6ef3d5bd8786b8
// 输出 Hex 编码字节切片
hasher.ToHexBytes()  // []byte("3691ad040e80c43dc6e8ffe9bc6ef3d5bd8786b8")

// 输出 Base64 编码字符串
hasher.ToBase64String() // NpGtBA6AxD3G6P/pvG7z1b2Hhrg=
// 输出 Base64 编码字节切片
hasher.ToBase64Bytes()  // []byte("NpGtBA6AxD3G6P/pvG7z1b2Hhrg=")

// 输出未编码原始字符串
hasher.ToRawString()
// 输出未编码原始字节切片
hasher.ToRawBytes()
```
