---
title: MD5 消息认证码算法
head:
  - - meta
    - name: description
      content: HMAC-MD5 消息认证码算法，基于 MD5 哈希算法，使用密钥进行消息认证，生成 16 字节认证码，支持标准和流式处理，支持字符串、字节与文件输入，支持 Hex 和 Base64 输出格式
  - - meta
    - name: keywords
      content: dongle, go-dongle, HMAC, 消息认证码, MD5, 密钥, 流式处理, 字符串输入, 字节输入, 文件输入, Hex, Base64
---

# Hmac-Md5

`Hmac-Md5` 是一种基于 `md5` 的消息认证码算法，`dongle` 支持标准和流式 `md5` 消息认证码算法，提供多种输出格式。

> 注意：`WithKey` 方法必须在 `ByMd5` 之前调用

## 输入数据

```go
// 输入字符串
hasher := dongle.Hash.FromString("hello world").WithKey([]byte("dongle")).ByMd5()
// 输入字节切片
hasher := dongle.Hash.FromBytes([]byte("hello world")).WithKey([]byte("dongle")).ByMd5()
// 输入文件流
file, _ := os.Open("test.txt")
hasher := dongle.Hash.FromFile(file).WithKey([]byte("dongle")).ByMd5()

// 检查 HMAC 错误
if hasher.Error != nil {
	fmt.Printf("HMAC 错误: %v\n", hasher.Error)
	return
}
```

## 输出数据

```go
// 输出 Hex 编码字符串
hasher.ToHexString() // 4790626a275f776956386e5a3ea7b726
// 输出 Hex 编码字节切片
hasher.ToHexBytes()  // []byte("4790626a275f776956386e5a3ea7b726")

// 输出 Base64 编码字符串
hasher.ToBase64String() // R5Biaidfd2lWOG5aPqe3Jg==
// 输出 Base64 编码字节切片
hasher.ToBase64Bytes()  // []byte("R5Biaidfd2lWOG5aPqe3Jg==")

// 输出未编码原始字符串
hasher.ToRawString()
// 输出未编码原始字节切片
hasher.ToRawBytes()
```
