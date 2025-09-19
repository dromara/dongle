---
head:
  - - meta
    - name: description
      content: HMAC-SHA1算法|一个轻量级、语义化、对开发者友好的 golang 编码&密码库
  - - meta
    - name: keywords
      content: HMAC-SHA1
---

# Hmac-Sha1

`Hmac-Sha1` 是一种基于 `sha1` 的消息认证码算法，`dongle` 支持标准 `sha1` 消息认证码算法，提供多种输出格式。

> 注意：`WithKey` 方法必须在 `BySha1` 之前调用

## 输入数据

```go
// 输入字符串
hasher := dongle.Hash.FromString("hello world").WithKey([]byte("dongle")).BySha1()
// 输入字节切片
hasher := dongle.Hash.FromBytes([]byte("hello world")).WithKey([]byte("dongle")).BySha1()
// 输入文件流
file, _ := os.Open("test.txt")
hasher := dongle.Hash.FromFile(file).WithKey([]byte("dongle")).BySha1()

// 检查 HMAC 错误
if hasher.Error != nil {
	fmt.Printf("HMAC 错误: %v\n", hasher.Error)
	return
}
```

## 输出数据

```go
// 输出 Hex 编码字符串
hasher.ToHexString() // 91c103ef93ba7420902b0d1bf0903251c94b4a62
// 输出 Hex 编码字节切片
hasher.ToHexBytes()  // []byte("91c103ef93ba7420902b0d1bf0903251c94b4a62")

// 输出 Base64 编码字符串
hasher.ToBase64String() // kcED75O6dCCQKw0b8JAyUclLSmI=
// 输出 Base64 编码字节切片
hasher.ToBase64Bytes()  // []byte("kcED75O6dCCQKw0b8JAyUclLSmI=")

// 输出未编码原始字符串
hasher.ToRawString()
// 输出未编码原始字节切片
hasher.ToRawBytes()
```
