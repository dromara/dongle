---
head:
  - - meta
    - name: description
      content: 更新日志|一个轻量级、语义化、对开发者友好的 golang 时间处理库
---

# 更新日志
## [v1.2.1](https://github.com/dromara/dongle/compare/v1.2.0...v1.2.1) (2025-11-24)

* 修复 `Sm2` 非对称椭圆曲线加密算法中 `wNAF` 算法错误造成某些情况下解密失败的 `bug`
* 优化 `Sm2` 非对称椭圆曲线加密算法中曲线域元素运算实现
* 增加 `Sm2` 非对称椭圆曲线加密算法对 `BIT_STRING` 格式密钥直接解析支持
* 简化测试循环语法，从 `for` 循环改为 `range` 循环

## [v1.2.0](https://github.com/dromara/dongle/compare/v1.1.8...v1.2.0) (2025-11-11)

* 移除 `RSAKeyPair` 结构体的 `LoadPublicKey` 和 `LoadPrivateKey` 方法
* 移除 `Ed25519KeyPair` 结构体的 `LoadPublicKey` 和 `LoadPrivateKey` 方法
* 优化编码器和解码器性能，重用读缓冲区，减少内存分配和复制
* `RSAKeyPair` 结构体的 `GenKeyPair`, `SetPublicKey`, `SetPrivateKey` 方法从无返回值改为返回 `error`
* `Ed25519KeyPair` 结构体的 `GenKeyPair`, `SetPublicKey`, `SetPrivateKey` 方法从无返回值改为返回 `error`
* `RSAKeyPair` 结构体增加 `FormatPublicKey` 和 `FormatPrivateKey` 方法，用于将 `base64` 编码的 `der` 格式的 `RSA` 公钥和私钥格式化成 `pem` 格式
* `Ed25519KeyPair` 结构体增加 `FormatPublicKey`和 `FormatPrivateKey` 方法，用于将 `base64` 编码的 `der` 格式的 `Ed25519` 公钥和私钥格式化成 `pem` 格式
*  `RSAKeyPair` 结构体增加 `CompressPublicKey` 和 `CompressPrivateKey` 方法，用于将 `pem` 格式的 `RSA` 公钥和私钥压缩成经过 `base64` 编码的 `der` 格式
*  `Ed25519KeyPair` 结构体增加 `CompressPublicKey`和 `CompressPrivateKey` 方法，用于将 `pem` 格式的 `Ed25519` 公钥和私钥压缩成经过 `base64` 编码的 `der` 格式
*  增加 `Sm2` 非对称椭圆曲线加密算法支持，包括标准处理和流式处理

## [v1.1.8](https://github.com/dromara/dongle/compare/v1.1.7...v1.1.8) (2025-11-05)
* 修复 `*RsaKeyPair.formatPublicKey` 和 `*RsaKeyPair.formatPrivateKey` 格式化密钥失败的 bug
* 修复 `*Ed25519KeyPair.formatPublicKey` 和 `*Ed25519KeyPair.formatPrivateKey` 格式化密钥失败的 bug
* 修复解密时对编码过的密文解码失败后无法获取错误的 bug
* 对称分组加密算法中默认填充模式从 `PKCS7` 改为 `No`
* 增加 `Unicode` 编码解码支持，包括标准处理和流式处理
* 对称分组加密算法增加 `TBC` 填充模式支持

## [v1.1.7](https://github.com/dromara/dongle/compare/v1.1.6...v1.1.7) (2025-10-20)

* 修复非对称数字签名算法中验签错误的 bug [#30](https://github.com/dromara/dongle/issues)
* 优化流式处理逻辑，添加对 `reader` 位置重置的支持，确保从数据源的开头开始读取，避免因之前读取操作导致的位置偏移问题，保证流式操作的完整性和正确性
* `crypto/cipher/block.go` 中 `newXXXEncrypter` 和 `newXXXDecrypter` 系列私有方法更改成公开方法 `NewXXXEncrypter` 和 `NewXXXDecrypter`
* `crypto/cipher/padding.go` 中 `newXXXPadding` 和 `newXXXUnPadding` 系列私有方法更改成公开方法 `NewXXXPadding` 和 `NewXXXUnPadding`
* 增加 `sm4` 中国国家标准分组加密算法支持，包括标准处理和流式处理，支持不同分块模式和填充模式

## [v1.1.6](https://github.com/dromara/dongle/compare/v1.1.5...v1.1.6) (2025-10-12)

* 使用 `io.CopyBuffer` 简化流式处理逻辑
* 优化 `tea` 加密算法，支持不同分块模式和填充模式
* 增加 `xtea` 加密算法支持，包括标准处理和流式处理

## [v1.1.5](https://github.com/dromara/dongle/compare/v1.1.4...v1.1.5) (2025-10-01)

* 修复对称加密算法中对不需要填充的分组模式(如 CFB/OFB/CTR/GCM 等)进行填充时加解密错误的bug

## [v1.1.4](https://github.com/dromara/dongle/compare/v1.1.3...v1.1.4) (2025-09-23)

* 将方法接受者从指针改成值，防止出现使用全局默认实例时属性污染现象，调用方 `API` 没有任何影响
* 增加 `twofish` 加密算法支持，包括标准处理和流式处理

## [v1.1.3](https://github.com/dromara/dongle/compare/v1.1.2...v1.1.3) (2025-09-15)

* 优化 `3DES` 对称加密算法对 `16` 字节密钥的兼容
* 优化 `DES` 对称加密算法对不支持的 `GCM` 模式的校验
* 优化 `3DES` 对称加密算法对不支持的 `GCM` 模式的校验
* 优化 `Blowfish` 对称加密算法对不支持的 `GCM` 模式的校验
* 更新 `testify` 依赖至 `v1.11.1` 
* 增加 `Salsa20` 加密算法支持，包括标准处理和流式处理

## [v1.1.2](https://github.com/dromara/dongle/compare/v1.1.1...v1.1.2) (2025-09-08)

* 编码/解码支持通过 `coding.BufferSize` 全局变量自定义文件流缓冲区大小
* 加密/解密支持通过 `crypto.BufferSize` 全局变量自定义文件流缓冲区大小
* Hash/Hmac 算法支持通过 `hash.BufferSize` 全局变量自定义文件流缓冲区大小
* 增加 `Blake2b` 哈希算法支持，包括 `blake2b-256`、`blake2b-384` 和 `blake2b-512`
* 增加 `Blake2s` 哈希算法支持，包括 `blake2s-128` 和 `blake2s-256`
* 增加 `ChaCha20` 加密算法支持
* 增加 `ChaCha20Poly1305` 加密算法支持

## [v1.1.1](https://github.com/dromara/dongle/compare/v1.1.0...v1.1.1) (2025-09-01)

* 对称加密算法从 `ByXXX(cipher.XXXCipher)` 改成 `ByXXX(*cipher.XXXCipher)`
* 将工具包名从 `utils` 改成 `util`
* 编码/解码、加密/解密、Hash/Hmac、签名/验签支持真正的流式处理
* 当输入数据为空时，直接返回空数据而不执行后续操作
* 增加 `ED25519` 数字签名和验证支持
* 增加 `SM3` 哈希算法支持
* 增加 `mock/hash.go` 来模拟 `hash.Hash` 接口的错误
* `coding/morse/morse.go` 增加对空格、标点符号和特殊字符的支持

## [v1.1.0](https://github.com/dromara/dongle/compare/v1.0.1...v1.1.0) (2025-08-23)
> ⚠️ 这是一个破坏性更新版本，请慎重升级，但是强烈建议升级

* 删除 `BySafeURL` 编码/解码方法
* 删除 `Sm3` 哈希算法(`hash`)和消息认证码算法(`hmac`)
* 重命名 `ByBase64URL` 编码/解码方法为 `ByBase64Url`
* 哈希算法(`hash`)调用方式从 `dongle.Encrypt.ByXXX()` 改成 `dongle.Hash.ByXXX()`
* 消息认证码算法(`hmac`)调用方式从 `dongle.Encrypt.ByHmacXXX()` 改成 `dongle.Hash.WithKey().ByXXX()`
* 重构 `AES`, `DES`, `3DES`, `Blowfish` 等对称加密/解密方法，统一使用 `cipher.NewXXXCipher()`
* 重构 `RSA` 等非对称加密/解密方法，统一使用 `keypair.NewXXXKeyPair()`
* 增加对 `文件流` 编码/解码、加密/解密、Hash/Hmac、签名/验签的支持
* 新增`ByBase32Hex` 编码/解码方法
* `base32/base32Hex` 编码增加对自定义字符集的支持
* `base45` 编码增加对自定义字符集的支持
* `base58` 编码增加对自定义字符集的支持
* `base62` 编码增加对自定义字符集的支持
* `base64/base64Url` 编码增加对自定义字符集的支持

## [v1.0.1](https://github.com/dromara/dongle/compare/v1.0.0...v1.0.1) (2024-11-22)

* 优化代码质量和组织结构
* 修复 `AES-CBC-PKCS5` 加密解密错误的 bug
* `base62` 支持自定义编码表
* 删除 `errors.go` 文件，将错误信息迁移到各个文件里
* 统一单元测试格式
* 移除中文注释

## [v1.0.0](https://github.com/dromara/carbon/compare/v0.2.8...v1.0.0) (2024-11-11)

- 修复了 AES/ECB/PKCS5 填充导致的 panic 
- 更改了仓库和徽章 URL

有关更早版本的更新日志，请参阅 <a href="https://github.com/dromara/dongle/releases" target="_blank" rel="noreferrer">releases</a>
