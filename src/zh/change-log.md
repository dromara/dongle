---
head:
  - - meta
    - name: description
      content: 更新日志|一个轻量级、语义化、对开发者友好的 golang 时间处理库
---

# 更新日志

## [v1.1.7](https://github.com/dromara/dongle/compare/v1.1.6...v1.1.7) (2025-10-20)

* [fix] 修复非对称数字签名算法中验签错误的 bug [#30](https://github.com/dromara/dongle/issues)
* [chore] 优化流式处理逻辑，添加对 `reader` 位置重置的支持，确保从数据源的开头开始读取，避免因之前读取操作导致的位置偏移问题，保证流式操作的完整性和正确性
* [chore] `crypto/cipher/block.go` 中 `newXXXEncrypter` 和 `newXXXDecrypter` 系列私有方法更改成公开方法 `NewXXXEncrypter` 和 `NewXXXDecrypter`
* [chore] `crypto/cipher/padding.go` 中 `newXXXPadding` 和 `newXXXUnPadding` 系列私有方法更改成公开方法 `NewXXXPadding` 和 `NewXXXUnPadding`
* [feat] 增加 `sm4` 中国国家标准分组加密算法支持，包括标准处理和流式处理，支持不同分块模式和填充模式

## [v1.1.6](https://github.com/dromara/dongle/compare/v1.1.5...v1.1.6) (2025-10-12)

* [chore] 使用 `io.CopyBuffer` 简化流式处理逻辑
* [chore] 优化 `tea` 加密算法，支持不同分块模式和填充模式
* [feat] 增加 `xtea` 加密算法支持，包括标准处理和流式处理

## [v1.1.5](https://github.com/dromara/dongle/compare/v1.1.4...v1.1.5) (2025-10-01)

* [fix] 修复对称加密算法中对不需要填充的分组模式(如 CFB/OFB/CTR/GCM 等)进行填充时加解密错误的bug

## [v1.1.4](https://github.com/dromara/dongle/compare/v1.1.3...v1.1.4) (2025-09-23)

* [chore] 将方法接受者从指针改成值，防止出现使用全局默认实例时属性污染现象，调用方 `API` 没有任何影响
* [feat] 增加 `twofish` 加密算法支持，包括标准处理和流式处理

## [v1.1.3](https://github.com/dromara/dongle/compare/v1.1.2...v1.1.3) (2025-09-15)

* [chore] 优化 `3DES` 对称加密算法对 `16` 字节密钥的兼容
* [chore] 优化 `DES` 对称加密算法对不支持的 `GCM` 模式的校验
* [chore] 优化 `3DES` 对称加密算法对不支持的 `GCM` 模式的校验
* [chore] 优化 `Blowfish` 对称加密算法对不支持的 `GCM` 模式的校验
* [chore] 更新 `testify` 依赖至 `v1.11.1` 
* [feat] 增加 `Salsa20` 加密算法支持，包括标准处理和流式处理

## [v1.1.2](https://github.com/dromara/dongle/compare/v1.1.1...v1.1.2) (2025-09-08)

* [chore] 编码/解码支持通过 `coding.BufferSize` 全局变量自定义文件流缓冲区大小
* [chore] 加密/解密支持通过 `crypto.BufferSize` 全局变量自定义文件流缓冲区大小
* [chore] Hash/Hmac 算法支持通过 `hash.BufferSize` 全局变量自定义文件流缓冲区大小
* [feat] 增加 `Blake2b` 哈希算法支持，包括 `blake2b-256`、`blake2b-384` 和 `blake2b-512`
* [feat] 增加 `Blake2s` 哈希算法支持，包括 `blake2s-128` 和 `blake2s-256`
* [feat] 增加 `ChaCha20` 加密算法支持
* [feat] 增加 `ChaCha20Poly1305` 加密算法支持

## [v1.1.1](https://github.com/dromara/dongle/compare/v1.1.0...v1.1.1) (2025-09-01)

* [refactor] 对称加密算法从 `ByXXX(cipher.XXXCipher)` 改成 `ByXXX(*cipher.XXXCipher)`
* [refactor] 将工具包名从 `utils` 改成 `util`
* [refactor] 编码/解码、加密/解密、Hash/Hmac、签名/验签支持真正的流式处理
* [refactor] 当输入数据为空时，直接返回空数据而不执行后续操作
* [feat] 增加 `ED25519` 数字签名和验证支持
* [feat] 增加 `SM3` 哈希算法支持
* [feat] 增加 `mock/hash.go` 来模拟 `hash.Hash` 接口的错误
* [feat] `coding/morse/morse.go` 增加对空格、标点符号和特殊字符的支持

## [v1.1.0](https://github.com/dromara/dongle/compare/v1.0.1...v1.1.0) (2025-08-23)
> ⚠️ 这是一个破坏性更新版本，请慎重升级，但是强烈建议升级

* [refactor] 删除 `BySafeURL` 编码/解码方法
* [refactor] 删除 `Sm3` 哈希算法(`hash`)和消息认证码算法(`hmac`)
* [refactor] 重命名 `ByBase64URL` 编码/解码方法为 `ByBase64Url`
* [refactor] 哈希算法(`hash`)调用方式从 `dongle.Encrypt.ByXXX()` 改成 `dongle.Hash.ByXXX()`
* [refactor] 消息认证码算法(`hmac`)调用方式从 `dongle.Encrypt.ByHmacXXX()` 改成 `dongle.Hash.WithKey().ByXXX()`
* [refactor] 重构 `AES`, `DES`, `3DES`, `Blowfish` 等对称加密/解密方法，统一使用 `cipher.NewXXXCipher()`
* [refactor] 重构 `RSA` 等非对称加密/解密方法，统一使用 `keypair.NewXXXKeyPair()`
* [feat] 增加对 `文件流` 编码/解码、加密/解密、Hash/Hmac、签名/验签的支持
* [feat] 新增`ByBase32Hex` 编码/解码方法
* [feat] `base32/base32Hex` 编码增加对自定义字符集的支持
* [feat] `base45` 编码增加对自定义字符集的支持
* [feat] `base58` 编码增加对自定义字符集的支持
* [feat] `base62` 编码增加对自定义字符集的支持
* [feat] `base64/base64Url` 编码增加对自定义字符集的支持

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