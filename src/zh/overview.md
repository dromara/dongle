---
head:
  - - meta
    - name: description
      content: 项目简介|一个轻量级、语义化、对开发者友好的 golang 密码库
---

# 项目简介

`dongle`  是一个轻量级、语义化、对开发者友好的 `golang` 编码&密码库，拥有完善的单元测试覆盖，已被 [awesome-go](https://github.com/yinggaozhen/awesome-go-cn#密码学 "awesome-go-cn") 收录，并获得
`gitee` 2024 年最有价值项目（`GVP`）和 `gitcode` 2024 年度开源摘星计划 (`G-Star`) 项目

<img src="/gvp.jpg" width="100%" alt="gvp"/>
<img src="/gstar.jpg" width="100%" alt="g-star"/>

## 项目特性
- **丰富的编码算法支持**：支持 Base32/Base45/Base58/Base62/Base64/Base85/Base91/Base100/Hex/Morse/Unicode 等多种编码格式
- **强大的哈希算法支持**：支持 MD2/MD4/MD5、SHA1/SHA2/SHA3、SM3、BLAKE2b/BLAKE2s、RIPEMD160 等多种哈希算法和 HMAC 消息认证
- **完整的加密算法支持**：支持 RC4、AES、DES、3DES、Blowfish、SM4、ChaCha20、ChaCha20-Poly1305、Salsa20、TEA/XTea、Twofish 等对称加密算法，以及 RSA、SM2 等非对称加密算法
- **可靠的签名验证支持**：支持 RSA、ED25519、SM2 数字签名和验证，提供 PKCS#1、PKCS#8、SPKI/PKIX 密钥格式支持，确保数据完整性和身份认证
- **高效的流式处理**：支持大文件的流式编码解码、加密解密，大多数算法边读边处理，无需等待全部数据，内存占用低；Base58/Base62 与 SM2 因算法特性会整体缓存输入
- **全面的测试覆盖**：完善的单元测试覆盖，所有编码/解码、加密/解密、HASH/HMAC、签名/验证模块均有全面单元测试，覆盖所有边界和异常情况
- **安全可靠的设计**：提供输入验证、错误处理、内存安全等安全特性，支持密钥管理和错误消息统一
- **详细的错误处理**：提供详细的错误信息和类型，支持错误链追踪，便于调试和问题定位

## 仓库地址

[github.com/dromara/dongle](https://github.com/dromara/dongle "github.com/dromara/dongle")

[gitee.com/dromara/dongle](https://gitee.com/dromara/dongle "gitee.com/dromara/dongle")

[gitcode.com/dromara/dongle](https://gitcode.com/dromara/dongle "gitcode.com/dromara/dongle")

## Playground
[tools.go-pkg.com](https://tools.go-pkg.com "https://tools.go-pkg.com")
