---
head:
  - - meta
    - name: description
      content: 快速开始|一个轻量级、语义化、对开发者友好的 golang 编码&密码库
---

# 快速开始
> go version >= 1.23

```go
// 使用 github 库
go get -u github.com/dromara/dongle
import "github.com/dromara/dongle"

// 使用 gitee 库
go get -u gitee.com/dromara/dongle
import "gitee.com/dromara/dongle"

// 使用 gitcode 库
go get -u gitcode.com/dromara/dongle
import "gitcode.com/dromara/dongle"
```

`dongle` 已经捐赠给了 [dromara](https://dromara.org/ "dromara") 开源组织，仓库地址发生了改变，如果之前用的路径是
`golang-module/dongle`，请在 `go.mod` 里将原地址更换为新路径，或执行如下命令

```go
go mod edit -replace github.com/golang-module/dongle = github.com/dromara/dongle
```