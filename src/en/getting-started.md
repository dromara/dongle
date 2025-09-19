---
head:
  - - meta
    - name: description
      content: Quick Start | a simple, semantic and developer-friendly crypto package for golang
---

# Quick Start
> go version >= 1.23

```go
// via github 
go get -u github.com/dromara/dongle
import "github.com/dromara/dongle"

// via gitee
go get -u gitee.com/dromara/dongle
import "gitee.com/dromara/dongle"

// via gitcode 
go get -u gitcode.com/dromara/dongle
import "gitcode.com/dromara/dongle"
```

`Dongle` was donated to the [dromara](https://dromara.org/ "dromara") organization, the repository URL has changed. If
the previous repository used was `golang-module/dongle`, please replace the original repository with the new repository
in `go.mod`, or execute the following command:

```go
go mod edit -replace github.com/golang-module/dongle = github.com/dromara/dongle
```