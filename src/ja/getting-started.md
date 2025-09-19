---
head:
  - - meta
    - name: description
      content: クイックスタート | 軽量で、セマンティックで、開発者フレンドリーなgolang エンコード&暗号ライブラリ
---

# クイックスタート
> go version >= 1.23

```go
// github ライブラリを使用
go get -u github.com/dromara/dongle
import "github.com/dromara/dongle"

// gitee ライブラリを使用
go get -u gitee.com/dromara/dongle
import "gitee.com/dromara/dongle"

// gitcode ライブラリを使用
go get -u gitcode.com/dromara/dongle
import "gitcode.com/dromara/dongle"
```

`dongle` は既に [dromara](https://dromara.org/ "dromara") オープンソース組織に寄贈され、リポジトリアドレスが変更されました。以前のパスが
`golang-module/dongle` だった場合、`go.mod` で元のアドレスを新しいパスに置き換えるか、以下のコマンドを実行してください

```go
go mod edit -replace github.com/golang-module/dongle = github.com/dromara/dongle
```