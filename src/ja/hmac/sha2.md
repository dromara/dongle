---
title: HMAC-SHA2アルゴリズム
head:
  - - meta
    - name: description
      content: HMAC-SHA2アルゴリズム | 軽量で、セマンティックで、開発者フレンドリーなgolang エンコード&暗号ライブラリ
  - - meta
    - name: keywords
      content: HMAC-SHA2, HMAC-SHA224, HMAC-SHA256, HMAC-SHA384, HMAC-SHA512
---

# Hmac-Sha2

`Hmac-Sha2` は `sha2` ベースのメッセージ認証コードアルゴリズムシリーズで、`sha2-224`、`sha2-256`、`sha2-384`、`sha2-512` を含みます。`dongle` はすべての4つの `sha2` メッセージ認証コードアルゴリズムをサポートします。

- [Sha2-224](#sha2-224)：28バイトのハッシュ値を生成
- [Sha2-256](#sha2-256)：32バイトのハッシュ値を生成
- [Sha2-384](#sha2-384)：48バイトのハッシュ値を生成
- [Sha2-512](#sha2-512)：64バイトのハッシュ値を生成

> 注意：`WithKey` メソッドは `BySha2` の前に呼び出す必要があります

## Sha2-224

### 入力データ

```go
// 入力文字列
hasher := dongle.Hash.FromString("hello world").WithKey([]byte("dongle")).BySha2(224)

// 入力バイトスライス
hasher := dongle.Hash.FromBytes([]byte("hello world")).WithKey([]byte("dongle")).BySha2(224)

// 入力ファイルストリーム
file, _ := os.Open("test.txt")
hasher := dongle.Hash.FromFile(file).WithKey([]byte("dongle")).BySha2(224)

// HMACエラーをチェック
if hasher.Error != nil {
	fmt.Printf("HMACエラー: %v\n", hasher.Error)
	return
}
```

### 出力データ

```go
// Hexエンコード文字列を出力
hasher.ToHexString() // e15b9e5a7eccb1f17dc81dc07c909a891936dc3429dc0d940accbcec

// Hexエンコードバイトスライスを出力
hasher.ToHexBytes()  // []byte("e15b9e5a7eccb1f17dc81dc07c909a891936dc3429dc0d940accbcec")

// Base64エンコード文字列を出力
hasher.ToBase64String() // 4VueWn7MsfF9yB3AfJCaiRk23DQp3A2UCsy87A==

// Base64エンコードバイトスライスを出力
hasher.ToBase64Bytes()  // []byte("4VueWn7MsfF9yB3AfJCaiRk23DQp3A2UCsy87A==")

// エンコードなしの生文字列を出力
hasher.ToRawString()

// エンコードなしの生バイトスライスを出力
hasher.ToRawBytes()
```

## Sha2-256

### 入力データ

```go
// 入力文字列
hasher := dongle.Hash.FromString("hello world").WithKey([]byte("dongle")).BySha2(256)

// 入力バイトスライス
hasher := dongle.Hash.FromBytes([]byte("hello world")).WithKey([]byte("dongle")).BySha2(256)

// 入力ファイルストリーム
file, _ := os.Open("test.txt")
hasher := dongle.Hash.FromFile(file).WithKey([]byte("dongle")).BySha2(256)

// HMACエラーをチェック
if hasher.Error != nil {
	fmt.Printf("HMACエラー: %v\n", hasher.Error)
	return
}
```

### 出力データ

```go
// Hexエンコード文字列を出力
hasher.ToHexString() // 77f5c8ce4147600543e70b12701e7b78b5b95172332ebbb06de65fcea7112179

// Hexエンコードバイトスライスを出力
hasher.ToHexBytes()  // []byte("77f5c8ce4147600543e70b12701e7b78b5b95172332ebbb06de65fcea7112179")

// Base64エンコード文字列を出力
hasher.ToBase64String() // d/XIzkFHYAVD5wsScB57eLW5UXIzLruwbeZfzqcRIXk=

// Base64エンコードバイトスライスを出力
hasher.ToBase64Bytes()  // []byte("d/XIzkFHYAVD5wsScB57eLW5UXIzLruwbeZfzqcRIXk=")

// エンコードなしの生文字列を出力
hasher.ToRawString()

// エンコードなしの生バイトスライスを出力
hasher.ToRawBytes()
```

## Sha2-384

### 入力データ

```go
// 入力文字列
hasher := dongle.Hash.FromString("hello world").WithKey([]byte("dongle")).BySha2(384)

// 入力バイトスライス
hasher := dongle.Hash.FromBytes([]byte("hello world")).WithKey([]byte("dongle")).BySha2(384)

// 入力ファイルストリーム
file, _ := os.Open("test.txt")
hasher := dongle.Hash.FromFile(file).WithKey([]byte("dongle")).BySha2(384)

// HMACエラーをチェック
if hasher.Error != nil {
	fmt.Printf("HMACエラー: %v\n", hasher.Error)
	return
}
```

### 出力データ

```go
// Hexエンコード文字列を出力
hasher.ToHexString() // 421fcaa740216a31bbcd1f86f2212e0c68aa4b156a8ebc2ae55b3e75c4ee0509ea0325a0570ae739006b61d91d91d817fe8
// Hexエンコードバイトスライスを出力
hasher.ToHexBytes()  // []byte("421fcaa740216a31bbcd1f86f2212e0c68aa4b156a8ebc2ae55b3e75c4ee0509ea0325a0570ae739006b61d91d817fe8")

// Base64エンコード文字列を出力
hasher.ToBase64String() // Qh/Kp0AhajG7zR+G8iEuDGiqSxVqjrwq5Vs+dcTuBQnqAyWgVwrnOQBrYdkdgX/o
// Base64エンコードバイトスライスを出力
hasher.ToBase64Bytes()  // []byte("Qh/Kp0AhajG7zR+G8iEuDGiqSxVqjrwq5Vs+dcTuBQnqAyWgVwrnOQBrYdkdgX/o")

// エンコードなしの生文字列を出力
hasher.ToRawString()
// エンコードなしの生バイトスライスを出力
hasher.ToRawBytes()
```

## Sha2-512

### 入力データ

```go
// 入力文字列
hasher := dongle.Hash.FromString("hello world").WithKey([]byte("dongle")).BySha2(512)

// 入力バイトスライス
hasher := dongle.Hash.FromBytes([]byte("hello world")).WithKey([]byte("dongle")).BySha2(512)

// 入力ファイルストリーム
file, _ := os.Open("test.txt")
hasher := dongle.Hash.FromFile(file).WithKey([]byte("dongle")).BySha2(512)

// HMACエラーをチェック
if hasher.Error != nil {
	fmt.Printf("HMACエラー: %v\n", hasher.Error)
	return
}
```

### 出力データ

```go
// Hexエンコード文字列を出力
hasher.ToHexString() // d971b790bbc2a4ac81062bbffac693c9c234bae176c8faf5e304dbdb153032a826f12353964b4a4fb87abecd2dc237638a630cbad54a6b94b1f6ef5d5e2835d1

// Hexエンコードバイトスライスを出力
hasher.ToHexBytes()  // []byte("d971b790bbc2a4ac81062bbffac693c9c234bae176c8faf5e304dbdb153032a826f12353964b4a4fb87abecd2dc237638a630cbad54a6b94b1f6ef5d5e2835d1")

// Base64エンコード文字列を出力
hasher.ToBase64String() // 2XG3kLvCpKyBBiu/+saTycI0uuF2yPr14wTb2xUwMqgm8SNTlktKT7h6vs0twjdjimMMutVKa5Sx9u9dXig10Q==

// Base64エンコードバイトスライスを出力
hasher.ToBase64Bytes()  // []byte("2XG3kLvCpKyBBiu/+saTycI0uuF2yPr14wTb2xUwMqgm8SNTlktKT7h6vs0twjdjimMMutVKa5Sx9u9dXig10Q==")

// エンコードなしの生文字列を出力
hasher.ToRawString()

// エンコードなしの生バイトスライスを出力
hasher.ToRawBytes()
```





