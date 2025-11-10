---
title: SHA2ハッシュアルゴリズム
head:
  - - meta
    - name: description
      content: SHA2 ハッシュアルゴリズム、sha2-224、sha2-256、sha2-384、sha2-512 の4つのバリアントを提供、標準およびストリーミング処理をサポート、文字列、バイト、ファイル入力をサポート、Hex および Base64 出力形式をサポート
  - - meta
    - name: keywords
      content: dongle, go-dongle, ハッシュ, ダイジェスト, チェックサム, SHA2, sha2-224, sha2-256, sha2-384, sha2-512, ストリーミング処理, 文字列入力, バイト入力, ファイル入力, Hex, Base64
---

# Hash-Sha2

`Hash-Sha2` は異なる長さのハッシュ値を生成する一連のハッシュアルゴリズムで、`sha2-224`、`sha2-256`、`sha2-384`、`sha2-512` を含みます。`dongle` はすべての4つの `hash-sha2` バリアントおよびストリーミングをサポートしています。

- [Sha2-224](#sha2-224): 28バイトのハッシュ値を生成
- [Sha2-256](#sha2-256): 32バイトのハッシュ値を生成
- [Sha2-384](#sha2-384): 48バイトのハッシュ値を生成
- [Sha2-512](#sha2-512): 64バイトのハッシュ値を生成

## Sha2-224

### 入力データ

```go
// 入力文字列
hasher := dongle.Hash.FromString("hello world").BySha2(224)
// 入力バイトスライス
hasher := dongle.Hash.FromBytes([]byte("hello world")).BySha2(224)
// 入力ファイルストリーム
file, _ := os.Open("test.txt")
hasher := dongle.Hash.FromFile(file).BySha2(224)

// ハッシュエラーをチェック
if hasher.Error != nil {
	fmt.Printf("ハッシュエラー: %v\n", hasher.Error)
	return
}
```

### 出力データ

```go
// Hexエンコード文字列を出力
hasher.ToHexString() // 2f05477fc24bb4faefd86517156dafdecec45b8ad3cf2522a563582b
// Hexエンコードバイトスライスを出力
hasher.ToHexBytes()  // []byte("2f05477fc24bb4faefd86517156dafdecec45b8ad3cf2522a563582b")

// Base64エンコード文字列を出力
hasher.ToBase64String() // LwVHf8JLtPrv2GUXFW2v3s7EW4rTzyUipWNYKw==
// Base64エンコードバイトスライスを出力
hasher.ToBase64Bytes()  // []byte("LwVHf8JLtPrv2GUXFW2v3s7EW4rTzyUipWNYKw==")

// エンコードされていない生の文字列を出力
hasher.ToRawString()
// エンコードされていない生のバイトスライスを出力
hasher.ToRawBytes()
```

## Sha2-256

### 入力データ

```go
// 入力文字列
hasher := dongle.Hash.FromString("hello world").BySha2(256)
// 入力バイトスライス
hasher := dongle.Hash.FromBytes([]byte("hello world")).BySha2(256)
// 入力ファイルストリーム
file, _ := os.Open("test.txt")
hasher := dongle.Hash.FromFile(file).BySha2(256)

// ハッシュエラーをチェック
if hasher.Error != nil {
	fmt.Printf("ハッシュエラー: %v\n", hasher.Error)
	return
}
```

### 出力データ

```go
// Hexエンコード文字列を出力
hasher.ToHexString() // b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9
// Hexエンコードバイトスライスを出力
hasher.ToHexBytes()  // []byte("b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9")

// Base64エンコード文字列を出力
hasher.ToBase64String() // uU0nuZNNPgilLlLX2n2r+sSE7+N6U4DukIj3rOLvzek=
// Base64エンコードバイトスライスを出力
hasher.ToBase64Bytes()  // []byte("uU0nuZNNPgilLlLX2n2r+sSE7+N6U4DukIj3rOLvzek=")

// エンコードされていない生の文字列を出力
hasher.ToRawString()
// エンコードされていない生のバイトスライスを出力
hasher.ToRawBytes()
```

## Sha2-384

### 入力データ

```go
// 入力文字列
hasher := dongle.Hash.FromString("hello world").BySha2(384)
// 入力バイトスライス
hasher := dongle.Hash.FromBytes([]byte("hello world")).BySha2(384)
// 入力ファイルストリーム
file, _ := os.Open("test.txt")
hasher := dongle.Hash.FromFile(file).BySha2(384)

// ハッシュエラーをチェック
if hasher.Error != nil {
	fmt.Printf("ハッシュエラー: %v\n", hasher.Error)
	return
}
```

### 出力データ

```go
// Hexエンコード文字列を出力
hasher.ToHexString() // fdbd8e75a67f29f701a4e040385e2e23986303ea10239211af907fcbb83578b3e417cb71ce646efd0819dd8c088de1bd
// Hexエンコードバイトスライスを出力
hasher.ToHexBytes()  // []byte("fdbd8e75a67f29f701a4e040385e2e23986303ea10239211af907fcbb83578b3e417cb71ce646efd0819dd8c088de1bd")

// Base64エンコード文字列を出力
hasher.ToBase64String() // /b2OdaZ/KfcBpOBAOF4uI5hjA+oQI5IRr5B/y7g1eLPkF8txzmRu/QgZ3YwIjeG9
// Base64エンコードバイトスライスを出力
hasher.ToBase64Bytes()  // []byte("/b2OdaZ/KfcBpOBAOF4uI5hjA+oQI5IRr5B/y7g1eLPkF8txzmRu/QgZ3YwIjeG9")

// エンコードされていない生の文字列を出力
hasher.ToRawString()
// エンコードされていない生のバイトスライスを出力
hasher.ToRawBytes()
```

## Sha2-512

### 入力データ

```go
// 入力文字列
hasher := dongle.Hash.FromString("hello world").BySha2(512)
// 入力バイトスライス
hasher := dongle.Hash.FromBytes([]byte("hello world")).BySha2(512)
// 入力ファイルストリーム
file, _ := os.Open("test.txt")
hasher := dongle.Hash.FromFile(file).BySha2(512)

// ハッシュエラーをチェック
if hasher.Error != nil {
	fmt.Printf("ハッシュエラー: %v\n", hasher.Error)
	return
}
```

### 出力データ

```go
// Hexエンコード文字列を出力
hasher.ToHexString() // 309ecc489c12d6eb4cc40f50c902f2b4d0ed77ee511a7c7a9bcd3ca86d4cd86f989dd35bc5ff499670da34255b45b0cfd830e81f605dcf7dc5542e93ae9cd76f
// Hexエンコードバイトスライスを出力
hasher.ToHexBytes()  // []byte("309ecc489c12d6eb4cc40f50c902f2b4d0ed77ee511a7c7a9bcd3ca86d4cd86f989dd35bc5ff499670da34255b45b0cfd830e81f605dcf7dc5542e93ae9cd76f")

// Base64エンコード文字列を出力
hasher.ToBase64String() // MJ7MSJwS1utMxA9QyQLytNDtd+5RGnx6m808qG1M2G+YndNbxf9JlnDaNCVbRbDP2DDoH2Bdz33FVC6TrpzXbw==
// Base64エンコードバイトスライスを出力
hasher.ToBase64Bytes()  // []byte("MJ7MSJwS1utMxA9QyQLytNDtd+5RGnx6m808qG1M2G+YndNbxf9JlnDaNCVbRbDP2DDoH2Bdz33FVC6TrpzXbw==")

// エンコードされていない生の文字列を出力
hasher.ToRawString()
// エンコードされていない生のバイトスライスを出力
hasher.ToRawBytes()
```



