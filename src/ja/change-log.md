---
head:
  - - meta
    - name: description
      content: 更新ログ | 軽量で、セマンティックで、開発者フレンドリーなgolang エンコード&暗号ライブラリ
---

# 更新ログ
## [v1.2.1](https://github.com/dromara/dongle/compare/v1.2.0...v1.2.1) (2025-11-24)

* `Sm2` 非対称楕円曲線暗号化アルゴリズムの `wNAF` アルゴリズムエラーによる一部の復号化失敗のバグを修正
* `Sm2` 非対称楕円曲線暗号化アルゴリズムの曲線フィールド要素演算実装を最適化
* `Sm2` 非対称楕円曲線暗号化アルゴリズムに `BIT_STRING` 形式キーの直接解析サポートを追加
* テストループ構文を簡素化、`for` ループから `range` ループに変更

## [v1.2.0](https://github.com/dromara/dongle/compare/v1.1.8...v1.2.0) (2025-11-11)

* `RSAKeyPair` 構造体の `LoadPublicKey` および `LoadPrivateKey` メソッドを削除
* `Ed25519KeyPair` 構造体の `LoadPublicKey` および `LoadPrivateKey` メソッドを削除
* エンコーダーとデコーダーのパフォーマンスを最適化、読み取りバッファを再利用し、メモリ割り当てとコピーを削減
* `RSAKeyPair` 構造体の `GenKeyPair`、`SetPublicKey`、`SetPrivateKey` メソッドを返り値なしから `error` を返すように変更
* `Ed25519KeyPair` 構造体の `GenKeyPair`、`SetPublicKey`、`SetPrivateKey` メソッドを返り値なしから `error` を返すように変更
* `RSAKeyPair` 構造体に `FormatPublicKey` および `FormatPrivateKey` メソッドを追加、`base64` エンコードされた `der` 形式の `RSA` 公開鍵と秘密鍵を `pem` 形式にフォーマット
* `Ed25519KeyPair` 構造体に `FormatPublicKey` および `FormatPrivateKey` メソッドを追加、`base64` エンコードされた `der` 形式の `Ed25519` 公開鍵と秘密鍵を `pem` 形式にフォーマット
* `RSAKeyPair` 構造体に `CompressPublicKey` および `CompressPrivateKey` メソッドを追加、`pem` 形式の `RSA` 公開鍵と秘密鍵を `base64` エンコードされた `der` 形式に圧縮
* `Ed25519KeyPair` 構造体に `CompressPublicKey` および `CompressPrivateKey` メソッドを追加、`pem` 形式の `Ed25519` 公開鍵と秘密鍵を `base64` エンコードされた `der` 形式に圧縮
* `Sm2` 非対称楕円曲線暗号化アルゴリズムサポートを追加（標準処理とストリーム処理を含む）

## [v1.1.8](https://github.com/dromara/dongle/compare/v1.1.7...v1.1.8) (2025-11-05)
* `*RsaKeyPair.formatPublicKey` および `*RsaKeyPair.formatPrivateKey` による鍵のフォーマット失敗のバグを修正
* `*Ed25519KeyPair.formatPublicKey` および `*Ed25519KeyPair.formatPrivateKey` による鍵のフォーマット失敗のバグを修正
* 復号化時にエンコードされた暗号文のデコードが失敗した場合、エラーを取得できないバグを修正
* 対称ブロック暗号化アルゴリズムのデフォルトパディングモードを `PKCS7` から `No` に変更
* `Unicode` エンコード/デコードサポートを追加（標準処理とストリーム処理を含む）
* 対称ブロック暗号化アルゴリズムに `TBC` パディングモードサポートを追加

## [v1.1.7](https://github.com/dromara/dongle/compare/v1.1.6...v1.1.7) (2025-10-20)
* 非対称デジタル署名アルゴリズムの検証エラーのバグを修正 [#30](https://github.com/dromara/dongle/issues)
* ストリーム処理ロジックを最適化し、`reader` 位置リセットサポートを追加してデータソースの先頭から読み取りを保証し、以前の読み取り操作による位置オフセット問題を回避し、ストリーム操作の完全性と正確性を保証
* `crypto/cipher/block.go` の `newXXXEncrypter` と `newXXXDecrypter` シリーズのプライベートメソッドを公開メソッド `NewXXXEncrypter` と `NewXXXDecrypter` に変更
* `crypto/cipher/padding.go` の `newXXXPadding` と `newXXXUnPadding` シリーズのプライベートメソッドを公開メソッド `NewXXXPadding` と `NewXXXUnPadding` に変更
* `sm4` 中国国家標準ブロック暗号化アルゴリズムサポートを追加（標準処理とストリーム処理を含み、異なるブロックモードとパディングモードをサポート）

## [v1.1.6](https://github.com/dromara/dongle/compare/v1.1.5...v1.1.6) (2025-10-12)

* `io.CopyBuffer` を使用してストリーム処理ロジックを簡素化
* `tea` 暗号化アルゴリズムを最適化し、異なるブロックモードとパディングモードをサポート
* `xtea` 暗号化アルゴリズムサポートを追加（標準処理とストリーム処理を含む）

## [v1.1.5](https://github.com/dromara/dongle/compare/v1.1.4...v1.1.5) (2025-10-01)

* パディングが不要なブロックモード（CFB/OFB/CTR/GCM など）で対称暗号化アルゴリズムがパディングを実行した際の暗号化/復号化エラーのバグを修正

## [v1.1.4](https://github.com/dromara/dongle/compare/v1.1.3...v1.1.4) (2025-09-23)

* グローバルデフォルトインスタンス使用時のプロパティ汚染を防ぐため、メソッドレシーバーをポインタから値に変更、呼び出し側 `API` への影響はなし
* `twofish` 暗号化アルゴリズムサポートを追加（標準処理とストリーム処理を含む）

## [v1.1.3](https://github.com/dromara/dongle/compare/v1.1.2...v1.1.3) (2025-09-15)

* `3DES` 対称暗号化アルゴリズムの `16` バイトキー互換性を最適化
* `DES` 対称暗号化アルゴリズムのサポートされていない `GCM` モード検証を最適化
* `3DES` 対称暗号化アルゴリズムのサポートされていない `GCM` モード検証を最適化
* `Blowfish` 対称暗号化アルゴリズムのサポートされていない `GCM` モード検証を最適化
* `testify` 依存関係を `v1.11.1` に更新
* `Salsa20` 暗号化アルゴリズムサポートを追加（標準処理とストリーム処理を含む）

## [v1.1.2](https://github.com/dromara/dongle/compare/v1.1.1...v1.1.2) (2025-09-08)

* エンコード/デコードが `coding.BufferSize` グローバル変数によるファイルストリームバッファサイズのカスタマイズをサポート
* 暗号化/復号化が `crypto.BufferSize` グローバル変数によるファイルストリームバッファサイズのカスタマイズをサポート
* Hash/Hmacアルゴリズムが `hash.BufferSize` グローバル変数によるファイルストリームバッファサイズのカスタマイズをサポート
* `Blake2b` ハッシュアルゴリズムサポートを追加（`blake2b-256`、`blake2b-384`、`blake2b-512` を含む）
* `Blake2s` ハッシュアルゴリズムサポートを追加（`blake2s-128`、`blake2s-256` を含む）
* `ChaCha20` 暗号化アルゴリズムサポートを追加
* `ChaCha20Poly1305` 暗号化アルゴリズムサポートを追加

## [v1.1.1](https://github.com/dromara/dongle/compare/v1.1.0...v1.1.1) (2025-09-01)

* 対称暗号化アルゴリズムを `ByXXX(cipher.XXXCipher)` から `ByXXX(*cipher.XXXCipher)` に変更
* ユーティリティパッケージ名を `utils` から `util` に変更
* エンコード/デコード、暗号化/復号化、Hash/Hmac、署名/検証の真のストリーム処理をサポート
* 入力データが空の場合、後続処理を実行せずに直接空データを返す
* `ED25519` デジタル署名と検証サポートを追加
* `SM3` ハッシュアルゴリズムサポートを追加
* `hash.Hash` インターフェースのエラーをモックするための `mock/hash.go` を追加
* `coding/morse/morse.go` にスペース、句読点、特殊文字のサポートを追加

## [v1.1.0](https://github.com/dromara/dongle/compare/v1.0.1...v1.1.0) (2025-08-23)
> ⚠️ これは破壊的な更新バージョンです。慎重にアップグレードしてください。ただし、アップグレードを強く推奨します

* `BySafeURL` エンコード/デコードメソッドを削除
* `Sm3` ハッシュアルゴリズム(`hash`)とメッセージ認証コードアルゴリズム(`hmac`)を削除
* `ByBase64URL` エンコード/デコードメソッドを `ByBase64Url` に名前変更
* ハッシュアルゴリズム(`hash`)呼び出し方式を `dongle.Encrypt.ByXXX()` から `dongle.Hash.ByXXX()` に変更
* メッセージ認証コードアルゴリズム(`hmac`)呼び出し方式を `dongle.Encrypt.ByHmacXXX()` から `dongle.Hash.WithKey().ByXXX()` に変更
* `AES`, `DES`, `3DES`, `Blowfish` などの対称暗号化/復号化メソッドをリファクタリング、`cipher.NewXXXCipher()` で統一
* `RSA` などの非対称暗号化/復号化メソッドをリファクタリング、`keypair.NewXXXKeyPair()` で統一
* `ファイルストリーム` のエンコード/デコード、暗号化/復号化、Hash/Hmac、署名/検証サポートを追加
* `ByBase32Hex` エンコード/デコードメソッドを新規追加
* `base32/base32Hex` エンコードにカスタム文字セットサポートを追加
* `base45` エンコードにカスタム文字セットサポートを追加
* `base58` エンコードにカスタム文字セットサポートを追加
* `base62` エンコードにカスタム文字セットサポートを追加
* `base64/base64Url` エンコードにカスタム文字セットサポートを追加

## [v1.0.1](https://github.com/dromara/dongle/compare/v1.0.0...v1.0.1) (2024-11-22)

* コード品質と組織構造を最適化
* `AES-CBC-PKCS5` 暗号化復号化エラーのBugを修正
* `base62` カスタムエンコードテーブルをサポート
* `errors.go` ファイルを削除、エラー情報を各ファイルに移行
* 単体テストフォーマットを統一
* 中文コメントを削除

## [v1.0.0](https://github.com/dromara/carbon/compare/v0.2.8...v1.0.0) (2024-11-11)

- AES/ECB/PKCS5 パディングによる panic を修正 
- リポジトリとバッジURLを変更

より古いバージョンの更新ログについては、<a href="https://github.com/dromara/dongle/releases" target="_blank" rel="noreferrer">releases</a> を参照してください