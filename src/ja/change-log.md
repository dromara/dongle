---
head:
  - - meta
    - name: description
      content: 更新ログ | 軽量で、セマンティックで、開発者フレンドリーなgolang エンコード&暗号ライブラリ
---

# 更新ログ

## [v1.1.8](https://github.com/dromara/dongle/compare/v1.1.7...v1.1.8) (2025-11-01)
* [feat] `Unicode` エンコード/デコードサポートを追加（標準処理とストリーム処理を含む）
* [feat] 対称ブロック暗号化アルゴリズムに `TBC` パディングモードサポートを追加

## [v1.1.7](https://github.com/dromara/dongle/compare/v1.1.6...v1.1.7) (2025-10-20)
* [fix] 非対称デジタル署名アルゴリズムの検証エラーのバグを修正 [#30](https://github.com/dromara/dongle/issues)
* [chore] ストリーム処理ロジックを最適化し、`reader` 位置リセットサポートを追加してデータソースの先頭から読み取りを保証し、以前の読み取り操作による位置オフセット問題を回避し、ストリーム操作の完全性と正確性を保証
* [chore] `crypto/cipher/block.go` の `newXXXEncrypter` と `newXXXDecrypter` シリーズのプライベートメソッドを公開メソッド `NewXXXEncrypter` と `NewXXXDecrypter` に変更
* [chore] `crypto/cipher/padding.go` の `newXXXPadding` と `newXXXUnPadding` シリーズのプライベートメソッドを公開メソッド `NewXXXPadding` と `NewXXXUnPadding` に変更
* [feat] `sm4` 中国国家標準ブロック暗号化アルゴリズムサポートを追加（標準処理とストリーム処理を含み、異なるブロックモードとパディングモードをサポート）

## [v1.1.6](https://github.com/dromara/dongle/compare/v1.1.5...v1.1.6) (2025-10-12)

* [chore] `io.CopyBuffer` を使用してストリーム処理ロジックを簡素化
* [chore] `tea` 暗号化アルゴリズムを最適化し、異なるブロックモードとパディングモードをサポート
* [feat] `xtea` 暗号化アルゴリズムサポートを追加（標準処理とストリーム処理を含む）

## [v1.1.5](https://github.com/dromara/dongle/compare/v1.1.4...v1.1.5) (2025-10-01)

* [fix] パディングが不要なブロックモード（CFB/OFB/CTR/GCM など）で対称暗号化アルゴリズムがパディングを実行した際の暗号化/復号化エラーのバグを修正

## [v1.1.4](https://github.com/dromara/dongle/compare/v1.1.3...v1.1.4) (2025-09-23)

* [chore] グローバルデフォルトインスタンス使用時のプロパティ汚染を防ぐため、メソッドレシーバーをポインタから値に変更、呼び出し側 `API` への影響はなし
* [feat] `twofish` 暗号化アルゴリズムサポートを追加（標準処理とストリーム処理を含む）

## [v1.1.3](https://github.com/dromara/dongle/compare/v1.1.2...v1.1.3) (2025-09-15)

* [chore] `3DES` 対称暗号化アルゴリズムの `16` バイトキー互換性を最適化
* [chore] `DES` 対称暗号化アルゴリズムのサポートされていない `GCM` モード検証を最適化
* [chore] `3DES` 対称暗号化アルゴリズムのサポートされていない `GCM` モード検証を最適化
* [chore] `Blowfish` 対称暗号化アルゴリズムのサポートされていない `GCM` モード検証を最適化
* [chore] `testify` 依存関係を `v1.11.1` に更新
* [feat] `Salsa20` 暗号化アルゴリズムサポートを追加（標準処理とストリーム処理を含む）

## [v1.1.2](https://github.com/dromara/dongle/compare/v1.1.1...v1.1.2) (2025-09-08)

* [chore] エンコード/デコードが `coding.BufferSize` グローバル変数によるファイルストリームバッファサイズのカスタマイズをサポート
* [chore] 暗号化/復号化が `crypto.BufferSize` グローバル変数によるファイルストリームバッファサイズのカスタマイズをサポート
* [chore] Hash/Hmacアルゴリズムが `hash.BufferSize` グローバル変数によるファイルストリームバッファサイズのカスタマイズをサポート
* [feat] `Blake2b` ハッシュアルゴリズムサポートを追加（`blake2b-256`、`blake2b-384`、`blake2b-512` を含む）
* [feat] `Blake2s` ハッシュアルゴリズムサポートを追加（`blake2s-128`、`blake2s-256` を含む）
* [feat] `ChaCha20` 暗号化アルゴリズムサポートを追加
* [feat] `ChaCha20Poly1305` 暗号化アルゴリズムサポートを追加

## [v1.1.1](https://github.com/dromara/dongle/compare/v1.1.0...v1.1.1) (2025-09-01)

* [refactor] 対称暗号化アルゴリズムを `ByXXX(cipher.XXXCipher)` から `ByXXX(*cipher.XXXCipher)` に変更
* [refactor] ユーティリティパッケージ名を `utils` から `util` に変更
* [refactor] エンコード/デコード、暗号化/復号化、Hash/Hmac、署名/検証の真のストリーム処理をサポート
* [refactor] 入力データが空の場合、後続処理を実行せずに直接空データを返す
* [feat] `ED25519` デジタル署名と検証サポートを追加
* [feat] `SM3` ハッシュアルゴリズムサポートを追加
* [feat] `hash.Hash` インターフェースのエラーをモックするための `mock/hash.go` を追加
* [feat] `coding/morse/morse.go` にスペース、句読点、特殊文字のサポートを追加

## [v1.1.0](https://github.com/dromara/dongle/compare/v1.0.1...v1.1.0) (2025-08-23)
> ⚠️ これは破壊的な更新バージョンです。慎重にアップグレードしてください。ただし、アップグレードを強く推奨します

* [refactor] `BySafeURL` エンコード/デコードメソッドを削除
* [refactor] `Sm3` ハッシュアルゴリズム(`hash`)とメッセージ認証コードアルゴリズム(`hmac`)を削除
* [refactor] `ByBase64URL` エンコード/デコードメソッドを `ByBase64Url` に名前変更
* [refactor] ハッシュアルゴリズム(`hash`)呼び出し方式を `dongle.Encrypt.ByXXX()` から `dongle.Hash.ByXXX()` に変更
* [refactor] メッセージ認証コードアルゴリズム(`hmac`)呼び出し方式を `dongle.Encrypt.ByHmacXXX()` から `dongle.Hash.WithKey().ByXXX()` に変更
* [refactor] `AES`, `DES`, `3DES`, `Blowfish` などの対称暗号化/復号化メソッドをリファクタリング、`cipher.NewXXXCipher()` で統一
* [refactor] `RSA` などの非対称暗号化/復号化メソッドをリファクタリング、`keypair.NewXXXKeyPair()` で統一
* [feat] `ファイルストリーム` のエンコード/デコード、暗号化/復号化、Hash/Hmac、署名/検証サポートを追加
* [feat] `ByBase32Hex` エンコード/デコードメソッドを新規追加
* [feat] `base32/base32Hex` エンコードにカスタム文字セットサポートを追加
* [feat] `base45` エンコードにカスタム文字セットサポートを追加
* [feat] `base58` エンコードにカスタム文字セットサポートを追加
* [feat] `base62` エンコードにカスタム文字セットサポートを追加
* [feat] `base64/base64Url` エンコードにカスタム文字セットサポートを追加

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