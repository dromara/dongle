import {type DefaultTheme, defineConfig} from 'vitepress'

export const ja = defineConfig({
    lang: 'japanese',
    title: 'dongle',
    description: '軽量で意味的、開発者フレンドリーな golang エンコーディング&暗号化ライブラリ',
    head: [
        ['meta', { name: 'keywords', content: 'golang, dongle, エンコード, デコード, ハッシュ, hash, hamc, 対称暗号化, 対称復号化, 非対称暗号化, 非対称復号化' }],
    ],
    themeConfig: {
        nav: nav(),

        sidebar: {
            '/ja/': { base: '/ja/',items: sidebarGuide() },
        },

        editLink: {
            pattern: 'https://github.com/dromara/dongle/edit/docs/src/:path',
            text: 'GitHubでこのページを編集する'
        },

        footer: {
            message: 'MITライセンスに基づいて公開されており、許可なく複製することは禁止されています',
            copyright: `無断転載を禁じます © 2020-${new Date().getFullYear()} dongle team`
        },

        docFooter: {
            prev: '前のページ',
            next: '次のページ'
        },

        outline: {
            level: [2, 6],
            label: '現在のディレクトリ'
        },

        lastUpdated: {
            text: '最終更新日',
            formatOptions: {
                dateStyle: 'short',
                timeStyle: 'medium'
            }
        },

        langMenuLabel: '多言語',
        returnToTopLabel: 'トップに戻る',
        sidebarMenuLabel: 'メニュー',
        darkModeSwitchLabel: 'トピック＃トピック＃',
        lightModeSwitchTitle: 'ライトモードに切り替え',
        darkModeSwitchTitle: 'ダークカラーモードに切り替え'
    }
})

function nav(): DefaultTheme.NavItem[] {
    return [
        {
            text: 'ホーム',
            link: '/ja'
        },
        {
            text: '使用ドキュメント',
            link: '/ja/overview',
            activeMatch: '/ja/overview'
        },
        {
            text: '更新ログ',
            link: '/ja/change-log',
            activeMatch: '/ja/change-log'
        },
        {
            text: 'スポンサーサポート',
            link: '/ja/sponsor',
            activeMatch: '/ja/sponsor'
        },
		{
            text: 'Carbon',
            link: 'https://carbon.go-pkg.com/ja',
            activeMatch: 'https://carbon.go-pkg.com/ja'
        },
    ]
}

function sidebarGuide(): DefaultTheme.SidebarItem[] {
    return [
        {
            text: '入門ガイド',
            collapsed: false,
            items: [
                {text: 'プロジェクト紹介', link: 'overview',},
                {text: 'クイックスタート', link: 'getting-started',},
            ]
        },
        {
            text: 'エンコード/デコード',
            collapsed: false,
            items: [
                {text: 'base16/hex', link: 'coding/hex'},
                {text: 'base32', link: 'coding/base32'},
                {text: 'base45', link: 'coding/base45'},
                {text: 'base58', link: 'coding/base58'},
                {text: 'base62', link: 'coding/base62'},
                {text: 'base64 🔥', link: 'coding/base64'},
                {text: 'base85', link: 'coding/base85'},
                {text: 'base91', link: 'coding/base91'},
                {text: 'base100', link: 'coding/base100'},
                {text: 'morse 🔥', link: 'coding/morse'},
                {text: 'unicode 🔥', link: 'coding/unicode'},
            ]
        },
        {
            text: 'Hash アルゴリズム',
            collapsed: false,
            items: [
                {text: 'hash-blake2b', link: 'hash/blake2b'},
                {text: 'hash-blake2s', link: 'hash/blake2s'},
                {text: 'hash-md2', link: 'hash/md2'},
                {text: 'hash-md4', link: 'hash/md4'},
                {text: 'hash-md5 🔥', link: 'hash/md5'},
                {text: 'hash-sha1', link: 'hash/sha1'},
                {text: 'hash-sha2', link: 'hash/sha2'},
                {text: 'hash-sha3', link: 'hash/sha3'},
                {text: 'hash-sm3 🔥', link: 'hash/sm3'},
                {text: 'hash-ripemd160', link: 'hash/ripemd160'},
            ]
        },
        {
            text: 'Hmac アルゴリズム',
            collapsed: false,
            items: [
                {text: 'hmac-blake2b', link: 'hmac/blake2b'},
                {text: 'hmac-blake2s', link: 'hmac/blake2s'},
                {text: 'hmac-md2', link: 'hmac/md2'},
                {text: 'hmac-md4', link: 'hmac/md4'},
                {text: 'hmac-md5 🔥', link: 'hmac/md5'},
                {text: 'hmac-sha1', link: 'hmac/sha1'},
                {text: 'hmac-sha2', link: 'hmac/sha2'},
                {text: 'hmac-sha3', link: 'hmac/sha3'},
                {text: 'hmac-sm3 🔥', link: 'hmac/sm3'},
                {text: 'hmac-ripemd160', link: 'hmac/ripemd160'},
            ]
        },
        {
            text: '対称暗号化アルゴリズム',
            collapsed: false,
            items: [
                {text: 'aes 🔥', link: 'crypto/aes'},
                {text: 'des 🔥', link: 'crypto/des'},
                {text: '3des 🔥', link: 'crypto/3des'},
                {text: 'tea', link: 'crypto/tea'},
                {text: 'xtea', link: 'crypto/xtea'},
                {text: 'blowfish', link: 'crypto/blowfish'},
                {text: 'twofish', link: 'crypto/twofish'},
                {text: 'sm4 🔥', link: 'crypto/sm4'},
                {text: 'rc4', link: 'crypto/rc4'},
                {text: 'chacha20', link: 'crypto/chacha20'},
                {text: 'chacha20-poly1305', link: 'crypto/chacha20-poly1305'},
                {text: 'salsa20', link: 'crypto/salsa20'},
            ]
        },
        {
            text: '非対称暗号化アルゴリズム',
            collapsed: false,
            items: [
                {text: 'rsa 🔥', link: 'crypto/rsa'},
                {text: 'sm2 🔥', link: 'crypto/sm2'},
            ]
        },
        {
            text: 'デジタル署名/検証',
            collapsed: false,
            items: [
                {text: 'rsa 🔥', link: 'signature/rsa'},
                {text: 'ed25519', link: 'signature/ed25519'},
                {text: 'sm2', link: 'signature/sm2'},
            ]
        },
    ]
}

export const search: DefaultTheme.AlgoliaSearchOptions['locales'] = {
    ja: {
        placeholder: 'ドキュメントを検索',
        translations: {
            button: {
                buttonText: 'ドキュメントを検索',
                buttonAriaLabel: 'ドキュメントを検索'
            },
            modal: {
                searchBox: {
                },
                startScreen: {
                    recentSearchesTitle: '検索履歴',
                    noRecentSearchesText: '検索履歴がありません',
                    saveRecentSearchButtonTitle: '検索履歴に保存',
                    removeRecentSearchButtonTitle: '検索履歴から削除',
                    favoriteSearchesTitle: 'お気に入り',
                    removeFavoriteSearchButtonTitle: 'お気に入りから削除'
                },
                errorScreen: {
                    titleText: '結果を取得できません',
                    helpText: 'ネットワーク接続を確認してください'
                },
                footer: {
                    selectText: '選択',
                    navigateText: '切り替え',
                    closeText: '閉じる',
                },
                noResultsScreen: {
                    noResultsText: '関連する結果が見つかりません',
                    suggestedQueryText: '以下のクエリを試してください',
                    reportMissingResultsText: 'このクエリに結果があると思いますか？',
                    reportMissingResultsLinkText: 'フィードバックを送信'
                }
            }
        }
    }
}
