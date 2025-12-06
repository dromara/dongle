import {type DefaultTheme, defineConfig} from 'vitepress'

export const zh = defineConfig({
    lang: 'zh-Hans',
    title: 'dongle',
    description: '一个轻量级、语义化、对开发者友好的 golang 编码&密码库',
    head: [
        ['meta', { name: 'keywords', content: 'golang, dongle, 编码, 解码, 哈希, hash, hamc, 对称加密, 对称解密, 非对称加密, 非对称解密' }],
    ],
    themeConfig: {
        nav: nav(),

        sidebar: {
            '/zh/': { base: '/zh/', items: sidebarGuide() },
        },

        editLink: {
            pattern: 'https://github.com/dromara/dongle/edit/docs/src/:path',
            text: '在 GitHub 上编辑此页面'
        },

        footer: {
            message: '基于 MIT 许可发布，未经许可禁止任何形式的转载',
            copyright: `版权所有 © 2020-${new Date().getFullYear()} dongle team <a href="https://beian.miit.gov.cn" target="_blank">京ICP备19041346号-7</a>`
        },

        docFooter: {
            prev: '上一页',
            next: '下一页'
        },

        outline: {
            level: [2, 6],
            label: '当前页面'
        },

        lastUpdated: {
            text: '最后更新于',
            formatOptions: {
                dateStyle: 'short',
                timeStyle: 'medium'
            }
        },

        langMenuLabel: '多语言',
        returnToTopLabel: '回到顶部',
        sidebarMenuLabel: '菜单',
        darkModeSwitchLabel: '主题',
        lightModeSwitchTitle: '切换到浅色模式',
        darkModeSwitchTitle: '切换到深色模式'
    }
})

function nav(): DefaultTheme.NavItem[] {
    return [
        {
            text: '首页',
            link: '/zh'
        },
        {
            text: '使用文档',
            link: '/zh/overview',
            activeMatch: '/zh/overview'
        },
        {
            text: '更新日志',
            link: '/zh/change-log',
            activeMatch: '/zh/change-log'
        },
        {
            text: '赞助支持',
            link: '/zh/sponsor',
            activeMatch: '/zh/sponsor'
        },
		{
            text: 'Carbon',
            link: 'https://carbon.go-pkg.com/zh',
            activeMatch: 'https://carbon.go-pkg.com/zh'
        },
    ]
}

function sidebarGuide(): DefaultTheme.SidebarItem[] {
    return [
        {
            text: '入门指引',
            collapsed: false,
            items: [
                {text: '项目简介', link: 'overview',},
                {text: '快速开始', link: 'getting-started',},
            ]
        },
        {
            text: '编码/解码',
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
            text: 'Hash 算法',
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
            text: 'Hmac 算法',
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
            text: '对称加密算法',
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
            text: '非对称加密算法',
            collapsed: false,
            items: [
                {text: 'rsa 🔥', link: 'crypto/rsa'},
                {text: 'sm2 🔥', link: 'crypto/sm2'},
            ]
        },
        {
            text: '数字签名/验证',
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
    zh: {
        placeholder: '搜索文档',
        translations: {
            button: {
                buttonText: '搜索文档',
                buttonAriaLabel: '搜索文档'
            },
            modal: {
                searchBox: {
                },
                startScreen: {
                    recentSearchesTitle: '搜索历史',
                    noRecentSearchesText: '没有搜索历史',
                    saveRecentSearchButtonTitle: '保存至搜索历史',
                    removeRecentSearchButtonTitle: '从搜索历史中移除',
                    favoriteSearchesTitle: '收藏',
                    removeFavoriteSearchButtonTitle: '从收藏中移除'
                },
                errorScreen: {
                    titleText: '无法获取结果',
                    helpText: '你可能需要检查你的网络连接'
                },
                footer: {
                    selectText: '选择',
                    navigateText: '切换',
                    closeText: '关闭',
                },
                noResultsScreen: {
                    noResultsText: '无法找到相关结果',
                    suggestedQueryText: '你可以尝试查询',
                    reportMissingResultsText: '你认为该查询应该有结果？',
                    reportMissingResultsLinkText: '点击反馈'
                }
            }
        }
    }
}
