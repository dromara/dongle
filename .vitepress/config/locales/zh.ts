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
                {text: 'Base16/Hex', link: 'coding/hex'},
                {text: 'Base32', link: 'coding/base32'},
                {text: 'Base45', link: 'coding/base45'},
                {text: 'Base58', link: 'coding/base58'},
                {text: 'Base62', link: 'coding/base62'},
                {text: 'Base64', link: 'coding/base64'},
                {text: 'Base85', link: 'coding/base85'},
                {text: 'Base91', link: 'coding/base91'},
                {text: 'Base100', link: 'coding/base100'},
                {text: 'Morse', link: 'coding/morse'},
            ]
        },
        {
            text: 'Hash 算法',
            collapsed: false,
            items: [
                {text: 'Hash-Blake2b', link: 'hash/blake2b'},
                {text: 'Hash-Blake2s', link: 'hash/blake2s'},
                {text: 'Hash-Md2', link: 'hash/md2'},
                {text: 'Hash-Md4', link: 'hash/md4'},
                {text: 'Hash-Md5', link: 'hash/md5'},
                {text: 'Hash-Sha1', link: 'hash/sha1'},
                {text: 'Hash-Sha2', link: 'hash/sha2'},
                {text: 'Hash-Sha3', link: 'hash/sha3'},
                {text: 'Hash-Sm3', link: 'hash/sm3'},
                {text: 'Hash-Ripemd160', link: 'hash/ripemd160'},
            ]
        },
        {
            text: 'Hmac 算法',
            collapsed: false,
            items: [
                {text: 'Hmac-Blake2b', link: 'hmac/blake2b'},
                {text: 'Hmac-Blake2s', link: 'hmac/blake2s'},
                {text: 'Hmac-Md2', link: 'hmac/md2'},
                {text: 'Hmac-Md4', link: 'hmac/md4'},
                {text: 'Hmac-Md5', link: 'hmac/md5'},
                {text: 'Hmac-Sha1', link: 'hmac/sha1'},
                {text: 'Hmac-Sha2', link: 'hmac/sha2'},
                {text: 'Hmac-Sha3', link: 'hmac/sha3'},
                {text: 'Hmac-Sm3', link: 'hmac/sm3'},
                {text: 'Hmac-Ripemd160', link: 'hmac/ripemd160'},
            ]
        },
        {
            text: '对称加密算法',
            collapsed: false,
            items: [
                {text: 'Aes', link: 'crypto/aes'},
                {text: 'Blowfish', link: 'crypto/blowfish'},
                {text: 'Des', link: 'crypto/des'},
                {text: '3Des', link: 'crypto/3des'},
				{text: 'Rc4', link: 'crypto/rc4'},
				{text: 'Tea', link: 'crypto/tea'},
                {text: 'ChaCha20', link: 'crypto/chacha20'},
                {text: 'ChaCha20Poly1305', link: 'crypto/chacha20-poly1305'},
                {text: 'Salsa20', link: 'crypto/salsa20'},
            ]
        },
        {
            text: '非对称加密算法',
            collapsed: false,
            items: [
                {text: 'Rsa', link: 'crypto/rsa'},
            ]
        },
        {
            text: '数字签名/验证',
            collapsed: false,
            items: [
                {text: 'Rsa', link: 'signature/rsa'},
                {text: 'Ed25519', link: 'signature/ed25519'},
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
