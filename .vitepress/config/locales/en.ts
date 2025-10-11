import {type DefaultTheme, defineConfig} from 'vitepress'

export const en = defineConfig({
    lang: 'en-US',
    title: 'dongle',
    description: 'A simple, semantic and developer-friendly crypto package for golang',
    head: [
        ['meta', { name: 'keywords', content: 'golang, dongle, encoding, decoding, hash, hmac, symmetric encryption, symmetric decryption, asymmetric encryption, asymmetric decryption' }],
    ],
    themeConfig: {
        nav: nav(),

        sidebar: {
            '/': { items: sidebarGuide() },
        },

        editLink: {
            pattern: 'https://github.com/dromara/dongle/edit/docs/src/:path',
            text: 'Edit this page on GitHub'
        },

        footer: {
            message: 'Released under the MIT License, unauthorized reproduction is prohibited in any form',
            copyright: `Copyright © 2020-${new Date().getFullYear()} dongle team`
        },

        docFooter: {
            prev: 'Previous',
            next: 'Next'
        },

        outline: {
            level: [2, 6],
            label: 'On this page'
        },

        lastUpdated: {
            text: 'Last updated',
            formatOptions: {
                dateStyle: 'short',
                timeStyle: 'medium'
            }
        },

        langMenuLabel: 'Languages',
        returnToTopLabel: 'Back to top',
        sidebarMenuLabel: 'Menu',
        darkModeSwitchLabel: 'Theme',
        lightModeSwitchTitle: 'Switch to light mode',
        darkModeSwitchTitle: 'Switch to dark mode'
    }
})

function nav(): DefaultTheme.NavItem[] {
    return [
        {
            text: 'Home',
            link: '/'
        },
        {
            text: 'Doc',
            link: '/overview',
            activeMatch: '/overview'
        },
        {
            text: 'ChangeLog',
            link: '/change-log',
            activeMatch: '/change-log'
        },
        {
            text: 'Sponsor',
            link: '/sponsor',
            activeMatch: '/sponsor'
        },
		{
			text: 'Carbon',
			link: 'https://carbon.go-pkg.com/',
			activeMatch: 'https://carbon.go-pkg.com/'
		},
    ]
}

function sidebarGuide(): DefaultTheme.SidebarItem[] {
    return [
        {
            text: 'Getting Started',
            collapsed: false,
            items: [
                {text: 'overview', link: 'overview',},
                {text: 'quick start', link: 'getting-started',},
            ]
        },
        {
            text: 'Encoding/Decoding',
            collapsed: false,
            items: [
                {text: 'base16/hex', link: 'coding/hex'},
                {text: 'base32', link: 'coding/base32'},
                {text: 'base45', link: 'coding/base45'},
                {text: 'base58', link: 'coding/base58'},
                {text: 'base62', link: 'coding/base62'},
                {text: 'base64', link: 'coding/base64'},
                {text: 'base85', link: 'coding/base85'},
                {text: 'base91', link: 'coding/base91'},
                {text: 'base100', link: 'coding/base100'},
                {text: 'morse', link: 'coding/morse'},
            ]
        },
        {
            text: 'Hash Algorithms',
            collapsed: false,
            items: [
                {text: 'hash-blake2b', link: 'hash/blake2b'},
                {text: 'hash-blake2s', link: 'hash/blake2s'},
                {text: 'hash-md2', link: 'hash/md2'},
                {text: 'hash-md4', link: 'hash/md4'},
                {text: 'hash-md5', link: 'hash/md5'},
                {text: 'hash-sha1', link: 'hash/sha1'},
                {text: 'hash-sha2', link: 'hash/sha2'},
                {text: 'hash-sha3', link: 'hash/sha3'},
				{text: 'hash-sm3', link: 'hash/sm3'},
				{text: 'hash-ripemd160', link: 'hash/ripemd160'},
            ]
        },
        {
            text: 'Hmac Algorithms',
            collapsed: false,
            items: [
                {text: 'hmac-blake2b', link: 'hmac/blake2b'},
                {text: 'hmac-blake2s', link: 'hmac/blake2s'},
                {text: 'hmac-md2', link: 'hmac/md2'},
                {text: 'hmac-md4', link: 'hmac/md4'},
                {text: 'hmac-md5', link: 'hmac/md5'},
                {text: 'hmac-sha1', link: 'hmac/sha1'},
                {text: 'hmac-sha2', link: 'hmac/sha2'},
                {text: 'hmac-sha3', link: 'hmac/sha3'},
				{text: 'hmac-sm3', link: 'hmac/sm3'},
				{text: 'hmac-ripemd160', link: 'hmac/ripemd160'},
            ]
        },
        {
            text: 'Symmetric Encryption',
            collapsed: false,
            items: [
                {text: 'aes', link: 'crypto/aes'},
                {text: 'blowfish', link: 'crypto/blowfish'},
                {text: 'des', link: 'crypto/des'},
                {text: '3des', link: 'crypto/3des'},
                {text: 'rc4', link: 'crypto/rc4'},
				{text: 'tea', link: 'crypto/tea'},
				{text: 'xtea', link: 'crypto/xtea'},
				{text: 'chacha20', link: 'crypto/chacha20'},
				{text: 'chacha20-poly1305', link: 'crypto/chacha20-poly1305'},
                {text: 'salsa20', link: 'crypto/salsa20'},
                {text: 'twofish', link: 'crypto/twofish'},
            ]
        },
        {
            text: 'Asymmetric Encryption',
            collapsed: false,
            items: [
                {text: 'rsa', link: 'crypto/rsa'},
            ]
        },
        {
            text: 'Signature/Verification',
            collapsed: false,
            items: [
                {text: 'rsa', link: 'signature/rsa'},
				{text: 'ed25519', link: 'signature/ed25519'},
            ]
        },
    ]
}

