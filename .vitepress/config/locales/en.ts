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
                {text: 'Overview', link: 'overview',},
                {text: 'Quick Start', link: 'getting-started',},
            ]
        },
        {
            text: 'Encoding/Decoding',
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
            text: 'Hash Algorithms',
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
            text: 'Hmac Algorithms',
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
            text: 'Symmetric Encryption',
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
                {text: 'Twofish', link: 'crypto/twofish'},
            ]
        },
        {
            text: 'Asymmetric Encryption',
            collapsed: false,
            items: [
                {text: 'Rsa', link: 'crypto/rsa'},
            ]
        },
        {
            text: 'Signature/Verification',
            collapsed: false,
            items: [
                {text: 'Rsa', link: 'signature/rsa'},
				{text: 'Ed25519', link: 'signature/ed25519'},
            ]
        },
    ]
}

