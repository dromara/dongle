import type {HeadConfig} from 'vitepress';

export const head: HeadConfig[] = [
  ['link', { rel: 'icon', href: '/favicon.ico' }],
  ['meta', { name: 'theme-color', content: '#5f67ee' }],
  ['meta', { property: 'og:type', content: 'website' }],
  ['meta', { property: 'og:site_name', content: 'dongle' }],
  ['meta', { property: 'og:url', content: 'https://dongle.go-pkg.com' }],
  ['meta', { name: "viewport", content: "width=device-width, initial-scale=1.0, minimum-scale=1.0, maximum-scale=1.0, user-scalable=no,shrink-to-fit=no" }],
  ['script', {}, `window._hmt = window._hmt||[];(function(){var hm=document.createElement("script");hm.src="https://hm.baidu.com/hm.js?0c7714c469f75c60ebabfa1c5b7ff8ea";var s=document.getElementsByTagName("script")[0];s.parentNode.insertBefore(hm,s)})();`]
]