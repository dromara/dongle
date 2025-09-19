import type {MarkdownOptions} from 'vitepress';

export const markdown: MarkdownOptions = {
  // theme: 'github-dark',
  math: true,
  codeTransformers: [
    {
      postprocess(code) {
        return code.replace(/\[\!\!code/g, '[!code')
      }
    }
  ],
  config(md) {
    const fence = md.renderer.rules.fence!
  }
}