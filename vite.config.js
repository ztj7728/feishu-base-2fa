import { defineConfig } from 'vite';

export default defineConfig({
  // 使用相对路径，兼容 https://用户名.github.io/仓库名/ 这种 GitHub Pages 地址
  base: './',
});
