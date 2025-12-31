import { defineConfig } from 'tsdown'

export default defineConfig({
  entry: ['src/index.ts'],
  format: ['esm', 'cjs'],
  platform: 'node',
  exports: true,
  dts: true,
  minify: false,
  unbundle: true,
  sourcemap: false,
  treeshake: true,
})
