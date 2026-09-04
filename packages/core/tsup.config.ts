import { defineConfig } from 'tsup';

export default defineConfig({
  entry: ['src/index.ts'],
  format: ['esm', 'cjs'],
  dts: true,
  sourcemap: true,
  clean: true,
  target: 'es2022',
  platform: 'neutral',
  treeshake: true,
  // Inline the codec's definitions JSON: an external JSON import needs `with { type: 'json' }`,
  // which esbuild drops from the ESM output and Node then refuses to load.
  noExternal: [/ripple-binary-codec\/dist\/enums\/definitions\.json$/],
});
